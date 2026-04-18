#include "scanner/dedup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// FNV-1a 32-bit hash
static uint32_t fnv1a(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t hash_str(const char *s) {
    return fnv1a(s, strlen(s));
}

// Open-addressed hash table keyed by IP (uint32_t).
// Value: per-field hashes for change detection.
//
// Sharding: 256 shards of ~16K entries each, each guarded by its own mutex.
// A single global mutex serialises all 8 worker threads on every lookup —
// with 20K+ hits/sec, the cache-line bounce on the mutex + cond var alone
// dominates a large fraction of the dedup cost. Sharding spreads contention
// across 256 cache lines so simultaneous lookups on different /24 addresses
// don't stall each other. Total memory usage and total bucket count are
// unchanged.
#define DEDUP_TABLE_BITS   22
#define DEDUP_TABLE_SIZE   (1u << DEDUP_TABLE_BITS)
#define DEDUP_TABLE_MASK   (DEDUP_TABLE_SIZE - 1u)

#define DEDUP_SHARD_BITS   8
#define DEDUP_SHARD_COUNT  (1u << DEDUP_SHARD_BITS)
#define DEDUP_SHARD_MASK   (DEDUP_SHARD_COUNT - 1u)
#define DEDUP_SHARD_SIZE   (DEDUP_TABLE_SIZE / DEDUP_SHARD_COUNT)
#define DEDUP_SHARD_MASKL  (DEDUP_SHARD_SIZE - 1u)

typedef struct {
    uint32_t ip;            // 0 = empty
    uint32_t version_hash;
    uint32_t motd_hash;
    uint16_t players_online;
    uint16_t players_max;
} dedup_entry_t;

// Pad each mutex onto its own cache line to prevent false sharing between
// adjacent shards when threads race on nearby IPs.
typedef struct {
    pthread_mutex_t lock;
    char _pad[64 - sizeof(pthread_mutex_t) % 64];
} padded_mutex_t;

static dedup_entry_t *table = NULL;
static padded_mutex_t shard_locks[DEDUP_SHARD_COUNT];

void dedup_init(void) {
    if (!table) {
        table = (dedup_entry_t *)calloc(DEDUP_TABLE_SIZE, sizeof(dedup_entry_t));
        for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
            pthread_mutex_init(&shard_locks[i].lock, NULL);
        }
    }
}

void dedup_reset(void) {
    if (table) {
        for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
            pthread_mutex_lock(&shard_locks[i].lock);
        }
        memset(table, 0, DEDUP_TABLE_SIZE * sizeof(dedup_entry_t));
        for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
            pthread_mutex_unlock(&shard_locks[i].lock);
        }
    }
}

static uint32_t ip_key_parse(const char *ip_str) {
    // Parse IP to uint32. Inline for speed — avoid dependency on utils.
    uint32_t a = 0, b = 0, c = 0, d = 0;
    sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d);
    uint32_t v = (a << 24) | (b << 16) | (c << 8) | d;
    return v == 0 ? 1 : v;  // 0 reserved for empty
}

static uint32_t ip_key_from_info(const server_info_t *info) {
    // Prefer the pre-parsed uint32 stashed by the scanner; only fall back to
    // string parsing when a caller forgot to populate it (old code paths).
    if (info->ip_u32 != 0) {
        return info->ip_u32;
    }
    return ip_key_parse(info->ip);
}

dedup_result_t dedup_check(const server_info_t *info, uint32_t *changed_fields) {
    if (!table) {
        *changed_fields = CHANGED_NEW;
        return DEDUP_NEW;
    }

    uint32_t key = ip_key_from_info(info);
    uint32_t ver_h = hash_str(info->version);
    uint32_t mot_h = hash_str(info->motd);

    // Knuth multiplicative hash — the top bits pick the shard and the lower
    // bits pick the base index within the shard. We take the shard from the
    // high bits so that nearby IPs (e.g., whole /24 blocks discovered by the
    // same worker in one pass) land on *different* shards, evening out
    // contention.
    uint32_t h = key * 2654435761u;
    uint32_t shard = (h >> (32 - DEDUP_SHARD_BITS)) & DEDUP_SHARD_MASK;
    uint32_t local_idx = h & DEDUP_SHARD_MASKL;
    uint32_t base = shard * DEDUP_SHARD_SIZE;

    pthread_mutex_t *lk = &shard_locks[shard].lock;
    pthread_mutex_lock(lk);

    // Linear probe (max 32 steps) within the shard.
    for (uint32_t probe = 0; probe < 32; probe++) {
        uint32_t slot = base + ((local_idx + probe) & DEDUP_SHARD_MASKL);
        dedup_entry_t *e = &table[slot];

        if (e->ip == 0) {
            e->ip = key;
            e->version_hash = ver_h;
            e->motd_hash = mot_h;
            e->players_online = (uint16_t)info->players.online;
            e->players_max = (uint16_t)info->players.max;
            pthread_mutex_unlock(lk);
            *changed_fields = CHANGED_NEW;
            return DEDUP_NEW;
        }

        if (e->ip == key) {
            uint32_t cf = 0;
            if (e->version_hash != ver_h)                             cf |= CHANGED_VERSION;
            if (e->motd_hash != mot_h)                                cf |= CHANGED_MOTD;
            if (e->players_online != (uint16_t)info->players.online)  cf |= CHANGED_PLAYERS;
            if (e->players_max != (uint16_t)info->players.max)        cf |= CHANGED_MAX_PLAYERS;

            if (cf) {
                e->version_hash = ver_h;
                e->motd_hash = mot_h;
                e->players_online = (uint16_t)info->players.online;
                e->players_max = (uint16_t)info->players.max;
                pthread_mutex_unlock(lk);
                *changed_fields = cf;
                return DEDUP_CHANGED;
            }

            pthread_mutex_unlock(lk);
            *changed_fields = 0;
            return DEDUP_UNCHANGED;
        }
    }

    pthread_mutex_unlock(lk);
    *changed_fields = CHANGED_NEW;
    return DEDUP_NEW;
}
