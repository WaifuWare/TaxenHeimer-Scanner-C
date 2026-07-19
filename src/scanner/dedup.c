#include "scanner/dedup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

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
// Sharding: 256 shards, each guarded by its own mutex. A single global
// mutex serialised all workers on every lookup — with 20K+ hits/sec,
// the cache-line bounce on the mutex alone dominated cost. Sharding
// spreads contention across 256 cache lines so simultaneous lookups on
// different /24 addresses don't stall each other.
//
// The table size is chosen at init time so bedrock-only runs (small
// public-server universe) can allocate a ~4 MiB table instead of the
// ~64 MiB default — see dedup_init. Shard count stays at 256
// regardless; only the per-shard slot count shrinks.
#define DEDUP_SHARD_BITS   8
#define DEDUP_SHARD_COUNT  (1u << DEDUP_SHARD_BITS)
#define DEDUP_SHARD_MASK   (DEDUP_SHARD_COUNT - 1u)

static uint32_t table_bits  = 22;
static uint32_t table_size  = 0;   // 1u << table_bits
static uint32_t shard_size  = 0;   // table_size / DEDUP_SHARD_COUNT
static uint32_t shard_maskl = 0;   // shard_size - 1

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

void dedup_init(uint32_t bits) {
    if (table) return;  // idempotent — first caller wins

    // Clamp to a sane range. Lower bound preserves probe-room headroom
    // (shard_size must be > 32 so the linear-probe cap isn't the entire
    // shard); upper bound stays at 24 so we don't blow past 256 MiB by
    // accident.
    if (bits < 12) bits = 12;
    if (bits > 24) bits = 24;
    table_bits  = bits;
    table_size  = 1u << table_bits;
    shard_size  = table_size / DEDUP_SHARD_COUNT;
    shard_maskl = shard_size - 1u;

    // aligned_alloc (not calloc) so the table starts on a page
    // boundary — dedup_trim's MADV_DONTNEED requires page-aligned
    // addresses.
    long ps = sysconf(_SC_PAGESIZE);
    size_t page = ps > 0 ? (size_t)ps : 4096;
    size_t bytes = (size_t)table_size * sizeof(dedup_entry_t);
    size_t rounded = (bytes + page - 1) & ~(page - 1);
    table = (dedup_entry_t *)aligned_alloc(page, rounded);
    if (table) {
        memset(table, 0, rounded);
    }
    for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
        pthread_mutex_init(&shard_locks[i].lock, NULL);
    }
}

void dedup_reset(void) {
    if (table) {
        for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
            pthread_mutex_lock(&shard_locks[i].lock);
        }
        memset(table, 0, (size_t)table_size * sizeof(dedup_entry_t));
        // Drop the physical backing too — after reset there's no reason
        // to keep the old touched-page set in RSS. Next insert will
        // fault the relevant page back in on demand.
        long ps = sysconf(_SC_PAGESIZE);
        size_t page = ps > 0 ? (size_t)ps : 4096;
        size_t bytes = (size_t)table_size * sizeof(dedup_entry_t);
        size_t rounded = (bytes + page - 1) & ~(page - 1);
        madvise(table, rounded, MADV_DONTNEED);
        for (uint32_t i = 0; i < DEDUP_SHARD_COUNT; i++) {
            pthread_mutex_unlock(&shard_locks[i].lock);
        }
    }
}

void dedup_trim(void) {
    if (!table) return;

    long ps = sysconf(_SC_PAGESIZE);
    size_t page = ps > 0 ? (size_t)ps : 4096;
    size_t entries_per_page = page / sizeof(dedup_entry_t);
    if (entries_per_page == 0) return;

    // Iterate shard-by-shard so we only ever block inserts on one /256th
    // of the table at a time. Each shard is 16K entries = 64 pages at
    // 4K, so the critical section is small and bounded.
    // Guard against shrunk tables where a whole page no longer fits in
    // a shard — then per-page trim is pointless (the first touch of any
    // entry in the shard pulls in the page).
    if (shard_size < entries_per_page) return;

    for (uint32_t s = 0; s < DEDUP_SHARD_COUNT; s++) {
        uint32_t base = s * shard_size;

        pthread_mutex_lock(&shard_locks[s].lock);
        for (uint32_t off = 0;
             off + entries_per_page <= shard_size;
             off += (uint32_t)entries_per_page) {
            dedup_entry_t *start = &table[base + off];
            int empty = 1;
            for (size_t k = 0; k < entries_per_page; k++) {
                if (start[k].ip != 0) { empty = 0; break; }
            }
            if (empty) {
                // DONTNEED is idempotent on an already-reclaimed page,
                // so calling it on pages that were never dirtied in the
                // first place is cheap — the kernel just revalidates the
                // zero-page mapping.
                madvise(start, page, MADV_DONTNEED);
            }
        }
        pthread_mutex_unlock(&shard_locks[s].lock);
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
    uint32_t local_idx = h & shard_maskl;
    uint32_t base = shard * shard_size;

    pthread_mutex_t *lk = &shard_locks[shard].lock;
    pthread_mutex_lock(lk);

    // Linear probe (max 32 steps) within the shard.
    for (uint32_t probe = 0; probe < 32; probe++) {
        uint32_t slot = base + ((local_idx + probe) & shard_maskl);
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
