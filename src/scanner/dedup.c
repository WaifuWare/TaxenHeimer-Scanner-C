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
#define DEDUP_TABLE_BITS 22
#define DEDUP_TABLE_SIZE (1 << DEDUP_TABLE_BITS)  // 4M entries
#define DEDUP_TABLE_MASK (DEDUP_TABLE_SIZE - 1)

typedef struct {
    uint32_t ip;            // 0 = empty
    uint32_t version_hash;
    uint32_t motd_hash;
    uint16_t players_online;
    uint16_t players_max;
} dedup_entry_t;

static dedup_entry_t *table = NULL;
static pthread_mutex_t dedup_lock = PTHREAD_MUTEX_INITIALIZER;

void dedup_init(void) {
    if (!table) {
        table = (dedup_entry_t *)calloc(DEDUP_TABLE_SIZE, sizeof(dedup_entry_t));
    }
}

void dedup_reset(void) {
    if (table) {
        memset(table, 0, DEDUP_TABLE_SIZE * sizeof(dedup_entry_t));
    }
}

static uint32_t ip_key(const char *ip_str) {
    // Parse IP to uint32. Inline for speed — avoid dependency on utils.
    uint32_t a = 0, b = 0, c = 0, d = 0;
    sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d);
    uint32_t v = (a << 24) | (b << 16) | (c << 8) | d;
    return v == 0 ? 1 : v;  // 0 reserved for empty
}

dedup_result_t dedup_check(const server_info_t *info, uint32_t *changed_fields) {
    if (!table) {
        *changed_fields = CHANGED_NEW;
        return DEDUP_NEW;
    }

    uint32_t key = ip_key(info->ip);
    uint32_t ver_h = hash_str(info->version);
    uint32_t mot_h = hash_str(info->motd);

    uint32_t idx = (key * 2654435761u) & DEDUP_TABLE_MASK;  // Knuth multiplicative

    pthread_mutex_lock(&dedup_lock);

    // Linear probe (max 32 steps)
    for (int probe = 0; probe < 32; probe++) {
        uint32_t slot = (idx + (uint32_t)probe) & DEDUP_TABLE_MASK;
        dedup_entry_t *e = &table[slot];

        if (e->ip == 0) {
            // Empty slot — new entry
            e->ip = key;
            e->version_hash = ver_h;
            e->motd_hash = mot_h;
            e->players_online = (uint16_t)info->players.online;
            e->players_max = (uint16_t)info->players.max;
            pthread_mutex_unlock(&dedup_lock);
            *changed_fields = CHANGED_NEW;
            return DEDUP_NEW;
        }

        if (e->ip == key) {
            // Existing entry — check for changes
            uint32_t cf = 0;
            if (e->version_hash != ver_h)                   cf |= CHANGED_VERSION;
            if (e->motd_hash != mot_h)                      cf |= CHANGED_MOTD;
            if (e->players_online != (uint16_t)info->players.online) cf |= CHANGED_PLAYERS;
            if (e->players_max != (uint16_t)info->players.max)      cf |= CHANGED_MAX_PLAYERS;

            if (cf) {
                // Update stored state
                e->version_hash = ver_h;
                e->motd_hash = mot_h;
                e->players_online = (uint16_t)info->players.online;
                e->players_max = (uint16_t)info->players.max;
                pthread_mutex_unlock(&dedup_lock);
                *changed_fields = cf;
                return DEDUP_CHANGED;
            }

            pthread_mutex_unlock(&dedup_lock);
            *changed_fields = 0;
            return DEDUP_UNCHANGED;
        }
    }

    // Table full in this neighborhood — treat as new (rare at <50% load)
    pthread_mutex_unlock(&dedup_lock);
    *changed_fields = CHANGED_NEW;
    return DEDUP_NEW;
}
