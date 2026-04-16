#include "scanner/subnet_stats.h"
#include "core/settings.h"
#include <string.h>
#include <stdatomic.h>

#ifndef ADAPTIVE_THRESHOLD
#define ADAPTIVE_THRESHOLD 16000
#endif

#ifndef SOCKET_TIMEOUT_MS_LOW
#define SOCKET_TIMEOUT_MS_LOW 200
#endif

static subnet_stats_entry_t table[65536];

void subnet_stats_init(void) {
    memset(table, 0, sizeof(table));
}

void subnet_stats_record(uint32_t ip, int hit) {
    uint16_t idx = (uint16_t)(ip >> 16);
    __atomic_add_fetch(&table[idx].scanned, 1, __ATOMIC_RELAXED);
    if (hit) {
        __atomic_add_fetch(&table[idx].hits, 1, __ATOMIC_RELAXED);
    }
}

int subnet_stats_get_timeout(uint32_t ip) {
    uint16_t idx = (uint16_t)(ip >> 16);
    uint16_t scanned = __atomic_load_n(&table[idx].scanned, __ATOMIC_RELAXED);
    uint16_t hits    = __atomic_load_n(&table[idx].hits, __ATOMIC_RELAXED);

    // Only reduce timeout if we've scanned 25% of the /16 AND found zero hits.
    // Once a single hit exists, this /16 stays at full timeout forever.
    if (hits > 0) return SOCKET_TIMEOUT_MS;
    if (scanned >= ADAPTIVE_THRESHOLD) return SOCKET_TIMEOUT_MS_LOW;
    return SOCKET_TIMEOUT_MS;
}

void subnet_stats_get(uint32_t ip, uint16_t *out_scanned, uint16_t *out_hits) {
    uint16_t idx = (uint16_t)(ip >> 16);
    if (out_scanned) *out_scanned = __atomic_load_n(&table[idx].scanned, __ATOMIC_RELAXED);
    if (out_hits)    *out_hits    = __atomic_load_n(&table[idx].hits, __ATOMIC_RELAXED);
}

void subnet_stats_reset(void) {
    memset(table, 0, sizeof(table));
}
