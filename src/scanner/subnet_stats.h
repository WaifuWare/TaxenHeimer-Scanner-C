#ifndef SUBNET_STATS_H
#define SUBNET_STATS_H

#include <stdint.h>

// Per-/16 hit tracking for adaptive timeout.
// 256 KB static array indexed by (ip >> 16).

typedef struct {
    uint16_t scanned;
    uint16_t hits;
} subnet_stats_entry_t;

void subnet_stats_init(void);
void subnet_stats_record(uint32_t ip, int hit);

// Returns adaptive timeout in ms for this IP's /16.
int subnet_stats_get_timeout(uint32_t ip);

// Get raw (scanned, hits) for a /16 subnet.
void subnet_stats_get(uint32_t ip, uint16_t *out_scanned, uint16_t *out_hits);

// Reset all counters (call between full passes).
void subnet_stats_reset(void);

#endif
