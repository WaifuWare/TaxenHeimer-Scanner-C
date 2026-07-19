#ifndef DEDUP_H
#define DEDUP_H

#include "scanner/scanner.h"
#include <stdint.h>

// Changed-fields bitmask
#define CHANGED_NEW          (1 << 0)
#define CHANGED_VERSION      (1 << 1)
#define CHANGED_MOTD         (1 << 2)
#define CHANGED_PLAYERS      (1 << 3)
#define CHANGED_MAX_PLAYERS  (1 << 4)

typedef enum {
    DEDUP_NEW,        // never seen
    DEDUP_CHANGED,    // seen before, something changed
    DEDUP_UNCHANGED,  // seen before, identical
} dedup_result_t;

// table_bits picks the table size: 1 << table_bits slots × sizeof(entry).
// Default = 22 (4 Mi slots ≈ 64 MiB) for full-internet Java scans. Pass
// a smaller value (e.g. 18 = 256 Ki slots ≈ 4 MiB) when the target
// universe is small — the bedrock public IP set worldwide fits there
// easily and the smaller table means fewer cache misses + drastically
// lower RSS. Must be in [12, 24]; values outside that range clamp.
void dedup_init(uint32_t table_bits);
void dedup_reset(void);

// Check if this server should be reported. Fills changed_fields bitmask.
dedup_result_t dedup_check(const server_info_t *info, uint32_t *changed_fields);

// dedup_trim scans the hash table a shard at a time and MADV_DONTNEEDs
// every page whose 256 entries are all empty (ip == 0). The page table
// entries stay mapped but physical memory is dropped, so RSS for the
// table settles at the working-set size instead of the peak touched-set
// size. Safe to call periodically — zero-filled on next access, which
// matches an empty hash slot. Caller is expected to run this on a slow
// cadence (minutes) from a background thread; it briefly holds each
// shard lock in turn.
void dedup_trim(void);

#endif
