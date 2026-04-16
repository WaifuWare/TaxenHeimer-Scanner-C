#ifndef PRIORITY_H
#define PRIORITY_H

#include <stdint.h>

#define PRIORITY_FILE "subnet_stats.json"

// Reorder subnets by hit density. Top 20% by density first, rest shuffled.
// Uses per-/16 stats from subnet_stats module. Mutates the array in-place.
void priority_reorder(int32_t *subnets, int count);

// Persist hit counts for all subnets to disk.
void priority_save(const int32_t *subnets, int count);

// Load hit counts from disk into subnet_stats table.
void priority_load(void);

#endif
