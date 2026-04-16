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

void dedup_init(void);
void dedup_reset(void);

// Check if this server should be reported. Fills changed_fields bitmask.
dedup_result_t dedup_check(const server_info_t *info, uint32_t *changed_fields);

#endif
