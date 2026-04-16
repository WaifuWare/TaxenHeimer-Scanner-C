#include "scanner/priority.h"
#include "scanner/subnet_stats.h"
#include "core/log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int32_t subnet;
    uint16_t hits;
} scored_t;

static int cmp_hits_desc(const void *a, const void *b) {
    return (int)((const scored_t *)b)->hits - (int)((const scored_t *)a)->hits;
}

void priority_reorder(int32_t *subnets, int count) {
    if (count <= 1) return;

    scored_t *scored = (scored_t *)malloc(sizeof(scored_t) * (size_t)count);
    if (!scored) return;

    int with_hits = 0;
    for (int i = 0; i < count; i++) {
        scored[i].subnet = subnets[i];
        uint16_t scanned, hits;
        subnet_stats_get((uint32_t)subnets[i], &scanned, &hits);
        scored[i].hits = hits;
        if (hits > 0) with_hits++;
    }

    // Sort by hits descending — high-yield subnets bubble to top
    qsort(scored, (size_t)count, sizeof(scored_t), cmp_hits_desc);

    // Top portion (those with hits) stays sorted by density.
    // Bottom portion (zero hits) gets shuffled so we don't always scan same order.
    srand((unsigned)time(NULL));
    for (int i = count - 1; i > with_hits; i--) {
        int j = with_hits + (rand() % (i - with_hits + 1));
        scored_t tmp = scored[i]; scored[i] = scored[j]; scored[j] = tmp;
    }

    // Write back
    for (int i = 0; i < count; i++) {
        subnets[i] = scored[i].subnet;
    }

    log_info("Priority reorder: %d with hits (first), %d shuffled", with_hits, count - with_hits);
    free(scored);
}

void priority_save(const int32_t *subnets, int count) {
    (void)subnets; (void)count;
}

void priority_load(void) {
}
