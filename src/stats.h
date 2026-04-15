/*
 * Statistics tracking
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

// Statistics structure
typedef struct {
    uint64_t scanned;
    uint64_t found;
    uint64_t errors;
    time_t start_time;
    pthread_mutex_t lock;
} stats_t;

// Global statistics
extern stats_t g_stats;

// Statistics functions
void stats_init(void);
void stats_increment_scanned(void);
void stats_increment_found(void);
void stats_increment_errors(void);
void stats_get(uint64_t *scanned, uint64_t *found, uint64_t *errors);
double stats_get_rate(void);
void stats_print(void);

#endif // STATS_H
