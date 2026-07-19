/*
 * Statistics tracking
 *
 * Two counters:
 *   scanned — number of IPs that went through a probe (port scan, SYN, or
 *             full SLP). For HYBRID/SYNBLAST this is the prescan count;
 *             for EPOLL/IOURING/RAW/BEDROCK it's the full-check count.
 *   slp     — number of full SLP handshakes completed (success or fail).
 *             Tracks "real work" across modes. For non-hybrid engines slp
 *             equals scanned; for HYBRID/SYNBLAST slp << scanned because
 *             only prescan hits escalate to full SLP.
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

// Statistics structure
typedef struct {
    uint64_t scanned;
    uint64_t slp;
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
void stats_add_scanned(uint64_t n);
void stats_increment_slp(void);
void stats_increment_found(void);
void stats_increment_errors(void);
void stats_get(uint64_t *scanned, uint64_t *found, uint64_t *errors);
uint64_t stats_get_slp(void);

// Lifetime-average rates (scanned_total / uptime)
double stats_get_rate(void);

// EMA-smoothed instantaneous rates. Caller-agnostic: state lives in stats.c
// so TUI and log-only paths read the same number. Sample with each call;
// a min-interval guard inside avoids division-by-zero for rapid repeat calls.
double stats_get_instant_rate(void);
double stats_get_instant_slp_rate(void);

void stats_print(void);

#endif // STATS_H
