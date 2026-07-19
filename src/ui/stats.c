/*
 * Statistics implementation
 */

#include "ui/stats.h"
#include <stdio.h>
#include <string.h>

// Global statistics
stats_t g_stats;

// EMA state — separate from g_stats so we can use a dedicated mutex and
// CLOCK_MONOTONIC without bloating the hot path.
static struct {
    struct timespec last_ts;
    uint64_t last_scanned;
    uint64_t last_slp;
    double   rate_scanned;
    double   rate_slp;
    pthread_mutex_t lock;
    int initialized;
} g_ema;

void stats_init(void) {
    memset(&g_stats, 0, sizeof(stats_t));
    g_stats.start_time = time(NULL);
    pthread_mutex_init(&g_stats.lock, NULL);

    memset(&g_ema, 0, sizeof(g_ema));
    pthread_mutex_init(&g_ema.lock, NULL);
}

void stats_increment_scanned(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.scanned++;
    pthread_mutex_unlock(&g_stats.lock);
}

void stats_add_scanned(uint64_t n) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.scanned += n;
    pthread_mutex_unlock(&g_stats.lock);
}

void stats_increment_slp(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.slp++;
    pthread_mutex_unlock(&g_stats.lock);
}

void stats_increment_found(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.found++;
    pthread_mutex_unlock(&g_stats.lock);
}

void stats_increment_errors(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.errors++;
    pthread_mutex_unlock(&g_stats.lock);
}

void stats_get(uint64_t *scanned, uint64_t *found, uint64_t *errors) {
    pthread_mutex_lock(&g_stats.lock);
    if (scanned) *scanned = g_stats.scanned;
    if (found) *found = g_stats.found;
    if (errors) *errors = g_stats.errors;
    pthread_mutex_unlock(&g_stats.lock);
}

uint64_t stats_get_slp(void) {
    pthread_mutex_lock(&g_stats.lock);
    uint64_t v = g_stats.slp;
    pthread_mutex_unlock(&g_stats.lock);
    return v;
}

double stats_get_rate(void) {
    pthread_mutex_lock(&g_stats.lock);
    time_t elapsed = time(NULL) - g_stats.start_time;
    double rate = elapsed > 0 ? (double)g_stats.scanned / elapsed : 0.0;
    pthread_mutex_unlock(&g_stats.lock);
    return rate;
}

// Shared EMA update. Returns current smoothed rates via out-params.
// alpha=0.4 matches the old TUI behaviour; guards dt<50ms to reuse the
// previous smoothed value so two quick callers (TUI + log-only) don't
// reset each other's state.
static void ema_sample(double *out_scanned_rate, double *out_slp_rate) {
    uint64_t scanned, slp;
    pthread_mutex_lock(&g_stats.lock);
    scanned = g_stats.scanned;
    slp     = g_stats.slp;
    pthread_mutex_unlock(&g_stats.lock);

    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);

    pthread_mutex_lock(&g_ema.lock);
    if (!g_ema.initialized) {
        g_ema.last_ts = now_ts;
        g_ema.last_scanned = scanned;
        g_ema.last_slp = slp;
        g_ema.initialized = 1;
        *out_scanned_rate = 0.0;
        *out_slp_rate = 0.0;
        pthread_mutex_unlock(&g_ema.lock);
        return;
    }
    double dt = (double)(now_ts.tv_sec - g_ema.last_ts.tv_sec)
              + (double)(now_ts.tv_nsec - g_ema.last_ts.tv_nsec) / 1e9;
    if (dt >= 0.05) {
        uint64_t d_scanned = scanned >= g_ema.last_scanned ? (scanned - g_ema.last_scanned) : 0;
        uint64_t d_slp     = slp     >= g_ema.last_slp     ? (slp     - g_ema.last_slp)     : 0;
        double instant_scanned = (double)d_scanned / dt;
        double instant_slp     = (double)d_slp     / dt;
        if (g_ema.rate_scanned == 0.0) g_ema.rate_scanned = instant_scanned;
        else g_ema.rate_scanned = g_ema.rate_scanned * 0.6 + instant_scanned * 0.4;
        if (g_ema.rate_slp == 0.0) g_ema.rate_slp = instant_slp;
        else g_ema.rate_slp = g_ema.rate_slp * 0.6 + instant_slp * 0.4;
        g_ema.last_ts = now_ts;
        g_ema.last_scanned = scanned;
        g_ema.last_slp = slp;
    }
    *out_scanned_rate = g_ema.rate_scanned;
    *out_slp_rate     = g_ema.rate_slp;
    pthread_mutex_unlock(&g_ema.lock);
}

double stats_get_instant_rate(void) {
    double s, l;
    ema_sample(&s, &l);
    return s;
}

double stats_get_instant_slp_rate(void) {
    double s, l;
    ema_sample(&s, &l);
    return l;
}

void stats_print(void) {
    uint64_t scanned, found, errors;
    double rate;

    pthread_mutex_lock(&g_stats.lock);
    scanned = g_stats.scanned;
    found = g_stats.found;
    errors = g_stats.errors;
    time_t elapsed = time(NULL) - g_stats.start_time;
    rate = elapsed > 0 ? (double)scanned / elapsed : 0.0;
    pthread_mutex_unlock(&g_stats.lock);

    printf("\r\033[KScanned: %lu | Found: %lu | Errors: %lu | Speed: %.1f ip/s",
           scanned, found, errors, rate);
    fflush(stdout);
}
