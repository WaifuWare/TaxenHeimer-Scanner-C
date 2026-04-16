/*
 * Statistics implementation
 */

#include "ui/stats.h"
#include <stdio.h>
#include <string.h>

// Global statistics
stats_t g_stats;

// Initialize statistics
void stats_init(void) {
    memset(&g_stats, 0, sizeof(stats_t));
    g_stats.start_time = time(NULL);
    pthread_mutex_init(&g_stats.lock, NULL);
}

// Increment scanned counter
void stats_increment_scanned(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.scanned++;
    pthread_mutex_unlock(&g_stats.lock);
}

// Add N to scanned counter (batch increment for prescan thread)
void stats_add_scanned(uint64_t n) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.scanned += n;
    pthread_mutex_unlock(&g_stats.lock);
}

// Increment found counter
void stats_increment_found(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.found++;
    pthread_mutex_unlock(&g_stats.lock);
}

// Increment errors counter
void stats_increment_errors(void) {
    pthread_mutex_lock(&g_stats.lock);
    g_stats.errors++;
    pthread_mutex_unlock(&g_stats.lock);
}

// Get current statistics
void stats_get(uint64_t *scanned, uint64_t *found, uint64_t *errors) {
    pthread_mutex_lock(&g_stats.lock);
    if (scanned) *scanned = g_stats.scanned;
    if (found) *found = g_stats.found;
    if (errors) *errors = g_stats.errors;
    pthread_mutex_unlock(&g_stats.lock);
}

// Get scan rate (IPs per second)
double stats_get_rate(void) {
    pthread_mutex_lock(&g_stats.lock);
    time_t elapsed = time(NULL) - g_stats.start_time;
    double rate = elapsed > 0 ? (double)g_stats.scanned / elapsed : 0.0;
    pthread_mutex_unlock(&g_stats.lock);
    return rate;
}

// Print statistics (single lock acquisition)
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
