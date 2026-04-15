/*
 * API reporting to Go backend
 */

#ifndef API_H
#define API_H

#include "scanner.h"
#include "settings.h"
#include <stdbool.h>

// Check if libcurl is available
#ifdef HAVE_CURL

// Initialize API client
int api_init(void);

// Cleanup API client
void api_cleanup(void);

// Report server to API
int api_report_server(const server_info_t *info);

// Flush pending batch
void api_flush_batch(void);

// Check if API is available
bool api_is_available(void);

#else
// Stub implementations when curl is not available
static inline int api_init(void) { return 0; }
static inline void api_cleanup(void) {}
static inline int api_report_server(const server_info_t *info) { (void)info; return -1; }
static inline void api_flush_batch(void) {}
static inline bool api_is_available(void) { return false; }
#endif

#endif // API_H
