/*
 * API reporting to Go backend via Unix domain socket IPC
 */

#ifndef API_H
#define API_H

#include "scanner.h"
#include "settings.h"
#include <stdbool.h>

// Initialize API client
int api_init(void);

// Cleanup API client
void api_cleanup(void);

// Report server to API (adds to current batch; sends when batch fills)
int api_report_server(const server_info_t *info);

// Flush pending batch (call on shutdown)
void api_flush_batch(void);

// Check if API is available
bool api_is_available(void);

#endif // API_H
