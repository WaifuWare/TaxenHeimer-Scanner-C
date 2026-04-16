/*
 * Terminal UI for scanner
 */

#ifndef UI_H
#define UI_H

#include "ui/stats.h"
#include "scanner/scanner.h"

// Initialize UI
void ui_init(void);

// Shutdown UI
void ui_shutdown(void);

// Print banner
void ui_print_banner(void);

// Print configuration
void ui_print_config(int threads, int subnets, int port, int timeout_ms);

// Print server found with full details
void ui_print_server(const server_info_t *info);

// Print statistics
void ui_print_stats(void);

// Print final summary
void ui_print_summary(uint64_t scanned, uint64_t found, uint64_t errors);

// Render fancy header (like Nim version)
void ui_render_header(int current_subnet, int total_subnets, int host_offset, int host_total);

// Log message with timestamp
void ui_log(const char *level, const char *message);

// Thread-safe print for shutdown messages
void ui_print_shutdown_message(const char *message);

#endif // UI_H
