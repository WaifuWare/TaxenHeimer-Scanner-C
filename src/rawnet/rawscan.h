#ifndef RAWSCAN_H
#define RAWSCAN_H

#include "scanner/scanner.h"

// Requires CAP_NET_RAW. Returns -1 if raw sockets unavailable.
int rawscan_init(void);
void rawscan_shutdown(void);

// Drop-in replacement for scan_batch_async using raw sockets.
int rawscan_batch(char ips[][16], int count, scan_callback_t callback);

// Set interrupt flag for clean shutdown.
void rawscan_set_interrupt(volatile sig_atomic_t *flag);

#endif
