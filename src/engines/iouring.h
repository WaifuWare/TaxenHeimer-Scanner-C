/*
 * io_uring-based SLP scanner — async connect/send/recv via kernel ring.
 *
 * Drop-in replacement for scan_batch_async(). Works behind NAT (kernel TCP).
 * No CAP_NET_RAW needed. Requires kernel 5.6+ (IORING_OP_CONNECT/SEND/RECV).
 *
 * Typical win over epoll: fewer syscalls per scan (SQE submission batches
 * many ops in one io_uring_enter() vs. N epoll_ctl + send/recv/close),
 * plus the kernel can drain completions without a context switch.
 */

#ifndef IOURING_H
#define IOURING_H

#include <signal.h>
#include "scanner/scanner.h"

// Probe kernel for required ops. Returns 0 if supported, -1 otherwise.
int iouring_init(void);
void iouring_shutdown(void);

void iouring_set_interrupt(volatile sig_atomic_t *flag);

// Scan a batch of IPs asynchronously via io_uring. Same semantics as
// scan_batch_async. Callback invoked per IP (success or fail).
int iouring_scan_batch(char ips[][16], int count, scan_callback_t callback);

#endif
