/*
 * Kernel-based port prescan — fast connect() probe to detect open ports.
 *
 * Works behind NAT (uses kernel TCP stack → conntrack → NAT mapping).
 * No CAP_NET_RAW needed. ~10-50k IPs/sec with 1024 concurrent probes.
 *
 * Same interface as synblast: probe batch → push responsive IPs to queue.
 */

#ifndef PORTSCAN_H
#define PORTSCAN_H

#include <signal.h>
#include <stdint.h>

typedef struct hit_queue hit_queue_t;

void portscan_init(void);
void portscan_set_interrupt(volatile sig_atomic_t *flag);

// Probe a batch of IPs using non-blocking connect().
// Open ports pushed to queue. Returns number of open ports found.
int portscan_prescan(char ips[][16], int count, hit_queue_t *queue);

// Diagnostic counters
void portscan_get_stats(uint64_t *probed, uint64_t *open);

#endif
