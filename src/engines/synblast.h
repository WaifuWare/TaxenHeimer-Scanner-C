/*
 * SYN prescan engine — blast SYNs, collect SYN-ACKs, feed responsive IPs
 * to worker threads for full Minecraft SLP probing.
 *
 * Much faster than full-connect scanning: only does SYN/RST, no TCP data
 * exchange. ~99.99% of IPs won't have port 25565 open, so eliminating them
 * at SYN speed gives 10-100x throughput improvement.
 *
 * Requires CAP_NET_RAW.
 */

#ifndef SYNBLAST_H
#define SYNBLAST_H

#include <signal.h>
#include <stdint.h>

typedef struct hit_queue hit_queue_t;

// Initialize SYN prescan engine. Returns 0 on success, -1 on failure.
int  synblast_init(void);
void synblast_shutdown(void);
void synblast_set_interrupt(volatile sig_atomic_t *flag);

// SYN-prescan a batch of IPs. Responsive IPs are pushed to the queue.
// Returns number of responsive IPs found.
int synblast_prescan(char ips[][16], int count, hit_queue_t *queue);

// Diagnostic counters
void synblast_get_stats(uint64_t *syns_sent, uint64_t *syns_failed,
                        uint64_t *rx_packets, uint64_t *synacks_recv);

#endif
