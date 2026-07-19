/*
 * XDP + AF_XDP prescan.
 *
 * Replaces synblast's AF_PACKET RX path with an XDP program that redirects
 * SYN-ACK packets straight from the NIC driver hook into a userspace ring
 * buffer, skipping the kernel stack. Typical gain: 5-15x over AF_PACKET
 * on the same NIC, mostly from skipping skb allocation + netfilter + TCP.
 *
 * TX still uses synblast's crafted-SYN sender (tcpkt.c) — XDP_TX would
 * also work but requires per-packet header construction inside the BPF
 * program, and SYN floods benefit more from userspace-batched sendmmsg.
 *
 * Requirements:
 *   - Kernel 5.4+ (AF_XDP stable) — 5.10+ preferred for needs-wakeup mode.
 *   - libbpf + libxdp build-time deps.
 *   - Compiled BPF object (xdp_filter.bpf.o) co-located with the binary.
 *   - CAP_NET_ADMIN + CAP_BPF (or CAP_SYS_ADMIN on older kernels).
 *   - NIC driver with native XDP support (virtio-net, i40e, ice, mlx5,
 *     ixgbe, …). Generic XDP works but halves the throughput gain.
 *
 * Runtime:
 *   - Pass target interface name + queue id via xdp_init(ifname, queue_id).
 *   - Userspace polls RX ring, extracts IP/port, pushes to hit queue.
 */

#ifndef XDP_H
#define XDP_H

#include <signal.h>
#include <stdint.h>

typedef struct hit_queue hit_queue_t;

int  xdp_init(const char *ifname, int queue_id);
void xdp_shutdown(void);

void xdp_set_interrupt(volatile sig_atomic_t *flag);

// Probe: send SYNs to the given IPs, drain XDP ring for SYN-ACK replies,
// push responders onto `queue`. Same interface as synblast_prescan so the
// main.c hybrid pipeline can swap between them without structural change.
int xdp_prescan(char ips[][16], int count, hit_queue_t *queue);

// Diagnostics: pass / redirect counters mirrored from BPF stats_map.
void xdp_get_stats(uint64_t *syns_sent, uint64_t *syns_failed,
                   uint64_t *rx_packets, uint64_t *synacks_recv);

#endif
