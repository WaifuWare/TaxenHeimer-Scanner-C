/*
 * XDP eBPF filter for TaxenHeimer prescan.
 *
 * Runs in the NIC driver hook before the kernel stack allocates an skb.
 * Inspects Ethernet → IPv4 → TCP; redirects TCP SYN-ACK packets originating
 * from port 25565 into the AF_XDP socket bound at xsks_map[queue_id], which
 * userspace drains via the RX ring. Everything else continues up the stack
 * so normal host traffic (SSH, DNS, etc.) is unaffected.
 *
 * Compile with clang -O2 -g -target bpf -c. Attach via bpf_xdp_attach().
 *
 * Verifier constraints:
 *   - All pointer derefs must be bounds-checked against data_end.
 *   - No unbounded loops (none needed here).
 *   - Stack ≤ 512 B.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MC_PORT 25565

// Map populated by userspace: key = queue_id, value = AF_XDP socket fd.
// BPF_MAP_TYPE_XSKMAP is the kernel type required by bpf_redirect_map
// for AF_XDP steering.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

// Drop counter — userspace reads this for diagnostics (how many non-MC
// packets bypassed the filter vs. redirected hits).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);  // [0] = pass, [1] = redirect
} stats_map SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats_map, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

SEC("xdp")
int taxen_prescan_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto pass;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto pass;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) goto pass;
    if (ip->protocol != IPPROTO_TCP) goto pass;

    // IP header may have options — use ihl
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip)) goto pass;
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end) goto pass;

    // Match SYN-ACK only, source port 25565 (reply from scanned server)
    if (tcp->source != bpf_htons(MC_PORT)) goto pass;
    if (!(tcp->syn && tcp->ack)) goto pass;

    bump_stat(1);
    // queue_id 0 — userspace binds AF_XDP socket to queue 0 for single-queue
    // NICs. Multi-queue support needs N sockets bound to N queues.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);

pass:
    bump_stat(0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
