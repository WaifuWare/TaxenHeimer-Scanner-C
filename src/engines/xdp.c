/*
 * AF_XDP prescan: redirect SYN-ACK replies from NIC driver straight into
 * userspace ring, parse, push IP to hit queue. TX reuses sendto() over
 * AF_INET raw socket from tcpkt.c for crafted SYN blasts.
 *
 * Build deps: pkg-config libbpf libxdp. BPF object compiled separately by
 * Makefile with clang -target bpf. Load at init() via libxdp.
 *
 * Frame layout (UMEM):
 *   UMEM is one big mmap'd buffer of N × FRAME_SIZE bytes. Each frame holds
 *   one packet. Fill ring tells kernel "here are addrs you can RX into".
 *   Completion ring (TX) unused here since we TX via raw socket.
 *
 * Runtime note: AF_XDP needs CAP_NET_ADMIN + CAP_BPF (or root). XDP_FLAGS
 * DRV_MODE falls back to SKB_MODE if the driver lacks native support; the
 * scanner logs which mode was negotiated so the operator can tell whether
 * they're getting the fast path.
 */

#define _GNU_SOURCE
#include "engines/xdp.h"
#include "engines/tcpkt.h"
#include "scanner/hitqueue.h"
#include "core/settings.h"
#include "core/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define NUM_FRAMES       4096
#define FRAME_SIZE       XSK_UMEM__DEFAULT_FRAME_SIZE   // 4096
#define FILL_SIZE        XSK_RING_PROD__DEFAULT_NUM_DESCS
#define COMP_SIZE        XSK_RING_CONS__DEFAULT_NUM_DESCS
#define RX_SIZE          XSK_RING_CONS__DEFAULT_NUM_DESCS
#define TX_SIZE          XSK_RING_PROD__DEFAULT_NUM_DESCS

#define RX_DRAIN_MAX     256     // CQEs reaped per drain loop
#define RX_DEADLINE_MS   200     // wait for replies this long per batch

typedef struct {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    void *umem_area;
    int   ifindex;
    int   queue_id;
    int   tx_raw_fd;        // separate raw socket for crafted SYN sends
    uint32_t src_ip;
    uint16_t src_port;
} xdp_ctx_t;

static xdp_ctx_t g_xdp;
static struct xdp_program *g_prog = NULL;
static int g_ready = 0;
static int g_stats_map_fd = -1;
static volatile sig_atomic_t *g_interrupt = NULL;

static uint64_t g_syns_sent   = 0;
static uint64_t g_syns_failed = 0;
static uint64_t g_rx_packets  = 0;
static uint64_t g_synacks     = 0;

void xdp_set_interrupt(volatile sig_atomic_t *flag) { g_interrupt = flag; }
static inline int xdp_interrupted(void) { return g_interrupt && *g_interrupt; }

// Locate the compiled BPF object. Search next to the binary, then /usr/lib.
static int find_bpf_object(char *out, size_t cap) {
    const char *candidates[] = {
        "./xdp_filter.bpf.o",
        "build/xdp_filter.bpf.o",
        "/usr/local/lib/taxenheimer/xdp_filter.bpf.o",
        "/usr/lib/taxenheimer/xdp_filter.bpf.o",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], R_OK) == 0) {
            snprintf(out, cap, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

// Silence libbpf/libxdp chatter. Emit WARN+ only; drop INFO/DEBUG so the
// TUI isn't scrolled off by noisy dispatcher-fallback and xdp_metadata
// ELF notes on every boot.
static int xdp_libbpf_print(enum libbpf_print_level level,
                            const char *fmt, va_list ap) {
    if (level > LIBBPF_WARN) return 0;
    return vfprintf(stderr, fmt, ap);
}

int xdp_init(const char *ifname, int queue_id) {
    libbpf_set_print(xdp_libbpf_print);
    if (!ifname || !*ifname) {
        log_error("xdp: interface name required (-i eth0)");
        return -1;
    }
    int ifidx = if_nametoindex(ifname);
    if (!ifidx) {
        log_error("xdp: interface '%s' not found", ifname);
        return -1;
    }

    // Discover source IP for the crafted SYN sender.
    char probe_if[IF_NAMESIZE] = {0};
    if (tcpkt_get_local_ip(&g_xdp.src_ip, probe_if, sizeof(probe_if)) < 0) {
        log_error("xdp: cannot resolve local IP on default route");
        return -1;
    }
    g_xdp.src_port = 54321;
    g_xdp.ifindex  = ifidx;
    g_xdp.queue_id = queue_id;

    // Allocate UMEM
    size_t umem_sz = (size_t)NUM_FRAMES * FRAME_SIZE;
    g_xdp.umem_area = mmap(NULL, umem_sz, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (g_xdp.umem_area == MAP_FAILED) {
        log_error("xdp: UMEM mmap failed: %s", strerror(errno));
        return -1;
    }

    struct xsk_umem_config ucfg = {
        .fill_size      = FILL_SIZE,
        .comp_size      = COMP_SIZE,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };
    int err = xsk_umem__create(&g_xdp.umem, g_xdp.umem_area, umem_sz,
                               &g_xdp.fill, &g_xdp.comp, &ucfg);
    if (err) {
        log_error("xdp: xsk_umem__create: %s", strerror(-err));
        munmap(g_xdp.umem_area, umem_sz);
        return -1;
    }

    // Pre-fill the RX ring so the driver has frames to copy into.
    uint32_t idx;
    uint32_t reserved = xsk_ring_prod__reserve(&g_xdp.fill, FILL_SIZE, &idx);
    if (reserved != FILL_SIZE) {
        log_error("xdp: fill-ring reserve short (%u/%u)", reserved, FILL_SIZE);
        xsk_umem__delete(g_xdp.umem);
        munmap(g_xdp.umem_area, umem_sz);
        return -1;
    }
    for (uint32_t i = 0; i < FILL_SIZE; i++) {
        *xsk_ring_prod__fill_addr(&g_xdp.fill, idx + i) = (uint64_t)i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&g_xdp.fill, FILL_SIZE);

    // Create AF_XDP socket bound to (ifindex, queue_id).
    struct xsk_socket_config xcfg = {
        .rx_size       = RX_SIZE,
        .tx_size       = TX_SIZE,
        .libbpf_flags  = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,  // we attach our own prog
        .xdp_flags     = XDP_FLAGS_DRV_MODE,                    // native driver hook
        .bind_flags    = XDP_USE_NEED_WAKEUP,
    };
    err = xsk_socket__create(&g_xdp.xsk, ifname, queue_id,
                             g_xdp.umem, &g_xdp.rx, NULL, &xcfg);
    if (err == -EOPNOTSUPP) {
        log_warn("xdp: driver lacks native XDP; falling back to SKB_MODE");
        xcfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        err = xsk_socket__create(&g_xdp.xsk, ifname, queue_id,
                                 g_xdp.umem, &g_xdp.rx, NULL, &xcfg);
    }
    if (err) {
        log_error("xdp: xsk_socket__create: %s", strerror(-err));
        xsk_umem__delete(g_xdp.umem);
        munmap(g_xdp.umem_area, umem_sz);
        return -1;
    }

    // Load + attach the BPF program.
    char bpf_path[512];
    if (find_bpf_object(bpf_path, sizeof(bpf_path)) < 0) {
        log_error("xdp: xdp_filter.bpf.o not found (build with 'make xdp-bpf')");
        goto err_sock;
    }
    g_prog = xdp_program__open_file(bpf_path, "xdp", NULL);
    if (libxdp_get_error(g_prog)) {
        log_error("xdp: open BPF object %s: %s", bpf_path,
                  strerror(-libxdp_get_error(g_prog)));
        g_prog = NULL;
        goto err_sock;
    }
    err = xdp_program__attach(g_prog, ifidx, XDP_MODE_NATIVE, 0);
    if (err == -EOPNOTSUPP) {
        log_warn("xdp: native attach unsupported; using SKB mode");
        err = xdp_program__attach(g_prog, ifidx, XDP_MODE_SKB, 0);
    }
    if (err) {
        log_error("xdp: attach failed on %s: %s", ifname, strerror(-err));
        goto err_prog;
    }

    // Populate xsks_map[queue_id] = AF_XDP socket fd
    struct bpf_object *obj = xdp_program__bpf_obj(g_prog);
    struct bpf_map *xsk_map = bpf_object__find_map_by_name(obj, "xsks_map");
    if (!xsk_map) {
        log_error("xdp: BPF object missing xsks_map");
        goto err_attach;
    }
    int map_fd = bpf_map__fd(xsk_map);
    int xsk_fd = xsk_socket__fd(g_xdp.xsk);
    if (bpf_map_update_elem(map_fd, &queue_id, &xsk_fd, BPF_ANY) < 0) {
        log_error("xdp: populate xsks_map: %s", strerror(errno));
        goto err_attach;
    }

    struct bpf_map *stats = bpf_object__find_map_by_name(obj, "stats_map");
    g_stats_map_fd = stats ? bpf_map__fd(stats) : -1;

    // Crafted-SYN TX socket (raw IP, kernel computes nothing — we fill everything)
    g_xdp.tx_raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (g_xdp.tx_raw_fd < 0) {
        log_error("xdp: TX raw socket: %s (need CAP_NET_RAW)", strerror(errno));
        goto err_attach;
    }
    int one = 1;
    setsockopt(g_xdp.tx_raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    g_ready = 1;
    log_info("xdp: attached to %s (ifidx=%d, queue=%d, src_ip=%u.%u.%u.%u)",
             ifname, ifidx, queue_id,
             (g_xdp.src_ip >> 24) & 0xFF, (g_xdp.src_ip >> 16) & 0xFF,
             (g_xdp.src_ip >> 8)  & 0xFF, g_xdp.src_ip & 0xFF);
    return 0;

err_attach:
    xdp_program__detach(g_prog, ifidx, XDP_MODE_NATIVE, 0);
err_prog:
    xdp_program__close(g_prog);
    g_prog = NULL;
err_sock:
    xsk_socket__delete(g_xdp.xsk);
    xsk_umem__delete(g_xdp.umem);
    munmap(g_xdp.umem_area, (size_t)NUM_FRAMES * FRAME_SIZE);
    return -1;
}

void xdp_shutdown(void) {
    if (!g_ready) return;
    if (g_xdp.tx_raw_fd >= 0) close(g_xdp.tx_raw_fd);
    if (g_prog) {
        xdp_program__detach(g_prog, g_xdp.ifindex, XDP_MODE_NATIVE, 0);
        xdp_program__close(g_prog);
        g_prog = NULL;
    }
    if (g_xdp.xsk) xsk_socket__delete(g_xdp.xsk);
    if (g_xdp.umem) xsk_umem__delete(g_xdp.umem);
    if (g_xdp.umem_area) munmap(g_xdp.umem_area, (size_t)NUM_FRAMES * FRAME_SIZE);
    g_ready = 0;
}

// Drain the RX ring once: parse each packet, extract src IP, push to queue.
// Returns number of frames drained.
static int drain_rx(hit_queue_t *queue) {
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    int n = xsk_ring_cons__peek(&g_xdp.rx, RX_DRAIN_MAX, &idx_rx);
    if (n <= 0) return 0;

    // Reserve fill-ring slots for re-submission of the frames we're consuming.
    uint32_t reserved = xsk_ring_prod__reserve(&g_xdp.fill, n, &idx_fq);
    while (reserved < (uint32_t)n) {
        // Fill ring full — kernel will keep us from RXing more until we drain.
        // Shouldn't happen under normal operation; just recycle what we can.
        n = (int)reserved;
        if (n == 0) return 0;
        break;
    }

    for (int i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&g_xdp.rx, idx_rx + i);
        uint8_t *pkt = xsk_umem__get_data(g_xdp.umem_area, d->addr);
        uint32_t len = d->len;

        g_rx_packets++;

        // Parse Eth + IPv4 + TCP. Redundant guard since BPF already filtered;
        // cheap insurance against misconfigured maps on older kernels.
        if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
            goto recycle;
        struct ethhdr *eth = (struct ethhdr *)pkt;
        if (eth->h_proto != htons(ETH_P_IP)) goto recycle;
        struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_TCP) goto recycle;
        uint32_t ip_hlen = ip->ihl * 4;
        struct tcphdr *tcp = (struct tcphdr *)((uint8_t *)ip + ip_hlen);
        if (!(tcp->syn && tcp->ack)) goto recycle;
        if (tcp->source != htons(MINECRAFT_PORT)) goto recycle;

        uint32_t src_ip = ntohl(ip->saddr);
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                 (src_ip >> 8)  & 0xFF, src_ip & 0xFF);
        hitqueue_push(queue, ip_str);
        g_synacks++;

recycle:
        *xsk_ring_prod__fill_addr(&g_xdp.fill, idx_fq + i) = d->addr;
    }

    xsk_ring_cons__release(&g_xdp.rx, n);
    xsk_ring_prod__submit(&g_xdp.fill, n);
    return n;
}

// Send one crafted SYN via the raw IP socket.
static int tx_syn(uint32_t dst_ip) {
    uint8_t buf[64];
    uint32_t seq = (uint32_t)rand();
    int len = tcpkt_build_syn(buf, sizeof(buf),
                              g_xdp.src_ip, g_xdp.src_port,
                              dst_ip, MINECRAFT_PORT, seq);
    if (len <= 0) return -1;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MINECRAFT_PORT);
    dst.sin_addr.s_addr = htonl(dst_ip);

    ssize_t n = sendto(g_xdp.tx_raw_fd, buf, len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (n < 0) { g_syns_failed++; return -1; }
    g_syns_sent++;
    return 0;
}

int xdp_prescan(char ips[][16], int count, hit_queue_t *queue) {
    if (!g_ready || count <= 0) return 0;

    // Blast SYNs. Drain RX periodically so the ring doesn't overflow on
    // bursts of replies from previously-scanned subnets.
    for (int i = 0; i < count && !xdp_interrupted(); i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, ips[i], &a) != 1) continue;
        tx_syn(ntohl(a.s_addr));
        if ((i & 255) == 255) drain_rx(queue);
    }

    // Wait for late replies until deadline expires.
    struct timespec deadline, now;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += RX_DEADLINE_MS / 1000;
    deadline.tv_nsec += (RX_DEADLINE_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    while (!xdp_interrupted()) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long rem_ms = (deadline.tv_sec - now.tv_sec) * 1000
                    + (deadline.tv_nsec - now.tv_nsec) / 1000000;
        if (rem_ms <= 0) break;
        int drained = drain_rx(queue);
        if (drained == 0) {
            // Short sleep to avoid busy-spinning the CPU during idle periods.
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    return (int)g_synacks;
}

void xdp_get_stats(uint64_t *syns_sent, uint64_t *syns_failed,
                   uint64_t *rx_packets, uint64_t *synacks_recv) {
    if (syns_sent)    *syns_sent    = g_syns_sent;
    if (syns_failed)  *syns_failed  = g_syns_failed;
    if (rx_packets)   *rx_packets   = g_rx_packets;
    if (synacks_recv) *synacks_recv = g_synacks;
}
