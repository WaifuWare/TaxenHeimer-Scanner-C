/*
 * TaxenHeimer C Scanner - Main Entry Point
 * Minecraft server scanner rewritten in C
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <sys/resource.h>

#include "protocol/packet.h"
#include "scanner/scanner.h"
#include "util/utils.h"
#include "ui/stats.h"
#include "scanner/ranges.h"
#include "scanner/subnet_stats.h"
#include "scanner/dedup.h"
#include "scanner/priority.h"
#include "rawnet/rawscan.h"
#include "rawnet/synblast.h"
#include "scanner/hitqueue.h"
#include "scanner/portscan.h"
#include "net/api.h"
#include "core/settings.h"
#include "ui/ui.h"
#include "core/config.h"
#include "core/log.h"

// Global state
static volatile sig_atomic_t interrupted = 0;
static pthread_mutex_t subnet_lock = PTHREAD_MUTEX_INITIALIZER;
static int current_subnet_idx = 0;
static int32_t current_host_offset = 0;  // Track actual progress
static uint32_t threads_finished_mask = 0;  // Bitmask for thread states (saves 11 bytes)
static volatile int pass_completed = 0;     // Set by worker when full pass wraps
static int use_rawscan = 0;                 // 1 = raw socket mode active
static int use_hybrid = 0;                  // 1 = prescan + kernel TCP SLP workers
static int use_synblast = 0;               // 1 = raw SYN prescan, 0 = kernel connect prescan
static config_t g_config;
static hit_queue_t g_hit_queue;             // prescan → worker queue (hybrid mode)

// Thread argument structure
typedef struct {
    int32_t *subnets;
    int subnet_count;
    int thread_id;
    int32_t start_host_offset;
} thread_arg_t;

// Callback for found servers
static void on_server_found(const server_info_t *info) {
    // Feed adaptive timeout stats
    uint32_t ip_int = ip_to_int(info->ip);
    subnet_stats_record(ip_int, info->success ? 1 : 0);

    if (!info->success) {
        stats_increment_errors();
        stats_increment_scanned();
        return;
    }

    stats_increment_found();
    stats_increment_scanned();

    // Dedup: skip reporting unchanged servers
    uint32_t changed_fields = 0;
    dedup_result_t dr = dedup_check(info, &changed_fields);
    if (dr == DEDUP_UNCHANGED) {
        return;
    }

    // Print found server with all details
    ui_print_server(info);

    // Report to API (non-blocking)
    api_report_server(info);
}

// ─── Hybrid mode: prescan thread ─────────────────────────────────────────────
// Walks subnets, blasts SYNs, pushes responsive IPs to hit queue.
// Single-threaded — no subnet lock contention since it's the only producer.

static void *prescan_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    int32_t host_offset = targ->start_host_offset;

    while (!interrupted) {
        int local_subnet_idx = current_subnet_idx;

        if (local_subnet_idx >= targ->subnet_count) {
            current_subnet_idx = 0;
            local_subnet_idx = 0;
            host_offset = 0;
            pass_completed = 1;
        }

        // Collect IPs — larger batches since SYN blast is cheap
        int pool_size = IP_POOL * NUM_THREADS;  // grab what all threads would have
        char (*ips)[16] = malloc(sizeof(char[16]) * (size_t)pool_size);
        if (!ips) break;
        int ip_count = 0;

        for (int i = 0; i < pool_size * 20 && ip_count < pool_size && !interrupted; i++) {
            if (host_offset >= (1 << RANGE_SCANNER_SUBNET)) {
                current_subnet_idx++;
                current_host_offset = 0;
                if (current_subnet_idx >= targ->subnet_count) {
                    current_subnet_idx = 0;
                    pass_completed = 1;
                }
                local_subnet_idx = current_subnet_idx;
                host_offset = 0;
                break;
            }

            uint32_t subnet = (uint32_t)targ->subnets[local_subnet_idx];
            uint32_t ip_int = subnet | (uint32_t)host_offset;
            host_offset++;

            if ((host_offset & 0xFF) == 0) {
                current_host_offset = host_offset;
            }

            if (check_valid_ip(ip_int)) {
                int_to_ip(ip_int, ips[ip_count]);
                ip_count++;
            }
        }

        if (ip_count > 0) {
            // Count all probed IPs as scanned (non-responsive won't go through callback)
            stats_add_scanned((uint64_t)ip_count);

            // Prescan: detect open ports and push to worker queue
            if (use_synblast)
                synblast_prescan(ips, ip_count, &g_hit_queue);
            else
                portscan_prescan(ips, ip_count, &g_hit_queue);
        }

        free(ips);
    }

    // Signal workers to stop once prescan is done
    hitqueue_shutdown(&g_hit_queue);
    return NULL;
}

// ─── Hybrid mode: worker thread ──────────────────────────────────────────────
// Pulls responsive IPs from hit queue, does full SLP via kernel TCP.

static void on_hybrid_server_found(const server_info_t *info) {
    // Don't increment scanned — prescan thread already counted these
    uint32_t ip_int = ip_to_int(info->ip);
    subnet_stats_record(ip_int, info->success ? 1 : 0);

    if (!info->success) {
        stats_increment_errors();
        return;
    }

    stats_increment_found();

    uint32_t changed_fields = 0;
    dedup_result_t dr = dedup_check(info, &changed_fields);
    if (dr == DEDUP_UNCHANGED) return;

    ui_print_server(info);
    api_report_server(info);
}

static void *hybrid_worker_thread(void *arg) {
    (void)arg;

    char ips[SCAN_BATCH][16];

    while (!interrupted) {
        int count = hitqueue_pop_batch(&g_hit_queue, ips, SCAN_BATCH);
        if (count <= 0) break;

        scan_batch_async(ips, count, on_hybrid_server_found);
    }

    return NULL;
}

// Signal handler. Must call only async-signal-safe functions — POSIX lists
// write() as safe but printf/fflush/pthread_mutex_lock are NOT. The prior
// version called ui_print_shutdown_message which grabs a mutex and runs
// stdio; delivering SIGINT while any other thread held that mutex deadlocked
// the process. Here we just flip the flag and emit a fixed banner via
// write(); the main thread shows the friendly shutdown message.
static void signal_handler(int signum) {
    (void)signum;
    interrupted = 1;
    static const char msg[] = "\n[shutting down]\n";
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
}

// Scanner thread function
static void *scanner_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    int32_t host_offset = targ->start_host_offset;
    
    while (!interrupted) {
        // Get current subnet
        pthread_mutex_lock(&subnet_lock);
        int local_subnet_idx = current_subnet_idx;
        pthread_mutex_unlock(&subnet_lock);
        
        if (local_subnet_idx >= targ->subnet_count) {
            pthread_mutex_lock(&subnet_lock);
            current_subnet_idx = 0;
            local_subnet_idx = 0;
            pthread_mutex_unlock(&subnet_lock);
            host_offset = targ->thread_id;
        }
        
        // Collect IPs
        char ips[IP_POOL][16];
        int ip_count = 0;
        
        for (int i = 0; i < IP_POOL * 20 && ip_count < IP_POOL && !interrupted; i++) {
            if (host_offset >= (1 << RANGE_SCANNER_SUBNET)) {
                // Thread finished subnet
                pthread_mutex_lock(&subnet_lock);
                threads_finished_mask |= (1U << targ->thread_id);  // Set bit for this thread
                
                // Check if all threads finished (all bits set)
                uint32_t all_finished_mask = (1U << NUM_THREADS) - 1;
                if (threads_finished_mask == all_finished_mask) {
                    current_subnet_idx++;
                    if (current_subnet_idx >= targ->subnet_count) {
                        current_subnet_idx = 0;
                        pass_completed = 1;
                    }
                    threads_finished_mask = 0;
                    current_host_offset = 0;
                }
                
                local_subnet_idx = current_subnet_idx;
                pthread_mutex_unlock(&subnet_lock);
                host_offset = targ->thread_id;
                break;
            }
            
            uint32_t subnet = (uint32_t)targ->subnets[local_subnet_idx];
            uint32_t ip_int = subnet | (uint32_t)host_offset;
            
            host_offset += NUM_THREADS;

            // Update progress tracker — all threads contribute so bar reflects
            // the true frontier instead of just thread 0's stride.
            if ((host_offset & 0xFF) == 0) {  // throttle lock traffic
                pthread_mutex_lock(&subnet_lock);
                if (host_offset > current_host_offset) {
                    current_host_offset = host_offset;
                }
                pthread_mutex_unlock(&subnet_lock);
            }
            
            if (check_valid_ip(ip_int)) {
                int_to_ip(ip_int, ips[ip_count]);
                ip_count++;
            }
        }
        
        // Scan collected IPs concurrently
        if (use_rawscan)
            rawscan_batch(ips, ip_count, on_server_found);
        else
            scan_batch_async(ips, ip_count, on_server_found);
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    // Parse CLI. Scan mode is runtime-only now: pass -f each run for full
    // IPv4; absence selects the known-ranges list. There is no persisted
    // "current mode" — each mode keeps its own resume cursor in config.json.
    bool cli_full = false;
    bool cli_raw = false;
    bool cli_hybrid = false;
    bool cli_synblast = false;
    bool cli_log_only = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0 || strcmp(argv[i], "-f") == 0) {
            cli_full = true;
        } else if (strcmp(argv[i], "--raw") == 0 || strcmp(argv[i], "-r") == 0) {
            cli_raw = true;
        } else if (strcmp(argv[i], "--hybrid") == 0 || strcmp(argv[i], "-H") == 0) {
            cli_hybrid = true;
        } else if (strcmp(argv[i], "--synblast") == 0 || strcmp(argv[i], "-S") == 0) {
            cli_synblast = true;
        } else if (strcmp(argv[i], "--log-only") == 0 || strcmp(argv[i], "-l") == 0) {
            cli_log_only = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -f, --full       Scan the entire routable IPv4 space (default: known /16s)\n");
            printf("  -r, --raw        Use raw sockets (bypass kernel TCP, needs CAP_NET_RAW)\n");
            printf("  -H, --hybrid     Fast connect prescan + kernel TCP SLP (works behind NAT)\n");
            printf("  -S, --synblast   Raw SYN prescan + kernel TCP SLP (needs public IP + CAP_NET_RAW)\n");
            printf("  -l, --log-only   Disable TUI; emit plain timestamped log lines (auto when stdout is not a TTY)\n");
            printf("  -h, --help       Show this help\n");
            return 0;
        }
    }

    if (cli_log_only) ui_set_log_only(1);

    // Raise file descriptor limit — hybrid/synblast modes need many concurrent FDs
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;  // raise soft to hard limit
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    // Setup signal handlers
    // SIGPIPE: silently ignore. A scanned server RSTing mid-send, or the Go
    // backend disappearing, would otherwise kill the process outright with
    // no log. Individual write() calls still return EPIPE which the callers
    // already handle.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Wire interrupt flag into scanner so async loops abort on shutdown
    scanner_set_interrupt_flag(&interrupted);

    // Load config
    g_config = config_load();

    // Scan mode is chosen per-run; config.json stores separate resume cursors
    // for known vs full so flipping between them doesn't lose either.
    scan_mode_t desired_mode = cli_full ? SCAN_MODE_FULL_IPV4 : SCAN_MODE_KNOWN;
    int     cfg_subnet_idx   = (desired_mode == SCAN_MODE_FULL_IPV4) ? g_config.full_subnet_idx    : g_config.known_subnet_idx;
    int32_t cfg_host_offset  = (desired_mode == SCAN_MODE_FULL_IPV4) ? g_config.full_host_offset   : g_config.known_host_offset;

    // Initialize socket pool
    scanner_init_pool();

    // Initialize UI first so log messages appear in TUI scroll region
    ui_init();

    // Try raw socket mode if requested
    if (cli_raw && !cli_hybrid) {
        rawscan_set_interrupt(&interrupted);
        if (rawscan_init() == 0) {
            use_rawscan = 1;
            log_info("Raw socket scanner active — bypass kernel TCP");
        } else {
            log_error("Raw socket init failed — need CAP_NET_RAW: sudo setcap cap_net_raw+ep ./scanner");
            log_warn("Falling back to EPOLL mode");
        }
    }

    // Hybrid mode: kernel connect prescan (works behind NAT, no special caps)
    if (cli_hybrid && !cli_synblast) {
        portscan_init();
        portscan_set_interrupt(&interrupted);
        use_hybrid = 1;
        use_synblast = 0;
        hitqueue_init(&g_hit_queue);
        log_info("Hybrid mode active — connect prescan + kernel TCP SLP");
    }

    // Synblast mode: raw SYN prescan (needs public IP + CAP_NET_RAW)
    if (cli_synblast) {
        synblast_set_interrupt(&interrupted);
        if (synblast_init() == 0) {
            use_hybrid = 1;
            use_synblast = 1;
            hitqueue_init(&g_hit_queue);
            log_info("Synblast mode active — raw SYN prescan + kernel TCP SLP");
        } else {
            log_error("Synblast init failed — need CAP_NET_RAW: sudo setcap cap_net_raw+ep ./scanner");
            log_warn("Falling back to EPOLL mode");
        }
    }

    // Set engine label for TUI header
    if (use_hybrid && use_synblast) ui_set_engine("SYNBLAST");
    else if (use_hybrid) ui_set_engine("HYBRID");
    else if (use_rawscan) ui_set_engine("RAW");
    else ui_set_engine("EPOLL");

    // Initialize API client
    api_init();

    // Initialize statistics
    stats_init();

    // Initialize subnet adaptive timeout stats
    subnet_stats_init();

    // Initialize dedup table (~64 MB)
    dedup_init();

    // Build mutable subnet array based on mode (mutable for priority reorder).
    int subnet_count = 0;
    int32_t *subnets = NULL;

    if (desired_mode == SCAN_MODE_FULL_IPV4) {
        subnets = ranges_build_full_ipv4(&subnet_count);
        if (!subnets || subnet_count == 0) {
            log_error("Failed to build full IPv4 range list");
            return 1;
        }
        log_info("Scan mode: FULL IPv4 (%d routable /16 subnets)", subnet_count);
    } else {
        subnet_count = KNOWN_RANGES_COUNT;
        subnets = (int32_t *)malloc(sizeof(int32_t) * (size_t)subnet_count);
        if (!subnets) { log_error("alloc failed"); return 1; }
        memcpy(subnets, KNOWN_RANGES, sizeof(int32_t) * (size_t)subnet_count);
        log_info("Scan mode: KNOWN ranges (%d subnets)", subnet_count);
    }

    // Load saved priority data and apply initial reorder
    priority_load();

    // Clamp resume position to current subnet count (mode's list may have
    // shrunk between runs — reset cleanly rather than scanning phantom
    // entries).
    if (cfg_subnet_idx >= subnet_count || cfg_subnet_idx < 0) {
        cfg_subnet_idx = 0;
        cfg_host_offset = 0;
    }

    // Set initial subnet from config
    current_subnet_idx = cfg_subnet_idx;

    // Spread worker threads across all available CPU cores
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;

    // Thread count: hybrid uses 1 prescan + NUM_THREADS workers
    int total_threads = use_hybrid ? NUM_THREADS + 1 : NUM_THREADS;
    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)total_threads);
    thread_arg_t thread_args[NUM_THREADS + 1];  // +1 for prescan thread

    if (use_hybrid) {
        log_info("Detected %d CPUs — 1 prescan + %d SLP workers", ncpus, NUM_THREADS);

        // Start prescan thread (walks subnets, blasts SYNs)
        thread_args[0].subnets = subnets;
        thread_args[0].subnet_count = subnet_count;
        thread_args[0].thread_id = 0;
        thread_args[0].start_host_offset = cfg_host_offset;

        if (pthread_create(&threads[0], NULL, prescan_thread, &thread_args[0]) != 0) {
            log_error("Failed to create prescan thread");
            free(threads);
            return 1;
        }
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        pthread_setaffinity_np(threads[0], sizeof(cpuset), &cpuset);

        // Start worker threads (pull from queue, do SLP)
        for (int i = 0; i < NUM_THREADS; i++) {
            if (pthread_create(&threads[1 + i], NULL, hybrid_worker_thread, NULL) != 0) {
                log_error("Failed to create hybrid worker %d", i);
                free(threads);
                return 1;
            }
            CPU_ZERO(&cpuset);
            CPU_SET((1 + i) % ncpus, &cpuset);
            pthread_setaffinity_np(threads[1 + i], sizeof(cpuset), &cpuset);
        }
    } else {
        log_info("Detected %d CPUs — spreading %d workers", ncpus, NUM_THREADS);

        for (int i = 0; i < NUM_THREADS; i++) {
            thread_args[i].subnets = subnets;
            thread_args[i].subnet_count = subnet_count;
            thread_args[i].thread_id = i;
            thread_args[i].start_host_offset = cfg_host_offset + i;

            if (pthread_create(&threads[i], NULL, scanner_thread, &thread_args[i]) != 0) {
                log_error("Failed to create thread %d", i);
                free(threads);
                return 1;
            }

            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(i % ncpus, &cpuset);
            int rc = pthread_setaffinity_np(threads[i], sizeof(cpuset), &cpuset);
            if (rc != 0) {
                log_warn("pthread_setaffinity_np failed for thread %d: %d", i, rc);
            }
        }
    }
    
    // Stats display loop - also save config periodically
    int save_counter = 0;
    while (!interrupted) {
        usleep(500 * 1000);  // 500 ms refresh

        // Handle full-pass completion: reorder subnets + reset dedup
        if (pass_completed) {
            pass_completed = 0;
            log_info("Full pass completed — reordering subnets by hit density");
            pthread_mutex_lock(&subnet_lock);
            priority_reorder(subnets, subnet_count);
            pthread_mutex_unlock(&subnet_lock);
            dedup_reset();
            subnet_stats_reset();
        }

        // Feed prescan stats to UI (hybrid/synblast mode)
        if (use_hybrid && use_synblast) {
            uint64_t syns, fails, rxpkts, acks;
            synblast_get_stats(&syns, &fails, &rxpkts, &acks);
            ui_set_prescan_stats(syns, fails, rxpkts, acks);
        } else if (use_hybrid) {
            uint64_t probed, open;
            portscan_get_stats(&probed, &open);
            ui_set_prescan_stats(probed, 0, 0, open);
        }

        // Render fancy header
        pthread_mutex_lock(&subnet_lock);
        ui_render_header(current_subnet_idx, subnet_count,
                        current_host_offset, 1 << RANGE_SCANNER_SUBNET);
        pthread_mutex_unlock(&subnet_lock);

        // Save config every 30 seconds (60 ticks * 500ms). Writes only the
        // cursor for the mode we're currently running so the other mode's
        // resume position stays untouched.
        if (++save_counter >= 60) {
            save_counter = 0;
            pthread_mutex_lock(&subnet_lock);
            int     snap_idx = current_subnet_idx;
            int32_t snap_off = current_host_offset;
            pthread_mutex_unlock(&subnet_lock);
            if (desired_mode == SCAN_MODE_FULL_IPV4) {
                g_config.full_subnet_idx  = snap_idx;
                g_config.full_host_offset = snap_off;
            } else {
                g_config.known_subnet_idx  = snap_idx;
                g_config.known_host_offset = snap_off;
            }
            config_save(&g_config);
        }
    }
    
    ui_print_shutdown_message("Waiting for threads to finish...");

    // In hybrid mode, signal queue shutdown so workers unblock
    if (use_hybrid) {
        hitqueue_shutdown(&g_hit_queue);
    }

    // Wait for threads
    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);
    
    // Flush any pending API batch and wait for in-flight sends to finish
    api_flush_batch();
    api_wait_pending();
    
    // Final statistics
    uint64_t scanned, found, errors;
    stats_get(&scanned, &found, &errors);
    
    // Save final config for the mode we just ran.
    pthread_mutex_lock(&subnet_lock);
    int     final_idx = current_subnet_idx;
    int32_t final_off = current_host_offset;
    pthread_mutex_unlock(&subnet_lock);
    if (desired_mode == SCAN_MODE_FULL_IPV4) {
        g_config.full_subnet_idx  = final_idx;
        g_config.full_host_offset = final_off;
    } else {
        g_config.known_subnet_idx  = final_idx;
        g_config.known_host_offset = final_off;
    }
    config_save(&g_config);
    
    ui_print_summary(scanned, found, errors);
    
    // Cleanup API client
    api_cleanup();

    // Cleanup socket pool
    scanner_cleanup_pool();

    if (use_rawscan) rawscan_shutdown();
    if (use_hybrid) {
        if (use_synblast) synblast_shutdown();
        hitqueue_destroy(&g_hit_queue);
    }

    // Free subnet list
    free(subnets);

    ui_shutdown();
    
    return 0;
}
