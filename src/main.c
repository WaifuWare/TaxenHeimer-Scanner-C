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

#include "packet.h"
#include "scanner.h"
#include "utils.h"
#include "stats.h"
#include "ranges.h"
#include "api.h"
#include "settings.h"
#include "ui.h"
#include "config.h"
#include "log.h"

// Global state
static volatile sig_atomic_t interrupted = 0;
static pthread_mutex_t subnet_lock = PTHREAD_MUTEX_INITIALIZER;
static int current_subnet_idx = 0;
static int32_t current_host_offset = 0;  // Track actual progress
static uint32_t threads_finished_mask = 0;  // Bitmask for thread states (saves 11 bytes)
static config_t g_config;

// Thread argument structure
typedef struct {
    const int32_t *subnets;
    int subnet_count;
    int thread_id;
    int32_t start_host_offset;
} thread_arg_t;

// Callback for found servers
static void on_server_found(const server_info_t *info) {
    if (!info->success) {
        stats_increment_errors();
        stats_increment_scanned();
        return;
    }
    
    stats_increment_found();
    stats_increment_scanned();
    
    // Print found server with all details
    ui_print_server(info);
    
    // Report to API (non-blocking)
    api_report_server(info);
}

// Signal handler
static void signal_handler(int signum) {
    if (signum == SIGINT) {
        interrupted = 1;
        ui_print_shutdown_message("Received interrupt signal, shutting down...");
    }
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
        
        for (int i = 0; i < IP_POOL * 20 && ip_count < IP_POOL; i++) {
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
                    }
                    threads_finished_mask = 0;  // Reset all bits
                    current_host_offset = 0;    // Reset progress
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
        scan_batch_async(ips, ip_count, on_server_found);
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    // Parse CLI
    bool cli_full = false;
    bool cli_known = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0 || strcmp(argv[i], "-f") == 0) {
            cli_full = true;
        } else if (strcmp(argv[i], "--known") == 0 || strcmp(argv[i], "-k") == 0) {
            cli_known = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -k, --known    Scan only known Minecraft /16 subnets (default)\n");
            printf("  -f, --full     Scan the entire routable IPv4 space\n");
            printf("  -h, --help     Show this help\n");
            return 0;
        }
    }

    // Setup signal handler
    signal(SIGINT, signal_handler);

    // Wire interrupt flag into scanner so async loops abort on shutdown
    scanner_set_interrupt_flag(&interrupted);

    // Load config
    g_config = config_load();

    // Apply CLI mode override. Reset scan position on mode change so we don't
    // reuse an index from the wrong subnet array.
    scan_mode_t desired_mode = g_config.scan_mode;
    if (cli_full)  desired_mode = SCAN_MODE_FULL_IPV4;
    if (cli_known) desired_mode = SCAN_MODE_KNOWN;
    if (desired_mode != g_config.scan_mode) {
        log_info("Scan mode changed — resetting scan position");
        g_config.scan_mode = desired_mode;
        g_config.current_subnet_idx = 0;
        g_config.current_host_offset = 0;
        config_save(&g_config);
    }

    // Initialize socket pool
    scanner_init_pool();

    // Initialize UI
    ui_init();

    // Initialize API client
    api_init();

    // Initialize statistics
    stats_init();

    // Build subnet array based on mode
    const int32_t *subnets = NULL;
    int subnet_count = 0;
    int32_t *full_subnets = NULL;  // heap, only used in full mode

    if (g_config.scan_mode == SCAN_MODE_FULL_IPV4) {
        full_subnets = ranges_build_full_ipv4(&subnet_count);
        if (!full_subnets || subnet_count == 0) {
            log_error("Failed to build full IPv4 range list");
            return 1;
        }
        subnets = full_subnets;
        log_info("Scan mode: FULL IPv4 (%d routable /16 subnets)", subnet_count);
    } else {
        subnets = KNOWN_RANGES;
        subnet_count = KNOWN_RANGES_COUNT;
        log_info("Scan mode: KNOWN ranges (%d subnets)", subnet_count);
    }

    // Clamp resume position to new subnet count
    if (g_config.current_subnet_idx >= subnet_count) {
        g_config.current_subnet_idx = 0;
        g_config.current_host_offset = 0;
    }

    // Create threads
    pthread_t threads[NUM_THREADS];
    thread_arg_t thread_args[NUM_THREADS];

    // Set initial subnet from config
    current_subnet_idx = g_config.current_subnet_idx;

    // Spread worker threads across all available CPU cores so they don't end up
    // on a single core due to scheduler affinity inheritance.
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;
    log_info("Detected %d CPUs — spreading %d workers", ncpus, NUM_THREADS);

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_args[i].subnets = subnets;
        thread_args[i].subnet_count = subnet_count;
        thread_args[i].thread_id = i;
        thread_args[i].start_host_offset = g_config.current_host_offset + i;

        if (pthread_create(&threads[i], NULL, scanner_thread, &thread_args[i]) != 0) {
            log_error("Failed to create thread %d", i);
            return 1;
        }

        // Pin worker i to CPU (i % ncpus). Round-robin across all cores.
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i % ncpus, &cpuset);
        int rc = pthread_setaffinity_np(threads[i], sizeof(cpuset), &cpuset);
        if (rc != 0) {
            log_warn("pthread_setaffinity_np failed for thread %d: %d", i, rc);
        }
    }
    
    // Stats display loop - also save config periodically
    int save_counter = 0;
    while (!interrupted) {
        usleep(500 * 1000);  // 500 ms refresh

        // Render fancy header
        pthread_mutex_lock(&subnet_lock);
        ui_render_header(current_subnet_idx, subnet_count,
                        current_host_offset, 1 << RANGE_SCANNER_SUBNET);
        pthread_mutex_unlock(&subnet_lock);

        // Save config every 30 seconds (60 ticks * 500ms)
        if (++save_counter >= 60) {
            save_counter = 0;
            pthread_mutex_lock(&subnet_lock);
            g_config.current_subnet_idx = current_subnet_idx;
            g_config.current_host_offset = current_host_offset;
            pthread_mutex_unlock(&subnet_lock);
            config_save(&g_config);
        }
    }
    
    ui_print_shutdown_message("Waiting for threads to finish...");
    
    // Wait for threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Flush any pending API batch
    api_flush_batch();
    
    // Give API time to send final batch
    sleep(2);
    
    // Final statistics
    uint64_t scanned, found, errors;
    stats_get(&scanned, &found, &errors);
    
    // Save final config
    pthread_mutex_lock(&subnet_lock);
    g_config.current_subnet_idx = current_subnet_idx;
    g_config.current_host_offset = current_host_offset;
    pthread_mutex_unlock(&subnet_lock);
    config_save(&g_config);
    
    ui_print_summary(scanned, found, errors);
    
    // Cleanup API client
    api_cleanup();

    // Cleanup socket pool
    scanner_cleanup_pool();

    // Free full-IPv4 subnet list if allocated
    if (full_subnets) {
        free(full_subnets);
    }

    ui_shutdown();
    
    return 0;
}
