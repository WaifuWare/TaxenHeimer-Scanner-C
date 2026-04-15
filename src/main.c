/*
 * TaxenHeimer C Scanner - Main Entry Point
 * Minecraft server scanner rewritten in C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

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
            
            // Update progress (only thread 0 updates to avoid contention)
            if (targ->thread_id == 0) {
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
    (void)argc;
    (void)argv;
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    
    // Load config
    g_config = config_load();
    
    // Initialize socket pool
    scanner_init_pool();
    
    // Initialize UI
    ui_init();
    
    // Initialize API client
    api_init();
    
    // Initialize statistics
    stats_init();
    
    // Create threads
    pthread_t threads[NUM_THREADS];
    thread_arg_t thread_args[NUM_THREADS];
    
    // Set initial subnet from config
    current_subnet_idx = g_config.current_subnet_idx;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_args[i].subnets = KNOWN_RANGES;
        thread_args[i].subnet_count = KNOWN_RANGES_COUNT;
        thread_args[i].thread_id = i;
        thread_args[i].start_host_offset = g_config.current_host_offset + i;
        
        if (pthread_create(&threads[i], NULL, scanner_thread, &thread_args[i]) != 0) {
            log_error("Failed to create thread %d", i);
            return 1;
        }
    }
    
    // Stats display loop - also save config periodically
    int save_counter = 0;
    while (!interrupted) {
        sleep(2);
        
        // Render fancy header
        pthread_mutex_lock(&subnet_lock);
        ui_render_header(current_subnet_idx, KNOWN_RANGES_COUNT, 
                        current_host_offset, 1 << RANGE_SCANNER_SUBNET);
        pthread_mutex_unlock(&subnet_lock);
        
        // Save config every 30 seconds
        if (++save_counter >= 15) {
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
    
    ui_shutdown();
    
    return 0;
}
