/*
 * Scanner configuration settings
 * Edit these values to tune scanner performance
 */

#ifndef SETTINGS_H
#define SETTINGS_H

// Network settings
#define MINECRAFT_PORT 25565
#define SOCKET_TIMEOUT_MS 400           // Faster timeout for quicker failures
#define API_TIMEOUT_S 3
#define API_CONNECT_TIMEOUT_S 1

// Scanning performance
#define SCAN_BATCH 100                  // IPs per batch
#define IP_POOL 1000                    // IPs collected per thread iteration
#define MAX_CONCURRENT_SCANS 128        // Max concurrent socket connections per batch
#define NUM_THREADS 8                   // Worker threads
#define RANGE_SCANNER_SUBNET 16         // /16 subnet size

// API settings (Unix domain socket IPC to Go backend)
#define IPC_SOCKET_PATH "/tmp/taxenheimer/ipc.sock"
#define IPC_CONNECT_TIMEOUT_MS 1000
#define IPC_IO_TIMEOUT_MS 5000
#define MAX_CONCURRENT_API 20           // Max concurrent IPC senders

// Protocol settings
#define PROTOCOL_VERSION 769            // Minecraft 1.21.4
#define MAX_PACKET_SIZE 8192

// Private IP ranges (do not modify)
#define LOCAL_10_START   0x0A000000U
#define LOCAL_10_END     0x0AFFFFFFU
#define LOCAL_172_START  0xAC100000U
#define LOCAL_172_END    0xAC1FFFFFU
#define LOCAL_192_START  0xC0A80000U
#define LOCAL_192_END    0xC0A8FFFFU
#define LOCAL_169_START  0xA9FE0000U
#define LOCAL_169_END    0xA9FEFFFU

#endif // SETTINGS_H
