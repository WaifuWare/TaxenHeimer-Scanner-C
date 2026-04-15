/*
 * Scanner implementation
 */

#include "scanner.h"
#include "packet.h"
#include "../libs/cJSON/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

// Helper: Read varint with timeout
static int read_varint_timeout(int sockfd, int32_t *value, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval tv = {0, timeout_ms * 1000};
    
    if (select(sockfd + 1, &rfds, NULL, NULL, &tv) <= 0) {
        return -1;  // Timeout or error
    }
    
    return read_varint(sockfd, value);
}

// Scan a single IP address
int scan_ip(const char *ip, int port, server_info_t *info) {
    int sockfd = -1;
    struct sockaddr_in addr;
    struct timeval timeout;
    int ret = -1;
    
    // Initialize info
    memset(info, 0, sizeof(server_info_t));
    strncpy(info->ip, ip, sizeof(info->ip) - 1);
    info->port = port;
    info->success = false;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        goto cleanup;
    }
    
    // Set non-blocking for connect
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            goto cleanup;
        }
        
        // Wait for connection with timeout
        {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sockfd, &wfds);
            
            struct timeval tv = {0, SOCKET_TIMEOUT_MS * 1000};
            if (select(sockfd + 1, NULL, &wfds, NULL, &tv) <= 0) {
                goto cleanup;
            }
        }
        
        // Check if connection succeeded
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            goto cleanup;
        }
    }
    
    // Set back to blocking
    fcntl(sockfd, F_SETFL, flags);
    
    // Set socket timeout for recv/send
    timeout.tv_sec = SOCKET_TIMEOUT_MS / 1000;
    timeout.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Start timing right after connection is established
    
    // Send handshake
    packet_t handshake = {0};
    create_handshake_packet(&handshake, ip, port, STATE_STATUS);
    if (send(sockfd, handshake.data, handshake.len, 0) < 0) {
        goto cleanup;
    }
    
    // Send status request
    packet_t status_req = {0};
    create_status_request(&status_req);
    
    if (send(sockfd, status_req.data, status_req.len, 0) < 0) {
        goto cleanup;
    }
    
    // Read response
    int32_t pkt_len, pkt_id;
    if (read_varint_timeout(sockfd, &pkt_len, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    if (read_varint_timeout(sockfd, &pkt_id, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    
    // Read JSON length and data
    int32_t json_len;
    if (read_varint_timeout(sockfd, &json_len, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    
    if (json_len > 0 && json_len < MAX_PACKET_SIZE) {
        char json_buf[MAX_PACKET_SIZE];
        ssize_t total = 0;
        while (total < json_len) {
            // Use select() to enforce timeout on recv
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv = {0, SOCKET_TIMEOUT_MS * 1000};
            
            if (select(sockfd + 1, &rfds, NULL, NULL, &tv) <= 0) {
                goto cleanup;  // Timeout or error
            }
            
            ssize_t n = recv(sockfd, json_buf + total, json_len - total, 0);
            if (n <= 0) goto cleanup;
            total += n;
        }
        
        // End timing after receiving complete JSON
        
        json_buf[json_len] = '\0';
        
        // Parse JSON with cJSON
        cJSON *json = cJSON_Parse(json_buf);
        if (json) {
            // Parse description (MOTD)
            cJSON *desc_obj = cJSON_GetObjectItem(json, "description");
            if (desc_obj) {
                if (cJSON_IsString(desc_obj)) {
                    // Simple string MOTD - validate length before copying
                    size_t motd_len = strlen(desc_obj->valuestring);
                    if (motd_len > 0 && motd_len < sizeof(info->motd)) {
                        strncpy(info->motd, desc_obj->valuestring, sizeof(info->motd) - 1);
                        info->motd[sizeof(info->motd) - 1] = '\0';
                    }
                } else if (cJSON_IsObject(desc_obj)) {
                    // Complex MOTD with text field
                    cJSON *text = cJSON_GetObjectItem(desc_obj, "text");
                    if (cJSON_IsString(text) && text->valuestring) {
                        size_t motd_len = strlen(text->valuestring);
                        if (motd_len > 0 && motd_len < sizeof(info->motd)) {
                            strncpy(info->motd, text->valuestring, sizeof(info->motd) - 1);
                            info->motd[sizeof(info->motd) - 1] = '\0';
                        }
                    }
                }
            }
            
            // Parse version
            cJSON *version_obj = cJSON_GetObjectItem(json, "version");
            if (version_obj) {
                cJSON *name = cJSON_GetObjectItem(version_obj, "name");
                if (cJSON_IsString(name) && name->valuestring) {
                    size_t version_len = strlen(name->valuestring);
                    if (version_len > 0 && version_len < sizeof(info->version)) {
                        strncpy(info->version, name->valuestring, sizeof(info->version) - 1);
                        info->version[sizeof(info->version) - 1] = '\0';
                    }
                }
                
                cJSON *protocol = cJSON_GetObjectItem(version_obj, "protocol");
                if (cJSON_IsNumber(protocol)) {
                    // Validate protocol is in reasonable range
                    if (protocol->valueint > 0 && protocol->valueint < 1000) {
                        info->protocol = protocol->valueint;
                    }
                }
            }
            
            // Parse players
            cJSON *players_obj = cJSON_GetObjectItem(json, "players");
            if (players_obj) {
                cJSON *online = cJSON_GetObjectItem(players_obj, "online");
                if (cJSON_IsNumber(online)) {
                    // Validate player count is reasonable
                    if (online->valueint >= 0 && online->valueint < 1000000) {
                        info->players.online = online->valueint;
                    }
                }
                
                cJSON *max = cJSON_GetObjectItem(players_obj, "max");
                if (cJSON_IsNumber(max)) {
                    // Validate max players is reasonable
                    if (max->valueint >= 0 && max->valueint < 1000000) {
                        info->players.max = max->valueint;
                    }
                }
                
                // Extract player sample
                cJSON *sample = cJSON_GetObjectItem(players_obj, "sample");
                if (cJSON_IsArray(sample)) {
                    info->players.sample_count = 0;
                    cJSON *player_item = NULL;
                    cJSON_ArrayForEach(player_item, sample) {
                        if (info->players.sample_count >= 10) break;  // Max 10 players
                        
                        cJSON *name = cJSON_GetObjectItem(player_item, "name");
                        cJSON *id = cJSON_GetObjectItem(player_item, "id");
                        
                        if (cJSON_IsString(name) && name->valuestring) {
                            size_t name_len = strlen(name->valuestring);
                            if (name_len > 0 && name_len < sizeof(info->players.sample[0].name)) {
                                strncpy(info->players.sample[info->players.sample_count].name, 
                                       name->valuestring, sizeof(info->players.sample[0].name) - 1);
                                info->players.sample[info->players.sample_count].name[sizeof(info->players.sample[0].name) - 1] = '\0';
                            }
                        }
                        
                        if (cJSON_IsString(id) && id->valuestring) {
                            size_t id_len = strlen(id->valuestring);
                            if (id_len > 0 && id_len < sizeof(info->players.sample[0].id)) {
                                strncpy(info->players.sample[info->players.sample_count].id, 
                                       id->valuestring, sizeof(info->players.sample[0].id) - 1);
                                info->players.sample[info->players.sample_count].id[sizeof(info->players.sample[0].id) - 1] = '\0';
                            }
                        }
                        
                        info->players.sample_count++;
                    }
                }
            }
            
            // Skip favicon - don't store in memory
            
            cJSON_Delete(json);
            info->success = true;
            ret = 0;
        }
    }
    
cleanup:
    if (sockfd >= 0) close(sockfd);
    return ret;
}

// Scan a batch of IPs
int scan_batch(char ips[][16], int count, server_info_t *results) {
    int found = 0;
    
    for (int i = 0; i < count; i++) {
        if (scan_ip(ips[i], MINECRAFT_PORT, &results[i]) == 0) {
            found++;
        }
    }
    
    return found;
}

// Thread data for concurrent scanning
typedef struct {
    char ip[16];
    int port;
    server_info_t *result;
    scan_callback_t callback;
} scan_thread_data_t;

// Thread function for concurrent scanning
static void *scan_thread_func(void *arg) {
    scan_thread_data_t *data = (scan_thread_data_t *)arg;
    
    server_info_t info;
    scan_ip(data->ip, data->port, &info);
    
    if (data->callback) {
        data->callback(&info);
    }
    
    if (data->result) {
        *data->result = info;
    }
    
    free(data);
    return NULL;
}

// Initialize socket pool (stub)
void scanner_init_pool(void) {
}

// Cleanup socket pool (stub)
void scanner_cleanup_pool(void) {
}

// Scan batch concurrently with callback
int scan_batch_async(char ips[][16], int count, scan_callback_t callback) {
    int scanned = 0;
    
    // Process in chunks to limit concurrent connections
    for (int batch_start = 0; batch_start < count; batch_start += MAX_CONCURRENT_SCANS) {
        int batch_end = batch_start + MAX_CONCURRENT_SCANS;
        if (batch_end > count) batch_end = count;
        int batch_size = batch_end - batch_start;
        
        pthread_t threads[batch_size];
        
        for (int i = 0; i < batch_size; i++) {
            scan_thread_data_t *data = malloc(sizeof(scan_thread_data_t));
            if (!data) continue;
            
            strncpy(data->ip, ips[batch_start + i], sizeof(data->ip) - 1);
            data->port = MINECRAFT_PORT;
            data->result = NULL;
            data->callback = callback;
            
            if (pthread_create(&threads[i], NULL, scan_thread_func, data) != 0) {
                free(data);
            }
        }
        
        // Wait for this batch to complete before starting next
        for (int i = 0; i < batch_size; i++) {
            pthread_join(threads[i], NULL);
        }
        
        scanned += batch_size;
    }
    
    return scanned;
}
