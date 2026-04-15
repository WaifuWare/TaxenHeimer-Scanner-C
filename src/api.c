/*
 * API reporting implementation
 */

#include "api.h"
#include "log.h"

#ifdef HAVE_CURL

#include "../libs/cJSON/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>
#include <unistd.h>

// API semaphore for rate limiting
static pthread_mutex_t api_lock = PTHREAD_MUTEX_INITIALIZER;
static int api_concurrent = 0;
static bool api_available = true;

// Batch queue
#define BATCH_SIZE 50
#define MAX_BATCH_WAIT_MS 5000

typedef struct {
    server_info_t servers[BATCH_SIZE];
    int count;
    time_t created_at;
} batch_t;

static batch_t current_batch = {0};
static pthread_mutex_t batch_lock = PTHREAD_MUTEX_INITIALIZER;

// Initialize API client
int api_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return 0;
}

// Cleanup API client
void api_cleanup(void) {
    curl_global_cleanup();
}

// Check if API is available
bool api_is_available(void) {
    return api_available;
}

// Acquire API slot (rate limiting)
static void api_acquire_slot(void) {
    while (1) {
        pthread_mutex_lock(&api_lock);
        if (api_concurrent < MAX_CONCURRENT_API) {
            api_concurrent++;
            pthread_mutex_unlock(&api_lock);
            break;
        }
        pthread_mutex_unlock(&api_lock);
        usleep(5000);  // 5ms
    }
}

// Release API slot
static void api_release_slot(void) {
    pthread_mutex_lock(&api_lock);
    if (api_concurrent > 0) {
        api_concurrent--;
    }
    pthread_mutex_unlock(&api_lock);
}

// Determine software from version string
static void determine_software(const char *version_str, char *version_out, 
                               char *software_out, size_t max_len) {
    // Find first space to split version and software
    const char *space = strchr(version_str, ' ');
    
    if (space) {
        // Has space - first part is version, rest is software
        size_t version_len = space - version_str;
        if (version_len >= max_len) version_len = max_len - 1;
        strncpy(version_out, version_str, version_len);
        version_out[version_len] = '\0';
        
        strncpy(software_out, space + 1, max_len - 1);
        software_out[max_len - 1] = '\0';
    } else {
        // No space - treat whole thing as version
        strncpy(version_out, version_str, max_len - 1);
        version_out[max_len - 1] = '\0';
        strncpy(software_out, "Vanilla", max_len - 1);
    }
}

// CURL write callback (discard response)
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}

#endif // HAVE_CURL


// Send batch of servers to API
static void *api_batch_thread(void *arg) {
    batch_t *batch = (batch_t *)arg;
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(batch);
        api_release_slot();
        return NULL;
    }
    
    // Build batch JSON
    cJSON *root = cJSON_CreateObject();
    cJSON *servers_array = cJSON_CreateArray();
    
    for (int i = 0; i < batch->count; i++) {
        char version[256], software[256];
        determine_software(batch->servers[i].version, version, software, sizeof(version));
        
        cJSON *server = cJSON_CreateObject();
        cJSON_AddStringToObject(server, "ip", batch->servers[i].ip);
        cJSON_AddNumberToObject(server, "port", batch->servers[i].port);
        cJSON_AddStringToObject(server, "motd", batch->servers[i].motd[0] ? batch->servers[i].motd : "");
        cJSON_AddStringToObject(server, "version", version);
        cJSON_AddStringToObject(server, "software", software);
        cJSON_AddNumberToObject(server, "protocol", batch->servers[i].protocol);
        cJSON_AddNumberToObject(server, "players_online", batch->servers[i].players.online);
        cJSON_AddNumberToObject(server, "players_max", batch->servers[i].players.max);
        
        // Add player sample array
        cJSON *sample = cJSON_CreateArray();
        for (int j = 0; j < batch->servers[i].players.sample_count; j++) {
            cJSON *player = cJSON_CreateObject();
            cJSON_AddStringToObject(player, "name", batch->servers[i].players.sample[j].name);
            cJSON_AddStringToObject(player, "id", batch->servers[i].players.sample[j].id);
            cJSON_AddItemToArray(sample, player);
        }
        cJSON_AddItemToObject(server, "players_sample", sample);
        
        cJSON_AddItemToArray(servers_array, server);
    }
    
    cJSON_AddItemToObject(root, "servers", servers_array);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        free(batch);
        curl_easy_cleanup(curl);
        api_release_slot();
        return NULL;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    char batch_url[256];
    snprintf(batch_url, sizeof(batch_url), "%s/batch", API_URL);
    
    curl_easy_setopt(curl, CURLOPT_URL, batch_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        log_error("Batch API request failed: %s", curl_easy_strerror(res));
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 201 || http_code == 200) {
            log_info("Batch sent: %d servers", batch->count);
        } else {
            log_warn("Batch API returned HTTP %ld", http_code);
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_str);
    free(batch);
    
    api_release_slot();
    return NULL;
}

// Report server to API (batched)
int api_report_server(const server_info_t *info) {
    if (!info->success) return -1;
    if (info->version[0] == '\0') return -1;
    
    pthread_mutex_lock(&batch_lock);
    
    // Add to batch
    if (current_batch.count < BATCH_SIZE) {
        current_batch.servers[current_batch.count] = *info;
        current_batch.count++;
        
        // Send batch if full
        if (current_batch.count >= BATCH_SIZE) {
            api_acquire_slot();
            batch_t *batch = malloc(sizeof(batch_t));
            *batch = current_batch;
            current_batch.count = 0;
            current_batch.created_at = 0;
            
            pthread_t thread;
            if (pthread_create(&thread, NULL, api_batch_thread, batch) != 0) {
                api_release_slot();
                free(batch);
            } else {
                pthread_detach(thread);
            }
        }
    }
    
    pthread_mutex_unlock(&batch_lock);
    return 0;
}

// Flush pending batch (call on shutdown)
void api_flush_batch(void) {
    pthread_mutex_lock(&batch_lock);
    
    if (current_batch.count > 0) {
        api_acquire_slot();
        batch_t *batch = malloc(sizeof(batch_t));
        *batch = current_batch;
        current_batch.count = 0;
        current_batch.created_at = 0;
        
        pthread_t thread;
        if (pthread_create(&thread, NULL, api_batch_thread, batch) != 0) {
            api_release_slot();
            free(batch);
        } else {
            pthread_detach(thread);
        }
    }
    
    pthread_mutex_unlock(&batch_lock);
}
