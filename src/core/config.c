/*
 * Configuration implementation
 */

#include "core/config.h"
#include "core/log.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

config_t config_default(void) {
    config_t cfg = {0};
    cfg.previous_ip = 0;
    cfg.current_subnet_idx = 0;
    cfg.current_host_offset = 0;
    cfg.scan_mode = SCAN_MODE_KNOWN;
    return cfg;
}

config_t config_load(void) {
    config_t cfg = config_default();
    
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        log_info("Config file not found, creating new one");
        config_save(&cfg);
        return cfg;
    }
    
    // Read file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return cfg;
    }
    
    size_t bytes_read = fread(content, 1, size, f);
    if (bytes_read != (size_t)size) {
        log_warn("Failed to read config file completely");
        free(content);
        fclose(f);
        return cfg;
    }
    content[size] = '\0';
    fclose(f);
    
    // Parse JSON
    cJSON *json = cJSON_Parse(content);
    if (!json) {
        free(content);
        return cfg;
    }
    
    // Extract fields
    cJSON *prev_ip = cJSON_GetObjectItem(json, "previousIP");
    if (cJSON_IsNumber(prev_ip)) {
        cfg.previous_ip = prev_ip->valueint;
    }
    
    cJSON *subnet_idx = cJSON_GetObjectItem(json, "currentSubnetIdx");
    if (cJSON_IsNumber(subnet_idx)) {
        cfg.current_subnet_idx = subnet_idx->valueint;
        // Upper bound raised — full IPv4 mode has ~57k subnets
        if (cfg.current_subnet_idx < 0 || cfg.current_subnet_idx > 65536) {
            cfg.current_subnet_idx = 0;
        }
    }

    cJSON *host_offset = cJSON_GetObjectItem(json, "currentHostOffset");
    if (cJSON_IsNumber(host_offset)) {
        cfg.current_host_offset = host_offset->valueint;
    }

    cJSON *mode = cJSON_GetObjectItem(json, "scanMode");
    if (cJSON_IsNumber(mode)) {
        if (mode->valueint == SCAN_MODE_FULL_IPV4) {
            cfg.scan_mode = SCAN_MODE_FULL_IPV4;
        } else {
            cfg.scan_mode = SCAN_MODE_KNOWN;
        }
    }
    
    cJSON_Delete(json);
    free(content);
    
    return cfg;
}

void config_save(const config_t *cfg) {
    cJSON *json = cJSON_CreateObject();
    if (!json) return;
    
    cJSON_AddNumberToObject(json, "previousIP", cfg->previous_ip);
    cJSON_AddNumberToObject(json, "currentSubnetIdx", cfg->current_subnet_idx);
    cJSON_AddNumberToObject(json, "currentHostOffset", cfg->current_host_offset);
    cJSON_AddNumberToObject(json, "scanMode", (int)cfg->scan_mode);
    
    char *json_str = cJSON_Print(json);
    if (!json_str) {
        cJSON_Delete(json);
        return;
    }
    
    FILE *f = fopen(CONFIG_FILE, "w");
    if (f) {
        fprintf(f, "%s\n", json_str);
        fclose(f);
    }
    
    free(json_str);
    cJSON_Delete(json);
}
