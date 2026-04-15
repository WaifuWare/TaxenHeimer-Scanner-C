/*
 * Configuration implementation
 */

#include "config.h"
#include "log.h"
#include "../libs/cJSON/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

config_t config_default(void) {
    config_t cfg = {0};
    cfg.previous_ip = 0;
    cfg.current_subnet_idx = 0;
    cfg.current_host_offset = 0;
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
        // Sanity check
        if (cfg.current_subnet_idx > 10000) {
            cfg.current_subnet_idx = 0;
        }
    }
    
    cJSON *host_offset = cJSON_GetObjectItem(json, "currentHostOffset");
    if (cJSON_IsNumber(host_offset)) {
        cfg.current_host_offset = host_offset->valueint;
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
