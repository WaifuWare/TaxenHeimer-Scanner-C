/*
 * Configuration implementation
 */

#include "core/config.h"
#include "core/log.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

// Hard cap on config size. Legitimate config is a few hundred bytes; anything
// larger is either corruption or a hostile file placed there by a local user.
// Without the cap, a symlink to /dev/zero would OOM the scanner at startup.
#define CONFIG_MAX_BYTES (64 * 1024)

config_t config_default(void) {
    config_t cfg = {0};
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
    
    // Read file with a hard size cap.
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return cfg; }
    long size = ftell(f);
    if (size < 0 || size > CONFIG_MAX_BYTES) {
        log_warn("Config file missing/too large (size=%ld)", size);
        fclose(f);
        return cfg;
    }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return cfg; }

    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(f);
        return cfg;
    }

    size_t bytes_read = fread(content, 1, (size_t)size, f);
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
    
    cJSON *prev_ip = cJSON_GetObjectItem(json, "previousIP");
    if (cJSON_IsNumber(prev_ip)) {
        cfg.previous_ip = prev_ip->valueint;
    }

    // New per-mode keys.
    cJSON *v;
    if ((v = cJSON_GetObjectItem(json, "knownSubnetIdx")) && cJSON_IsNumber(v)) {
        cfg.known_subnet_idx = v->valueint;
        if (cfg.known_subnet_idx < 0 || cfg.known_subnet_idx > 65536) cfg.known_subnet_idx = 0;
    }
    if ((v = cJSON_GetObjectItem(json, "knownHostOffset")) && cJSON_IsNumber(v)) {
        cfg.known_host_offset = v->valueint;
    }
    if ((v = cJSON_GetObjectItem(json, "fullSubnetIdx")) && cJSON_IsNumber(v)) {
        cfg.full_subnet_idx = v->valueint;
        if (cfg.full_subnet_idx < 0 || cfg.full_subnet_idx > 65536) cfg.full_subnet_idx = 0;
    }
    if ((v = cJSON_GetObjectItem(json, "fullHostOffset")) && cJSON_IsNumber(v)) {
        cfg.full_host_offset = v->valueint;
    }

    // Migration from the pre-split schema. The legacy `scanMode` tells us
    // which bucket the saved `currentSubnetIdx`/`currentHostOffset` belonged
    // to. Once migrated, a subsequent save writes only the new keys.
    cJSON *legacy_idx  = cJSON_GetObjectItem(json, "currentSubnetIdx");
    cJSON *legacy_off  = cJSON_GetObjectItem(json, "currentHostOffset");
    cJSON *legacy_mode = cJSON_GetObjectItem(json, "scanMode");
    if (cJSON_IsNumber(legacy_idx)) {
        int idx = legacy_idx->valueint;
        if (idx < 0 || idx > 65536) idx = 0;
        int off = cJSON_IsNumber(legacy_off) ? legacy_off->valueint : 0;
        int mode = cJSON_IsNumber(legacy_mode) ? legacy_mode->valueint : SCAN_MODE_KNOWN;
        if (mode == SCAN_MODE_FULL_IPV4) {
            if (cfg.full_subnet_idx == 0 && cfg.full_host_offset == 0) {
                cfg.full_subnet_idx  = idx;
                cfg.full_host_offset = off;
            }
        } else {
            if (cfg.known_subnet_idx == 0 && cfg.known_host_offset == 0) {
                cfg.known_subnet_idx  = idx;
                cfg.known_host_offset = off;
            }
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
    cJSON_AddNumberToObject(json, "knownSubnetIdx", cfg->known_subnet_idx);
    cJSON_AddNumberToObject(json, "knownHostOffset", cfg->known_host_offset);
    cJSON_AddNumberToObject(json, "fullSubnetIdx", cfg->full_subnet_idx);
    cJSON_AddNumberToObject(json, "fullHostOffset", cfg->full_host_offset);
    
    char *json_str = cJSON_Print(json);
    if (!json_str) {
        cJSON_Delete(json);
        return;
    }

    // Atomic write: tempfile + rename. O_NOFOLLOW on both the tempfile and
    // the target prevents a local attacker from turning CONFIG_FILE into a
    // symlink that redirects the write elsewhere. O_EXCL on the tempfile
    // means a stale temp from a prior crash is rejected rather than
    // overwritten, so concurrent scanners don't clobber each other.
    char tmp_path[512];
    int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", CONFIG_FILE);
    if (tmp_len <= 0 || tmp_len >= (int)sizeof(tmp_path)) {
        free(json_str);
        cJSON_Delete(json);
        return;
    }

    // Remove any stale temp (ignore ENOENT). Then O_EXCL-create a fresh one.
    (void)unlink(tmp_path);
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_warn("config: open tmp failed: %s", strerror(errno));
        free(json_str);
        cJSON_Delete(json);
        return;
    }
    size_t json_len = strlen(json_str);
    ssize_t written = 0;
    while ((size_t)written < json_len) {
        ssize_t w = write(fd, json_str + written, json_len - (size_t)written);
        if (w <= 0) { written = -1; break; }
        written += w;
    }
    if (written >= 0) {
        (void)!write(fd, "\n", 1);
        fsync(fd);
    }
    close(fd);
    if (written < 0 || rename(tmp_path, CONFIG_FILE) != 0) {
        log_warn("config: rename failed: %s", strerror(errno));
        (void)unlink(tmp_path);
    }

    free(json_str);
    cJSON_Delete(json);
}
