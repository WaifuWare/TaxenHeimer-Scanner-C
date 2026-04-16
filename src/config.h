/*
 * Configuration persistence
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_FILE "config.json"

typedef enum {
    SCAN_MODE_KNOWN = 0,    // Iterate KNOWN_RANGES (default)
    SCAN_MODE_FULL_IPV4 = 1 // Iterate all routable /16 subnets
} scan_mode_t;

typedef struct {
    int32_t previous_ip;
    int current_subnet_idx;
    int32_t current_host_offset;
    scan_mode_t scan_mode;
} config_t;

// Load config from file
config_t config_load(void);

// Save config to file
void config_save(const config_t *cfg);

// Get default config
config_t config_default(void);

#endif // CONFIG_H
