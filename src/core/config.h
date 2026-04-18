/*
 * Configuration persistence
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_FILE "config.json"

// Runtime-only mode selector. NOT persisted — pass -f/--full on the command
// line each run to hit the full IPv4 space; default is KNOWN.
typedef enum {
    SCAN_MODE_KNOWN = 0,    // Iterate KNOWN_RANGES (default)
    SCAN_MODE_FULL_IPV4 = 1 // Iterate all routable /16 subnets
} scan_mode_t;

// Resume state. Each mode keeps its own cursor so switching between them
// doesn't clobber progress — run `-f` for a week, pause, run without -f,
// and resume on known-ranges from where you were, without losing the
// full-scan position.
typedef struct {
    int32_t previous_ip;
    int     known_subnet_idx;
    int32_t known_host_offset;
    int     full_subnet_idx;
    int32_t full_host_offset;
} config_t;

// Load config from file
config_t config_load(void);

// Save config to file
void config_save(const config_t *cfg);

// Get default config
config_t config_default(void);

#endif // CONFIG_H
