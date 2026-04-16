/*
 * Utility functions for IP handling
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "core/settings.h"

// IP conversion functions
void int_to_ip(uint32_t ip, char *buf);
uint32_t ip_to_int(const char *ip);

// IP validation
bool check_valid_ip(uint32_t ip);

#endif // UTILS_H
