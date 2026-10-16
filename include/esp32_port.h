#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool esp32_port_supported(uint32_t port);

/* Sets the port the box firmware connects to (443 restores the original code).
 * Returns how many connect functions were patched. */
int esp32_port_patch(uint8_t *image, size_t length, uint16_t port);
