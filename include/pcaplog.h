#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "pcaplog_types.h"
#include "net_config.h"

void pcaplog_open();
void pcaplog_close();
void pcaplog_write(http_connection_private_t *ctx, bool is_tx, const uint8_t *http_data, size_t http_len);
