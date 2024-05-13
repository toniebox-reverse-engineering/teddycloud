#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "pcaplog_types.h"
#include "net_config.h"

void pcaplog_open();
void pcaplog_close();
void pcaplog_write(pcaplog_ctx_t *ctx, bool is_tx, const uint8_t *payload, size_t payload_len);
void pcaplog_reset(pcaplog_ctx_t *ctx);
