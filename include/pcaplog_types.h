#pragma once
#include <stdint.h>

typedef struct
{
    uint32_t seq_rx;
    uint32_t seq_tx;
} pcaplog_t;

typedef struct
{
    uint32_t ipv4;
    uint32_t port;
} pcaplog_endpoint_t;

typedef struct
{
    pcaplog_t *pcap_data;
    pcaplog_endpoint_t local_endpoint;
    pcaplog_endpoint_t remote_endpoint;
} pcaplog_ctx_t;