#pragma once
#include <stdint.h>

typedef struct
{
    bool established;
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
    uint8_t ip_hl : 4; /* header length */
    uint8_t ip_v : 4;  /* version */
    uint8_t ip_tos;    /* type of service */
    uint16_t ip_len;   /* total length */
    uint16_t ip_id;    /* identification */
    uint16_t ip_off;   /* fragment offset field */
    uint8_t ip_ttl;    /* time to live */
    uint8_t ip_p;      /* protocol */
    uint16_t ip_sum;   /* checksum */
    uint32_t ip_src;   /* source and dest address */
    uint32_t ip_dst;
} pcaplog_ip_t;

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

typedef struct
{
    uint16_t th_sport;  /* source port */
    uint16_t th_dport;  /* destination port */
    uint32_t th_seq;    /* sequence number */
    uint32_t th_ack;    /* acknowledgement number */
    uint8_t th_x2 : 4;  /* (unused) */
    uint8_t th_off : 4; /* data offset */
    uint8_t th_flags;
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
} pcaplog_tcphdr_t;

typedef struct
{
    pcaplog_t *pcap_data;
    pcaplog_endpoint_t local_endpoint;
    pcaplog_endpoint_t remote_endpoint;
} pcaplog_ctx_t;
