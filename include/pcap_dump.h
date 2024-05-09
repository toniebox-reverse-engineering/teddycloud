/**
 * pcap_dump aims to provide some basic functions to write a packet data into a pcap file
 */
#ifndef PCAP_DUMP_H_
#define PCAP_DUMP_H_
#include <stdint.h>
#include "fs_port.h"

struct pd_timeval
{
    uint32_t tv_sec;  /* seconds */
    uint32_t tv_usec; /* microseconds */
};

struct pd_pcap_file_header
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;  /* gmt to local correction */
    uint32_t sigfigs;  /* accuracy of timestamps */
    uint32_t snaplen;  /* max length saved portion of each pkt */
    uint32_t linktype; /* data link type (LINKTYPE_*) */
};

struct pd_pcap_pkthdr
{
    struct pd_timeval ts; /* time stamp using 32 bits fields */
    uint32_t caplen;      /* length of portion present */
    uint32_t len;         /* length this packet (off wire) */
};

static inline uint16_t bswap16(uint16_t x)
{
    return (uint16_t)(((x & 0x00ffU) << 8) |
                      ((x & 0xff00U) >> 8));
}
static inline uint32_t bswap32(uint32_t x)
{
    return ((x & 0x000000ffUL) << 24) |
           ((x & 0x0000ff00UL) << 8) |
           ((x & 0x00ff0000UL) >> 8) |
           ((x & 0xff000000UL) >> 24);
}
static inline uint64_t bswap64(uint64_t x)
{
    return ((x & 0x00000000000000ffULL) << 56) |
           ((x & 0x000000000000ff00ULL) << 40) |
           ((x & 0x0000000000ff0000ULL) << 24) |
           ((x & 0x00000000ff000000ULL) << 8) |
           ((x & 0x000000ff00000000ULL) >> 8) |
           ((x & 0x0000ff0000000000ULL) >> 24) |
           ((x & 0x00ff000000000000ULL) >> 40) |
           ((x & 0xff00000000000000ULL) >> 56);
}

/**
 * Create a new pcap file and write pcap file with the default configuration:
 * - linktype : DLT_EN10MB,
 * - timezone : 0
 * - snaplen : 65535
 *
 * If the pcap file already exists then open and points to the end of the file to continue writting data
 *
 * @param  path path to the pcap file
 * @return      pointer points to the file
 */
FsFile *pd_open(const char *path);

/**
 * Create a new pcap file with given linktype, timezone and snaplen
 * - write a pcap header to a new file. Called by openPcapFile. Shouldn't be used outside pcap_dump.c
 * @param  path     path to the pcap file
 * @param  linktype link type
 * @param  thiszone timezone
 * @param  snaplen  snaplen
 * @return          pointer points to the file
 */
FsFile *pd_create(const char *path, int linktype, int thiszone, int snaplen);

/**
 * Write a buffer into a pcap file with given timestamp
 *
 * @param  fd  points to the pcap file
 * @param  buf packet data
 * @param  len length of packet
 * @return
 */
int pd_write(FsFile *fd, uint8_t *buf, int len);
/**
 * Close a pcap file after finish writing
 * @param fd points to pcap file
 */
void pd_close(FsFile *fd);

#endif // end of pcap_dump.h