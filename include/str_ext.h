#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Hex-encodes as many bytes of data as fit into output (incl. NUL
 * terminator) and returns the number of input bytes consumed. Call it in a
 * loop to encode input larger than the buffer.
 */
size_t hexEncode(const uint8_t *data, size_t len, char *output, size_t output_size);

/*
 * CSV-escapes as many bytes of input as fit into output (incl. NUL
 * terminator) and returns the number of input bytes consumed: '"' becomes
 * '""', CR/LF become "\r"/"\n", any other non-alphanumeric byte becomes '.'.
 */
size_t escapeString(const char *input, size_t size, char *output, size_t output_size);

/*
 * Splits "scheme://host/path?query" into host, path and query, each
 * written to a buffer of buf_size bytes. Returns false if the URL has no
 * scheme or path, or a part does not fit.
 */
bool split_url(const char *location, char *uri_base, char *uri_path, char *query_string, size_t buf_size);

/*
 * True if the IPv4 address (4 bytes, a.b.c.d) is a public unicast address. False for everything a server
 * must not be made to fetch from on behalf of a user: "this" network, loopback, private (RFC 1918),
 * shared/CGNAT, link-local (cloud metadata), IETF/test/benchmark ranges, multicast, reserved, broadcast.
 */
bool ipv4_is_public(const uint8_t ip[4]);
