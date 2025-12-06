/**
 * @file sha1_standalone.h
 * @brief Standalone SHA1 implementation for WASM
 * 
 * Public domain SHA1 implementation
 * Based on RFC 3174
 */

#ifndef _SHA1_STANDALONE_H
#define _SHA1_STANDALONE_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} Sha1Context;

void sha1Init(Sha1Context *context);
void sha1Update(Sha1Context *context, const uint8_t *data, size_t length);
void sha1Final(Sha1Context *context, uint8_t *digest);

#endif
