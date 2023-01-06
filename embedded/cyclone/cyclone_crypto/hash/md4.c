/**
 * @file md4.c
 * @brief MD4 (Message-Digest Algorithm)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @section Description
 *
 * The MD4 algorithm takes as input a message of arbitrary length and produces
 * as output a 128-bit message digest of the input. Refer to RFC 1320
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/md4.h"

//Check crypto library configuration
#if (MD4_SUPPORT == ENABLED)

//MD4 auxiliary functions
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define FF(a, b, c, d, x, s) a += F(b, c, d) + (x), a = ROL32(a, s)
#define GG(a, b, c, d, x, s) a += G(b, c, d) + (x) + 0x5A827999, a = ROL32(a, s)
#define HH(a, b, c, d, x, s) a += H(b, c, d) + (x) + 0x6ED9EBA1, a = ROL32(a, s)

//MD4 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//MD4 object identifier (1.2.840.113549.2.4)
const uint8_t md4Oid[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x04};

//Common interface for hash algorithms
const HashAlgo md4HashAlgo =
{
   "MD4",
   md4Oid,
   sizeof(md4Oid),
   sizeof(Md4Context),
   MD4_BLOCK_SIZE,
   MD4_DIGEST_SIZE,
   MD4_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) md4Compute,
   (HashAlgoInit) md4Init,
   (HashAlgoUpdate) md4Update,
   (HashAlgoFinal) md4Final,
   NULL
};


/**
 * @brief Digest a message using MD4
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t md4Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Md4Context *context;

   //Allocate a memory buffer to hold the MD4 context
   context = cryptoAllocMem(sizeof(Md4Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the MD4 context
      md4Init(context);
      //Digest the message
      md4Update(context, data, length);
      //Finalize the MD4 message digest
      md4Final(context, digest);

      //Free previously allocated memory
      cryptoFreeMem(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize MD4 message digest context
 * @param[in] context Pointer to the MD4 context to initialize
 **/

void md4Init(Md4Context *context)
{
   //Set initial hash value
   context->h[0] = 0x67452301;
   context->h[1] = 0xEFCDAB89;
   context->h[2] = 0x98BADCFE;
   context->h[3] = 0x10325476;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the MD4 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD4 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void md4Update(Md4Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the MD4 context
      context->size += n;
      context->totalSize += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 16-word blocks
      if(context->size == 64)
      {
         //Transform the 16-word block
         md4ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the MD4 message digest
 * @param[in] context Pointer to the MD4 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void md4Final(Md4Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   md4Update(context, padding, paddingSize);

   //Append the length of the original message
   context->x[14] = htole32((uint32_t) totalSize);
   context->x[15] = htole32((uint32_t) (totalSize >> 32));

   //Calculate the message digest
   md4ProcessBlock(context);

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 4; i++)
   {
      context->h[i] = htole32(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, MD4_DIGEST_SIZE);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the MD4 context
 **/

void md4ProcessBlock(Md4Context *context)
{
   uint_t i;

   //Initialize the 4 working registers
   uint32_t a = context->h[0];
   uint32_t b = context->h[1];
   uint32_t c = context->h[2];
   uint32_t d = context->h[3];

   //Process message in 16-word blocks
   uint32_t *x = context->x;

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      x[i] = letoh32(x[i]);
   }

   //Round 1
   FF(a, b, c, d, x[0],  3);
   FF(d, a, b, c, x[1],  7);
   FF(c, d, a, b, x[2],  11);
   FF(b, c, d, a, x[3],  19);
   FF(a, b, c, d, x[4],  3);
   FF(d, a, b, c, x[5],  7);
   FF(c, d, a, b, x[6],  11);
   FF(b, c, d, a, x[7],  19);
   FF(a, b, c, d, x[8],  3);
   FF(d, a, b, c, x[9],  7);
   FF(c, d, a, b, x[10], 11);
   FF(b, c, d, a, x[11], 19);
   FF(a, b, c, d, x[12], 3);
   FF(d, a, b, c, x[13], 7);
   FF(c, d, a, b, x[14], 11);
   FF(b, c, d, a, x[15], 19);

   //Round 2
   GG(a, b, c, d, x[0],  3);
   GG(d, a, b, c, x[4],  5);
   GG(c, d, a, b, x[8],  9);
   GG(b, c, d, a, x[12], 13);
   GG(a, b, c, d, x[1],  3);
   GG(d, a, b, c, x[5],  5);
   GG(c, d, a, b, x[9],  9);
   GG(b, c, d, a, x[13], 13);
   GG(a, b, c, d, x[2],  3);
   GG(d, a, b, c, x[6],  5);
   GG(c, d, a, b, x[10], 9);
   GG(b, c, d, a, x[14], 13);
   GG(a, b, c, d, x[3],  3);
   GG(d, a, b, c, x[7],  5);
   GG(c, d, a, b, x[11], 9);
   GG(b, c, d, a, x[15], 13);

   //Round 3
   HH(a, b, c, d, x[0],  3);
   HH(d, a, b, c, x[8],  9);
   HH(c, d, a, b, x[4],  11);
   HH(b, c, d, a, x[12], 15);
   HH(a, b, c, d, x[2],  3);
   HH(d, a, b, c, x[10], 9);
   HH(c, d, a, b, x[6],  11);
   HH(b, c, d, a, x[14], 15);
   HH(a, b, c, d, x[1],  3);
   HH(d, a, b, c, x[9],  9);
   HH(c, d, a, b, x[5],  11);
   HH(b, c, d, a, x[13], 15);
   HH(a, b, c, d, x[3],  3);
   HH(d, a, b, c, x[11], 9);
   HH(c, d, a, b, x[7],  11);
   HH(b, c, d, a, x[15], 15);

   //Update the hash value
   context->h[0] += a;
   context->h[1] += b;
   context->h[2] += c;
   context->h[3] += d;
}

#endif
