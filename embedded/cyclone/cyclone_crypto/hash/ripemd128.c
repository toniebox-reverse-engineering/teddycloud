/**
 * @file ripemd128.c
 * @brief RIPEMD-128 hash function
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/ripemd128.h"

//Check crypto library configuration
#if (RIPEMD128_SUPPORT == ENABLED)

//RIPEMD-128 auxiliary functions
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))

#define FF(a, b, c, d, x, s) a += F(b, c, d) + (x), a = ROL32(a, s)
#define GG(a, b, c, d, x, s) a += G(b, c, d) + (x) + 0x5A827999, a = ROL32(a, s)
#define HH(a, b, c, d, x, s) a += H(b, c, d) + (x) + 0x6ED9EBA1, a = ROL32(a, s)
#define II(a, b, c, d, x, s) a += I(b, c, d) + (x) + 0x8F1BBCDC, a = ROL32(a, s)

#define FFF(a, b, c, d, x, s) a += F(b, c, d) + (x), a = ROL32(a, s)
#define GGG(a, b, c, d, x, s) a += G(b, c, d) + (x) + 0x6D703EF3, a = ROL32(a, s)
#define HHH(a, b, c, d, x, s) a += H(b, c, d) + (x) + 0x5C4DD124, a = ROL32(a, s)
#define III(a, b, c, d, x, s) a += I(b, c, d) + (x) + 0x50A28BE6, a = ROL32(a, s)

//RIPEMD-128 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//RIPEMD-128 object identifier (1.3.36.3.2.2)
const uint8_t ripemd128Oid[5] = {0x2B, 0x24, 0x03, 0x02, 0x02};

//Common interface for hash algorithms
const HashAlgo ripemd128HashAlgo =
{
   "RIPEMD-128",
   ripemd128Oid,
   sizeof(ripemd128Oid),
   sizeof(Ripemd128Context),
   RIPEMD128_BLOCK_SIZE,
   RIPEMD128_DIGEST_SIZE,
   RIPEMD128_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) ripemd128Compute,
   (HashAlgoInit) ripemd128Init,
   (HashAlgoUpdate) ripemd128Update,
   (HashAlgoFinal) ripemd128Final,
   NULL
};


/**
 * @brief Digest a message using RIPEMD-128
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t ripemd128Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Ripemd128Context *context;

   //Allocate a memory buffer to hold the RIPEMD-128 context
   context = cryptoAllocMem(sizeof(Ripemd128Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the RIPEMD-128 context
      ripemd128Init(context);
      //Digest the message
      ripemd128Update(context, data, length);
      //Finalize the RIPEMD-128 message digest
      ripemd128Final(context, digest);

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
 * @brief Initialize RIPEMD-128 message digest context
 * @param[in] context Pointer to the RIPEMD-128 context to initialize
 **/

void ripemd128Init(Ripemd128Context *context)
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
 * @brief Update the RIPEMD-128 context with a portion of the message being hashed
 * @param[in] context Pointer to the RIPEMD-128 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void ripemd128Update(Ripemd128Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the RIPEMD-128 context
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
         ripemd128ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the RIPEMD-128 message digest
 * @param[in] context Pointer to the RIPEMD-128 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void ripemd128Final(Ripemd128Context *context, uint8_t *digest)
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
   ripemd128Update(context, padding, paddingSize);

   //Append the length of the original message
   context->x[14] = htole32((uint32_t) totalSize);
   context->x[15] = htole32((uint32_t) (totalSize >> 32));

   //Calculate the message digest
   ripemd128ProcessBlock(context);

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 4; i++)
   {
      context->h[i] = htole32(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, RIPEMD128_DIGEST_SIZE);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the RIPEMD-128 context
 **/

void ripemd128ProcessBlock(Ripemd128Context *context)
{
   uint_t i;

   //Initialize the working registers
   uint32_t aa= context->h[0];
   uint32_t bb = context->h[1];
   uint32_t cc = context->h[2];
   uint32_t dd = context->h[3];
   uint32_t aaa = context->h[0];
   uint32_t bbb = context->h[1];
   uint32_t ccc = context->h[2];
   uint32_t ddd = context->h[3];

   //Process message in 16-word blocks
   uint32_t *x = context->x;

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      x[i] = letoh32(x[i]);
   }

   //Round 1
   FF(aa, bb, cc, dd, x[0],  11);
   FF(dd, aa, bb, cc, x[1],  14);
   FF(cc, dd, aa, bb, x[2],  15);
   FF(bb, cc, dd, aa, x[3],  12);
   FF(aa, bb, cc, dd, x[4],  5);
   FF(dd, aa, bb, cc, x[5],  8);
   FF(cc, dd, aa, bb, x[6],  7);
   FF(bb, cc, dd, aa, x[7],  9);
   FF(aa, bb, cc, dd, x[8],  11);
   FF(dd, aa, bb, cc, x[9],  13);
   FF(cc, dd, aa, bb, x[10], 14);
   FF(bb, cc, dd, aa, x[11], 15);
   FF(aa, bb, cc, dd, x[12], 6);
   FF(dd, aa, bb, cc, x[13], 7);
   FF(cc, dd, aa, bb, x[14], 9);
   FF(bb, cc, dd, aa, x[15], 8);

   //Round 2
   GG(aa, bb, cc, dd, x[7],  7);
   GG(dd, aa, bb, cc, x[4],  6);
   GG(cc, dd, aa, bb, x[13], 8);
   GG(bb, cc, dd, aa, x[1],  13);
   GG(aa, bb, cc, dd, x[10], 11);
   GG(dd, aa, bb, cc, x[6],  9);
   GG(cc, dd, aa, bb, x[15], 7);
   GG(bb, cc, dd, aa, x[3],  15);
   GG(aa, bb, cc, dd, x[12], 7);
   GG(dd, aa, bb, cc, x[0],  12);
   GG(cc, dd, aa, bb, x[9],  15);
   GG(bb, cc, dd, aa, x[5],  9);
   GG(aa, bb, cc, dd, x[2],  11);
   GG(dd, aa, bb, cc, x[14], 7);
   GG(cc, dd, aa, bb, x[11], 13);
   GG(bb, cc, dd, aa, x[8],  12);

   //Round 3
   HH(aa, bb, cc, dd, x[3],  11);
   HH(dd, aa, bb, cc, x[10], 13);
   HH(cc, dd, aa, bb, x[14], 6);
   HH(bb, cc, dd, aa, x[4],  7);
   HH(aa, bb, cc, dd, x[9],  14);
   HH(dd, aa, bb, cc, x[15], 9);
   HH(cc, dd, aa, bb, x[8],  13);
   HH(bb, cc, dd, aa, x[1],  15);
   HH(aa, bb, cc, dd, x[2],  14);
   HH(dd, aa, bb, cc, x[7],  8);
   HH(cc, dd, aa, bb, x[0],  13);
   HH(bb, cc, dd, aa, x[6],  6);
   HH(aa, bb, cc, dd, x[13], 5);
   HH(dd, aa, bb, cc, x[11], 12);
   HH(cc, dd, aa, bb, x[5],  7);
   HH(bb, cc, dd, aa, x[12], 5);

   //Round 4
   II(aa, bb, cc, dd, x[1],  11);
   II(dd, aa, bb, cc, x[9],  12);
   II(cc, dd, aa, bb, x[11], 14);
   II(bb, cc, dd, aa, x[10], 15);
   II(aa, bb, cc, dd, x[0],  14);
   II(dd, aa, bb, cc, x[8],  15);
   II(cc, dd, aa, bb, x[12], 9);
   II(bb, cc, dd, aa, x[4],  8);
   II(aa, bb, cc, dd, x[13], 9);
   II(dd, aa, bb, cc, x[3],  14);
   II(cc, dd, aa, bb, x[7],  5);
   II(bb, cc, dd, aa, x[15], 6);
   II(aa, bb, cc, dd, x[14], 8);
   II(dd, aa, bb, cc, x[5],  6);
   II(cc, dd, aa, bb, x[6],  5);
   II(bb, cc, dd, aa, x[2],  12);

   //Parallel round 1
   III(aaa, bbb, ccc, ddd, x[5],  8);
   III(ddd, aaa, bbb, ccc, x[14], 9);
   III(ccc, ddd, aaa, bbb, x[7],  9);
   III(bbb, ccc, ddd, aaa, x[0],  11);
   III(aaa, bbb, ccc, ddd, x[9],  13);
   III(ddd, aaa, bbb, ccc, x[2],  15);
   III(ccc, ddd, aaa, bbb, x[11], 15);
   III(bbb, ccc, ddd, aaa, x[4],  5);
   III(aaa, bbb, ccc, ddd, x[13], 7);
   III(ddd, aaa, bbb, ccc, x[6],  7);
   III(ccc, ddd, aaa, bbb, x[15], 8);
   III(bbb, ccc, ddd, aaa, x[8],  11);
   III(aaa, bbb, ccc, ddd, x[1],  14);
   III(ddd, aaa, bbb, ccc, x[10], 14);
   III(ccc, ddd, aaa, bbb, x[3],  12);
   III(bbb, ccc, ddd, aaa, x[12], 6);

   //Parallel round 2
   HHH(aaa, bbb, ccc, ddd, x[6],  9);
   HHH(ddd, aaa, bbb, ccc, x[11], 13);
   HHH(ccc, ddd, aaa, bbb, x[3],  15);
   HHH(bbb, ccc, ddd, aaa, x[7],  7);
   HHH(aaa, bbb, ccc, ddd, x[0],  12);
   HHH(ddd, aaa, bbb, ccc, x[13], 8);
   HHH(ccc, ddd, aaa, bbb, x[5],  9);
   HHH(bbb, ccc, ddd, aaa, x[10], 11);
   HHH(aaa, bbb, ccc, ddd, x[14], 7);
   HHH(ddd, aaa, bbb, ccc, x[15], 7);
   HHH(ccc, ddd, aaa, bbb, x[8],  12);
   HHH(bbb, ccc, ddd, aaa, x[12], 7);
   HHH(aaa, bbb, ccc, ddd, x[4],  6);
   HHH(ddd, aaa, bbb, ccc, x[9],  15);
   HHH(ccc, ddd, aaa, bbb, x[1],  13);
   HHH(bbb, ccc, ddd, aaa, x[2],  11);

   //Parallel round 3
   GGG(aaa, bbb, ccc, ddd, x[15], 9);
   GGG(ddd, aaa, bbb, ccc, x[5],  7);
   GGG(ccc, ddd, aaa, bbb, x[1],  15);
   GGG(bbb, ccc, ddd, aaa, x[3],  11);
   GGG(aaa, bbb, ccc, ddd, x[7],  8);
   GGG(ddd, aaa, bbb, ccc, x[14], 6);
   GGG(ccc, ddd, aaa, bbb, x[6],  6);
   GGG(bbb, ccc, ddd, aaa, x[9],  14);
   GGG(aaa, bbb, ccc, ddd, x[11], 12);
   GGG(ddd, aaa, bbb, ccc, x[8],  13);
   GGG(ccc, ddd, aaa, bbb, x[12], 5);
   GGG(bbb, ccc, ddd, aaa, x[2],  14);
   GGG(aaa, bbb, ccc, ddd, x[10], 13);
   GGG(ddd, aaa, bbb, ccc, x[0],  13);
   GGG(ccc, ddd, aaa, bbb, x[4],  7);
   GGG(bbb, ccc, ddd, aaa, x[13], 5);

   //Parallel round 4
   FFF(aaa, bbb, ccc, ddd, x[8],  15);
   FFF(ddd, aaa, bbb, ccc, x[6],  5);
   FFF(ccc, ddd, aaa, bbb, x[4],  8);
   FFF(bbb, ccc, ddd, aaa, x[1],  11);
   FFF(aaa, bbb, ccc, ddd, x[3],  14);
   FFF(ddd, aaa, bbb, ccc, x[11], 14);
   FFF(ccc, ddd, aaa, bbb, x[15], 6);
   FFF(bbb, ccc, ddd, aaa, x[0],  14);
   FFF(aaa, bbb, ccc, ddd, x[5],  6);
   FFF(ddd, aaa, bbb, ccc, x[12], 9);
   FFF(ccc, ddd, aaa, bbb, x[2],  12);
   FFF(bbb, ccc, ddd, aaa, x[13], 9);
   FFF(aaa, bbb, ccc, ddd, x[9],  12);
   FFF(ddd, aaa, bbb, ccc, x[7],  5);
   FFF(ccc, ddd, aaa, bbb, x[10], 15);
   FFF(bbb, ccc, ddd, aaa, x[14], 8);

   //Combine results
   ddd = context->h[1] + cc + ddd;
   context->h[1] = context->h[2] + dd + aaa;
   context->h[2] = context->h[3] + aa + bbb;
   context->h[3] = context->h[0] + bb + ccc;
   context->h[0] = ddd;
}

#endif
