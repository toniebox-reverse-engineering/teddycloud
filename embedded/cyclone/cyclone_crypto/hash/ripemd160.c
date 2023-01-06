/**
 * @file ripemd160.c
 * @brief RIPEMD-160 hash function
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
#include "hash/ripemd160.h"

//Check crypto library configuration
#if (RIPEMD160_SUPPORT == ENABLED)

//RIPEMD-160 auxiliary functions
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

#define FF(a, b, c, d, e, x, s) a += F(b, c, d) + (x), a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define GG(a, b, c, d, e, x, s) a += G(b, c, d) + (x) + 0x5A827999, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define HH(a, b, c, d, e, x, s) a += H(b, c, d) + (x) + 0x6ED9EBA1, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define II(a, b, c, d, e, x, s) a += I(b, c, d) + (x) + 0x8F1BBCDC, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define JJ(a, b, c, d, e, x, s) a += J(b, c, d) + (x) + 0xA953FD4E, a = ROL32(a, s) + (e), c = ROL32(c, 10)

#define FFF(a, b, c, d, e, x, s) a += F(b, c, d) + (x), a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define GGG(a, b, c, d, e, x, s) a += G(b, c, d) + (x) + 0x7A6D76E9, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define HHH(a, b, c, d, e, x, s) a += H(b, c, d) + (x) + 0x6D703EF3, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define III(a, b, c, d, e, x, s) a += I(b, c, d) + (x) + 0x5C4DD124, a = ROL32(a, s) + (e), c = ROL32(c, 10)
#define JJJ(a, b, c, d, e, x, s) a += J(b, c, d) + (x) + 0x50A28BE6, a = ROL32(a, s) + (e), c = ROL32(c, 10)

//RIPEMD-160 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//RIPEMD-160 object identifier (1.3.36.3.2.1)
const uint8_t ripemd160Oid[5] = {0x2B, 0x24, 0x03, 0x02, 0x01};

//Common interface for hash algorithms
const HashAlgo ripemd160HashAlgo =
{
   "RIPEMD-160",
   ripemd160Oid,
   sizeof(ripemd160Oid),
   sizeof(Ripemd160Context),
   RIPEMD160_BLOCK_SIZE,
   RIPEMD160_DIGEST_SIZE,
   RIPEMD160_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) ripemd160Compute,
   (HashAlgoInit) ripemd160Init,
   (HashAlgoUpdate) ripemd160Update,
   (HashAlgoFinal) ripemd160Final,
   NULL
};


/**
 * @brief Digest a message using RIPEMD-160
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t ripemd160Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Ripemd160Context *context;

   //Allocate a memory buffer to hold the RIPEMD-160 context
   context = cryptoAllocMem(sizeof(Ripemd160Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the RIPEMD-160 context
      ripemd160Init(context);
      //Digest the message
      ripemd160Update(context, data, length);
      //Finalize the RIPEMD-160 message digest
      ripemd160Final(context, digest);

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
 * @brief Initialize RIPEMD-160 message digest context
 * @param[in] context Pointer to the RIPEMD-160 context to initialize
 **/

void ripemd160Init(Ripemd160Context *context)
{
   //Set initial hash value
   context->h[0] = 0x67452301;
   context->h[1] = 0xEFCDAB89;
   context->h[2] = 0x98BADCFE;
   context->h[3] = 0x10325476;
   context->h[4] = 0xC3D2E1F0;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the RIPEMD-160 context with a portion of the message being hashed
 * @param[in] context Pointer to the RIPEMD-160 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void ripemd160Update(Ripemd160Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the RIPEMD-160 context
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
         ripemd160ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the RIPEMD-160 message digest
 * @param[in] context Pointer to the RIPEMD-160 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void ripemd160Final(Ripemd160Context *context, uint8_t *digest)
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
   ripemd160Update(context, padding, paddingSize);

   //Append the length of the original message
   context->x[14] = htole32((uint32_t) totalSize);
   context->x[15] = htole32((uint32_t) (totalSize >> 32));

   //Calculate the message digest
   ripemd160ProcessBlock(context);

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 5; i++)
   {
      context->h[i] = htole32(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, RIPEMD160_DIGEST_SIZE);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the RIPEMD-160 context
 **/

void ripemd160ProcessBlock(Ripemd160Context *context)
{
   uint_t i;

   //Initialize the working registers
   uint32_t aa= context->h[0];
   uint32_t bb = context->h[1];
   uint32_t cc = context->h[2];
   uint32_t dd = context->h[3];
   uint32_t ee = context->h[4];
   uint32_t aaa = context->h[0];
   uint32_t bbb = context->h[1];
   uint32_t ccc = context->h[2];
   uint32_t ddd = context->h[3];
   uint32_t eee = context->h[4];

   //Process message in 16-word blocks
   uint32_t *x = context->x;

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      x[i] = letoh32(x[i]);
   }

   //Round 1
   FF(aa, bb, cc, dd, ee, x[0],  11);
   FF(ee, aa, bb, cc, dd, x[1],  14);
   FF(dd, ee, aa, bb, cc, x[2],  15);
   FF(cc, dd, ee, aa, bb, x[3],  12);
   FF(bb, cc, dd, ee, aa, x[4],  5);
   FF(aa, bb, cc, dd, ee, x[5],  8);
   FF(ee, aa, bb, cc, dd, x[6],  7);
   FF(dd, ee, aa, bb, cc, x[7],  9);
   FF(cc, dd, ee, aa, bb, x[8],  11);
   FF(bb, cc, dd, ee, aa, x[9],  13);
   FF(aa, bb, cc, dd, ee, x[10], 14);
   FF(ee, aa, bb, cc, dd, x[11], 15);
   FF(dd, ee, aa, bb, cc, x[12], 6);
   FF(cc, dd, ee, aa, bb, x[13], 7);
   FF(bb, cc, dd, ee, aa, x[14], 9);
   FF(aa, bb, cc, dd, ee, x[15], 8);

   //Round 2
   GG(ee, aa, bb, cc, dd, x[7],  7);
   GG(dd, ee, aa, bb, cc, x[4],  6);
   GG(cc, dd, ee, aa, bb, x[13], 8);
   GG(bb, cc, dd, ee, aa, x[1],  13);
   GG(aa, bb, cc, dd, ee, x[10], 11);
   GG(ee, aa, bb, cc, dd, x[6],  9);
   GG(dd, ee, aa, bb, cc, x[15], 7);
   GG(cc, dd, ee, aa, bb, x[3],  15);
   GG(bb, cc, dd, ee, aa, x[12], 7);
   GG(aa, bb, cc, dd, ee, x[0],  12);
   GG(ee, aa, bb, cc, dd, x[9],  15);
   GG(dd, ee, aa, bb, cc, x[5],  9);
   GG(cc, dd, ee, aa, bb, x[2],  11);
   GG(bb, cc, dd, ee, aa, x[14], 7);
   GG(aa, bb, cc, dd, ee, x[11], 13);
   GG(ee, aa, bb, cc, dd, x[8],  12);

   //Round 3
   HH(dd, ee, aa, bb, cc, x[3],  11);
   HH(cc, dd, ee, aa, bb, x[10], 13);
   HH(bb, cc, dd, ee, aa, x[14], 6);
   HH(aa, bb, cc, dd, ee, x[4],  7);
   HH(ee, aa, bb, cc, dd, x[9],  14);
   HH(dd, ee, aa, bb, cc, x[15], 9);
   HH(cc, dd, ee, aa, bb, x[8],  13);
   HH(bb, cc, dd, ee, aa, x[1],  15);
   HH(aa, bb, cc, dd, ee, x[2],  14);
   HH(ee, aa, bb, cc, dd, x[7],  8);
   HH(dd, ee, aa, bb, cc, x[0],  13);
   HH(cc, dd, ee, aa, bb, x[6],  6);
   HH(bb, cc, dd, ee, aa, x[13], 5);
   HH(aa, bb, cc, dd, ee, x[11], 12);
   HH(ee, aa, bb, cc, dd, x[5],  7);
   HH(dd, ee, aa, bb, cc, x[12], 5);

   //Round 4
   II(cc, dd, ee, aa, bb, x[1],  11);
   II(bb, cc, dd, ee, aa, x[9],  12);
   II(aa, bb, cc, dd, ee, x[11], 14);
   II(ee, aa, bb, cc, dd, x[10], 15);
   II(dd, ee, aa, bb, cc, x[0],  14);
   II(cc, dd, ee, aa, bb, x[8],  15);
   II(bb, cc, dd, ee, aa, x[12], 9);
   II(aa, bb, cc, dd, ee, x[4],  8);
   II(ee, aa, bb, cc, dd, x[13], 9);
   II(dd, ee, aa, bb, cc, x[3],  14);
   II(cc, dd, ee, aa, bb, x[7],  5);
   II(bb, cc, dd, ee, aa, x[15], 6);
   II(aa, bb, cc, dd, ee, x[14], 8);
   II(ee, aa, bb, cc, dd, x[5],  6);
   II(dd, ee, aa, bb, cc, x[6],  5);
   II(cc, dd, ee, aa, bb, x[2],  12);

   //Round 5
   JJ(bb, cc, dd, ee, aa, x[4],  9);
   JJ(aa, bb, cc, dd, ee, x[0],  15);
   JJ(ee, aa, bb, cc, dd, x[5],  5);
   JJ(dd, ee, aa, bb, cc, x[9],  11);
   JJ(cc, dd, ee, aa, bb, x[7],  6);
   JJ(bb, cc, dd, ee, aa, x[12], 8);
   JJ(aa, bb, cc, dd, ee, x[2],  13);
   JJ(ee, aa, bb, cc, dd, x[10], 12);
   JJ(dd, ee, aa, bb, cc, x[14], 5);
   JJ(cc, dd, ee, aa, bb, x[1],  12);
   JJ(bb, cc, dd, ee, aa, x[3],  13);
   JJ(aa, bb, cc, dd, ee, x[8],  14);
   JJ(ee, aa, bb, cc, dd, x[11], 11);
   JJ(dd, ee, aa, bb, cc, x[6],  8);
   JJ(cc, dd, ee, aa, bb, x[15], 5);
   JJ(bb, cc, dd, ee, aa, x[13], 6);

   //Parallel round 1
   JJJ(aaa, bbb, ccc, ddd, eee, x[5],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, x[14], 9);
   JJJ(ddd, eee, aaa, bbb, ccc, x[7],  9);
   JJJ(ccc, ddd, eee, aaa, bbb, x[0],  11);
   JJJ(bbb, ccc, ddd, eee, aaa, x[9],  13);
   JJJ(aaa, bbb, ccc, ddd, eee, x[2],  15);
   JJJ(eee, aaa, bbb, ccc, ddd, x[11], 15);
   JJJ(ddd, eee, aaa, bbb, ccc, x[4],  5);
   JJJ(ccc, ddd, eee, aaa, bbb, x[13], 7);
   JJJ(bbb, ccc, ddd, eee, aaa, x[6],  7);
   JJJ(aaa, bbb, ccc, ddd, eee, x[15], 8);
   JJJ(eee, aaa, bbb, ccc, ddd, x[8],  11);
   JJJ(ddd, eee, aaa, bbb, ccc, x[1],  14);
   JJJ(ccc, ddd, eee, aaa, bbb, x[10], 14);
   JJJ(bbb, ccc, ddd, eee, aaa, x[3],  12);
   JJJ(aaa, bbb, ccc, ddd, eee, x[12], 6);

   //Parallel round 2
   III(eee, aaa, bbb, ccc, ddd, x[6],   9);
   III(ddd, eee, aaa, bbb, ccc, x[11], 13);
   III(ccc, ddd, eee, aaa, bbb, x[3],  15);
   III(bbb, ccc, ddd, eee, aaa, x[7],  7);
   III(aaa, bbb, ccc, ddd, eee, x[0],  12);
   III(eee, aaa, bbb, ccc, ddd, x[13], 8);
   III(ddd, eee, aaa, bbb, ccc, x[5],  9);
   III(ccc, ddd, eee, aaa, bbb, x[10], 11);
   III(bbb, ccc, ddd, eee, aaa, x[14], 7);
   III(aaa, bbb, ccc, ddd, eee, x[15], 7);
   III(eee, aaa, bbb, ccc, ddd, x[8],  12);
   III(ddd, eee, aaa, bbb, ccc, x[12], 7);
   III(ccc, ddd, eee, aaa, bbb, x[4],  6);
   III(bbb, ccc, ddd, eee, aaa, x[9],  15);
   III(aaa, bbb, ccc, ddd, eee, x[1],  13);
   III(eee, aaa, bbb, ccc, ddd, x[2],  11);

   //Parallel round 3
   HHH(ddd, eee, aaa, bbb, ccc, x[15], 9);
   HHH(ccc, ddd, eee, aaa, bbb, x[5],  7);
   HHH(bbb, ccc, ddd, eee, aaa, x[1],  15);
   HHH(aaa, bbb, ccc, ddd, eee, x[3],  11);
   HHH(eee, aaa, bbb, ccc, ddd, x[7],  8);
   HHH(ddd, eee, aaa, bbb, ccc, x[14], 6);
   HHH(ccc, ddd, eee, aaa, bbb, x[6],  6);
   HHH(bbb, ccc, ddd, eee, aaa, x[9],  14);
   HHH(aaa, bbb, ccc, ddd, eee, x[11], 12);
   HHH(eee, aaa, bbb, ccc, ddd, x[8],  13);
   HHH(ddd, eee, aaa, bbb, ccc, x[12], 5);
   HHH(ccc, ddd, eee, aaa, bbb, x[2],  14);
   HHH(bbb, ccc, ddd, eee, aaa, x[10], 13);
   HHH(aaa, bbb, ccc, ddd, eee, x[0],  13);
   HHH(eee, aaa, bbb, ccc, ddd, x[4],  7);
   HHH(ddd, eee, aaa, bbb, ccc, x[13], 5);

   //Parallel round 4
   GGG(ccc, ddd, eee, aaa, bbb, x[8],  15);
   GGG(bbb, ccc, ddd, eee, aaa, x[6],  5);
   GGG(aaa, bbb, ccc, ddd, eee, x[4],  8);
   GGG(eee, aaa, bbb, ccc, ddd, x[1],  11);
   GGG(ddd, eee, aaa, bbb, ccc, x[3],  14);
   GGG(ccc, ddd, eee, aaa, bbb, x[11], 14);
   GGG(bbb, ccc, ddd, eee, aaa, x[15], 6);
   GGG(aaa, bbb, ccc, ddd, eee, x[0],  14);
   GGG(eee, aaa, bbb, ccc, ddd, x[5],  6);
   GGG(ddd, eee, aaa, bbb, ccc, x[12], 9);
   GGG(ccc, ddd, eee, aaa, bbb, x[2],  12);
   GGG(bbb, ccc, ddd, eee, aaa, x[13], 9);
   GGG(aaa, bbb, ccc, ddd, eee, x[9],  12);
   GGG(eee, aaa, bbb, ccc, ddd, x[7],  5);
   GGG(ddd, eee, aaa, bbb, ccc, x[10], 15);
   GGG(ccc, ddd, eee, aaa, bbb, x[14], 8);

   //Parallel round 5
   FFF(bbb, ccc, ddd, eee, aaa, x[12], 8);
   FFF(aaa, bbb, ccc, ddd, eee, x[15], 5);
   FFF(eee, aaa, bbb, ccc, ddd, x[10], 12);
   FFF(ddd, eee, aaa, bbb, ccc, x[4],  9);
   FFF(ccc, ddd, eee, aaa, bbb, x[1],  12);
   FFF(bbb, ccc, ddd, eee, aaa, x[5],  5);
   FFF(aaa, bbb, ccc, ddd, eee, x[8],  14);
   FFF(eee, aaa, bbb, ccc, ddd, x[7],  6);
   FFF(ddd, eee, aaa, bbb, ccc, x[6],  8);
   FFF(ccc, ddd, eee, aaa, bbb, x[2],  13);
   FFF(bbb, ccc, ddd, eee, aaa, x[13], 6);
   FFF(aaa, bbb, ccc, ddd, eee, x[14], 5);
   FFF(eee, aaa, bbb, ccc, ddd, x[0],  15);
   FFF(ddd, eee, aaa, bbb, ccc, x[3],  13);
   FFF(ccc, ddd, eee, aaa, bbb, x[9],  11);
   FFF(bbb, ccc, ddd, eee, aaa, x[11], 11);

   //Combine results
   ddd = context->h[1] + cc + ddd;
   context->h[1] = context->h[2] + dd + eee;
   context->h[2] = context->h[3] + ee + aaa;
   context->h[3] = context->h[4] + aa + bbb;
   context->h[4] = context->h[0] + bb + ccc;
   context->h[0] = ddd;
}

#endif
