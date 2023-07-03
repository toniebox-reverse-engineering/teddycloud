/**
 * @file md5.c
 * @brief MD5 (Message-Digest Algorithm)
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
 * The MD5 algorithm takes as input a message of arbitrary length and produces
 * as output a 128-bit message digest of the input. Refer to RFC 1321
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/md5.h"

//Check crypto library configuration
#if (MD5_SUPPORT == ENABLED)

//MD5 auxiliary functions
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define FF(a, b, c, d, x, s, k) a += F(b, c, d) + (x) + (k), a = ROL32(a, s) + (b)
#define GG(a, b, c, d, x, s, k) a += G(b, c, d) + (x) + (k), a = ROL32(a, s) + (b)
#define HH(a, b, c, d, x, s, k) a += H(b, c, d) + (x) + (k), a = ROL32(a, s) + (b)
#define II(a, b, c, d, x, s, k) a += I(b, c, d) + (x) + (k), a = ROL32(a, s) + (b)

//MD5 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//MD5 constants
static const uint32_t k[64] =
{
   0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
   0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
   0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
   0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
   0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
   0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
   0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
   0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

//MD5 object identifier (1.2.840.113549.2.5)
const uint8_t md5Oid[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05};

//Common interface for hash algorithms
const HashAlgo md5HashAlgo =
{
   "MD5",
   md5Oid,
   sizeof(md5Oid),
   sizeof(Md5Context),
   MD5_BLOCK_SIZE,
   MD5_DIGEST_SIZE,
   MD5_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) md5Compute,
   (HashAlgoInit) md5Init,
   (HashAlgoUpdate) md5Update,
   (HashAlgoFinal) md5Final,
   (HashAlgoFinalRaw) md5FinalRaw
};


/**
 * @brief Digest a message using MD5
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t md5Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Md5Context *context;

   //Allocate a memory buffer to hold the MD5 context
   context = cryptoAllocMem(sizeof(Md5Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the MD5 context
      md5Init(context);
      //Digest the message
      md5Update(context, data, length);
      //Finalize the MD5 message digest
      md5Final(context, digest);

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
 * @brief Initialize MD5 message digest context
 * @param[in] context Pointer to the MD5 context to initialize
 **/

__weak_func void md5Init(Md5Context *context)
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
 * @brief Update the MD5 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD5 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void md5Update(Md5Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the MD5 context
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
         md5ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the MD5 message digest
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

__weak_func void md5Final(Md5Context *context, uint8_t *digest)
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
   md5Update(context, padding, paddingSize);

   //Append the length of the original message
   context->x[14] = htole32((uint32_t) totalSize);
   context->x[15] = htole32((uint32_t) (totalSize >> 32));

   //Calculate the message digest
   md5ProcessBlock(context);

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 4; i++)
   {
      context->h[i] = htole32(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, MD5_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the MD5 message digest (no padding added)
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest
 **/

__weak_func void md5FinalRaw(Md5Context *context, uint8_t *digest)
{
   uint_t i;

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 4; i++)
   {
      context->h[i] = htole32(context->h[i]);
   }

   //Copy the resulting digest
   osMemcpy(digest, context->digest, MD5_DIGEST_SIZE);

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 4; i++)
   {
      context->h[i] = letoh32(context->h[i]);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the MD5 context
 **/

__weak_func void md5ProcessBlock(Md5Context *context)
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
   FF(a, b, c, d, x[0],  7,  k[0]);
   FF(d, a, b, c, x[1],  12, k[1]);
   FF(c, d, a, b, x[2],  17, k[2]);
   FF(b, c, d, a, x[3],  22, k[3]);
   FF(a, b, c, d, x[4],  7,  k[4]);
   FF(d, a, b, c, x[5],  12, k[5]);
   FF(c, d, a, b, x[6],  17, k[6]);
   FF(b, c, d, a, x[7],  22, k[7]);
   FF(a, b, c, d, x[8],  7,  k[8]);
   FF(d, a, b, c, x[9],  12, k[9]);
   FF(c, d, a, b, x[10], 17, k[10]);
   FF(b, c, d, a, x[11], 22, k[11]);
   FF(a, b, c, d, x[12], 7,  k[12]);
   FF(d, a, b, c, x[13], 12, k[13]);
   FF(c, d, a, b, x[14], 17, k[14]);
   FF(b, c, d, a, x[15], 22, k[15]);

   //Round 2
   GG(a, b, c, d, x[1],  5,  k[16]);
   GG(d, a, b, c, x[6],  9,  k[17]);
   GG(c, d, a, b, x[11], 14, k[18]);
   GG(b, c, d, a, x[0],  20, k[19]);
   GG(a, b, c, d, x[5],  5,  k[20]);
   GG(d, a, b, c, x[10], 9,  k[21]);
   GG(c, d, a, b, x[15], 14, k[22]);
   GG(b, c, d, a, x[4],  20, k[23]);
   GG(a, b, c, d, x[9],  5,  k[24]);
   GG(d, a, b, c, x[14], 9,  k[25]);
   GG(c, d, a, b, x[3],  14, k[26]);
   GG(b, c, d, a, x[8],  20, k[27]);
   GG(a, b, c, d, x[13], 5,  k[28]);
   GG(d, a, b, c, x[2],  9,  k[29]);
   GG(c, d, a, b, x[7],  14, k[30]);
   GG(b, c, d, a, x[12], 20, k[31]);

   //Round 3
   HH(a, b, c, d, x[5],  4,  k[32]);
   HH(d, a, b, c, x[8],  11, k[33]);
   HH(c, d, a, b, x[11], 16, k[34]);
   HH(b, c, d, a, x[14], 23, k[35]);
   HH(a, b, c, d, x[1],  4,  k[36]);
   HH(d, a, b, c, x[4],  11, k[37]);
   HH(c, d, a, b, x[7],  16, k[38]);
   HH(b, c, d, a, x[10], 23, k[39]);
   HH(a, b, c, d, x[13], 4,  k[40]);
   HH(d, a, b, c, x[0],  11, k[41]);
   HH(c, d, a, b, x[3],  16, k[42]);
   HH(b, c, d, a, x[6],  23, k[43]);
   HH(a, b, c, d, x[9],  4,  k[44]);
   HH(d, a, b, c, x[12], 11, k[45]);
   HH(c, d, a, b, x[15], 16, k[46]);
   HH(b, c, d, a, x[2],  23, k[47]);

   //Round 4
   II(a, b, c, d, x[0],  6,  k[48]);
   II(d, a, b, c, x[7],  10, k[49]);
   II(c, d, a, b, x[14], 15, k[50]);
   II(b, c, d, a, x[5],  21, k[51]);
   II(a, b, c, d, x[12], 6,  k[52]);
   II(d, a, b, c, x[3],  10, k[53]);
   II(c, d, a, b, x[10], 15, k[54]);
   II(b, c, d, a, x[1],  21, k[55]);
   II(a, b, c, d, x[8],  6,  k[56]);
   II(d, a, b, c, x[15], 10, k[57]);
   II(c, d, a, b, x[6],  15, k[58]);
   II(b, c, d, a, x[13], 21, k[59]);
   II(a, b, c, d, x[4],  6,  k[60]);
   II(d, a, b, c, x[11], 10, k[61]);
   II(c, d, a, b, x[2],  15, k[62]);
   II(b, c, d, a, x[9],  21, k[63]);

   //Update the hash value
   context->h[0] += a;
   context->h[1] += b;
   context->h[2] += c;
   context->h[3] += d;
}

#endif
