/**
 * @file blake2b.c
 * @brief BLAKE2 cryptographic hash and MAC (BLAKE2b variant)
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
 * BLAKE2b is cryptographic hash function optimized for 64-bit platforms that
 * produces digests of any size between 1 and 64 bytes. Refer to RFC 7693 for
 * more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/blake2b.h"

//Check crypto library configuration
#if (BLAKE2B_SUPPORT == ENABLED)

//Mixing function G (borrowed from ChaCha quarter-round function)
#define G(a, b, c, d, x, y) \
{ \
   a += b + x; \
   d ^= a; \
   d = ROR64(d, 32); \
   c += d; \
   b ^= c; \
   b = ROR64(b, 24); \
   a += b + y; \
   d ^= a; \
   d = ROR64(d, 16); \
   c += d; \
   b ^= c; \
   b = ROR64(b, 63); \
}

//Message schedule SIGMA
static const uint8_t sigma[12][16] =
{
   {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
   {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
   {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
   {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
   {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
   {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
   {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
   {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
   {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
   {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
   {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
   {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

//Initialization vector
static const uint64_t iv[8] =
{
   0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
   0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};


/**
 * @brief Digest a message using BLAKE2b
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @param[in] data Pointer to the message being hashed
 * @param[in] dataLen Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @param[in] digestLen Expected length of the digest
 * @return Error code
 **/

error_t blake2bCompute(const void *key, size_t keyLen, const void *data,
   size_t dataLen, uint8_t *digest, size_t digestLen)
{
   error_t error;
   Blake2bContext *context;

   //Allocate a memory buffer to hold the BLAKE2b context
   context = cryptoAllocMem(sizeof(Blake2bContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the hashing context
      error = blake2bInit(context, key, keyLen, digestLen);

      //Check status code
      if(!error)
      {
         //Digest the message
         blake2bUpdate(context, data, dataLen);
         //Finalize the BLAKE2b message digest
         blake2bFinal(context, digest);
      }

      //Free previously allocated memory
      cryptoFreeMem(context);
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
 * @brief Initialize BLAKE2b message digest context
 * @param[in] context Pointer to the BLAKE2b context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @param[in] digestLen Expected length of the digest
 * @return Error code
 **/

error_t blake2bInit(Blake2bContext *context, const void *key,
   size_t keyLen, size_t digestLen)
{
   size_t i;

   //Check the length of the key
   if(keyLen > 64)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the hash
   if(digestLen < 1 || digestLen > 64)
      return ERROR_INVALID_PARAMETER;

   //Initialize state vector
   for(i = 0; i < 8; i++)
   {
      context->h[i] = iv[i];
   }

   //The first byte of the parameter block is the hash size in bytes
   context->h[0] ^= digestLen;
   //The second byte of the parameter block is the key size in bytes
   context->h[0] ^= keyLen << 8;
   //Bytes 2 and 3 are set as 01
   context->h[0] ^= 0x01010000;

   //Number of bytes in the buffer
   context->size = 0;

   //Total number of bytes
   context->totalSize[0] = 0;
   context->totalSize[1] = 0;

   //Size of the digest
   context->digestSize = digestLen;

   //Clear input buffer
   osMemset(context->buffer, 0, 128);

   //Any secret key?
   if(keyLen > 0)
   {
      //Copy the secret key
      osMemcpy(context->buffer, key, keyLen);
      //The secret key is padded with zero bytes
      context->size = 128;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Update the BLAKE2b context with a portion of the message being hashed
 * @param[in] context Pointer to the BLAKE2b context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void blake2bUpdate(Blake2bContext *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Each message block consists of 16 words
      if(context->size == 128)
      {
         //Compress the 16-word block
         blake2bProcessBlock(context, FALSE);
         //Empty the buffer
         context->size = 0;
      }

      //The buffer can hold at most 128 bytes
      n = MIN(length, 128 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);
      //Update the length of the buffer
      context->size += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }
}


/**
 * @brief Finish the BLAKE2b message digest
 * @param[in] context Pointer to the BLAKE2b context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void blake2bFinal(Blake2bContext *context, uint8_t *digest)
{
   size_t i;

   //The last block is padded with zeros to full block size, if required
   for(i = context->size; i < 128; i++)
   {
      context->buffer[i] = 0;
   }

   //Compress the last block
   blake2bProcessBlock(context, TRUE);

   //Convert from host byte order to big-endian byte order
   for(i = 0; i < 8; i++)
   {
      context->h[i] = htole64(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, context->digestSize);
   }
}


/**
 * @brief Compression function F
 * @param[in] context Pointer to the BLAKE2b context
 * @param[in] last Flag indicating the last block
 **/

void blake2bProcessBlock(Blake2bContext *context, bool_t last)
{
   uint_t i;
   uint64_t *m;
   uint64_t v[16];

   //Initialize the working vector
   for(i = 0; i < 8; i++)
   {
      //First half from state
      v[i] = context->h[i];
      //Second half from IV
      v[i + 8] = iv[i];
   }

   //Increment offset counter
   context->totalSize[0] += context->size;

   //Propagate the carry if necessary
   if(context->totalSize[0] < context->size)
   {
      context->totalSize[1]++;
   }

   //Low word of the offset
   v[12] ^= context->totalSize[0];
   //High word of the offset
   v[13] ^= context->totalSize[1];

   //Last block flag?
   if(last)
   {
      //Invert all bits
      v[14] = ~v[14];
   }

   //Point to the message block vector
   m = context->m;

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      m[i] = letoh64(m[i]);
   }

   //Cryptographic mixing
   for(i = 0; i < 12; i++)
   {
      //The column rounds apply the quarter-round function to the four
      //columns, from left to right
      G(v[0], v[4], v[8],  v[12], m[sigma[i][0]], m[sigma[i][1]]);
      G(v[1], v[5], v[9],  v[13], m[sigma[i][2]], m[sigma[i][3]]);
      G(v[2], v[6], v[10], v[14], m[sigma[i][4]], m[sigma[i][5]]);
      G(v[3], v[7], v[11], v[15], m[sigma[i][6]], m[sigma[i][7]]);

      //The diagonal rounds apply the quarter-round function to the top-left,
      //bottom-right diagonal, followed by the pattern shifted one place to
      //the right, for three more quarter-rounds
      G(v[0], v[5], v[10], v[15], m[sigma[i][8]],  m[sigma[i][9]]);
      G(v[1], v[6], v[11], v[12], m[sigma[i][10]], m[sigma[i][11]]);
      G(v[2], v[7], v[8],  v[13], m[sigma[i][12]], m[sigma[i][13]]);
      G(v[3], v[4], v[9],  v[14], m[sigma[i][14]], m[sigma[i][15]]);
   }

   //XOR the two halves
   for(i = 0; i < 8; i++)
   {
      context->h[i] ^= v[i] ^ v[i + 8];
   }
}

#endif
