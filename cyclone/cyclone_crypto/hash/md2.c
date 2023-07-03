/**
 * @file md2.c
 * @brief MD2 (Message-Digest Algorithm)
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
 * The MD2 algorithm takes as input a message of arbitrary length and produces
 * as output a 128-bit message digest of the input. Refer to RFC 1319
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/md2.h"

//Check crypto library configuration
#if (MD2_SUPPORT == ENABLED)

//MD2 constants
static const uint8_t s[256] =
{
   0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
   0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
   0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
   0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
   0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
   0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
   0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
   0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
   0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
   0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
   0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
   0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
   0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
   0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
   0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
   0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
};

//MD2 object identifier (1.2.840.113549.2.2)
const uint8_t md2Oid[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02};

//Common interface for hash algorithms
const HashAlgo md2HashAlgo =
{
   "MD2",
   md2Oid,
   sizeof(md2Oid),
   sizeof(Md2Context),
   MD2_BLOCK_SIZE,
   MD2_DIGEST_SIZE,
   MD2_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) md2Compute,
   (HashAlgoInit) md2Init,
   (HashAlgoUpdate) md2Update,
   (HashAlgoFinal) md2Final,
   NULL
};


/**
 * @brief Digest a message using MD2
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t md2Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Md2Context *context;

   //Allocate a memory buffer to hold the MD2 context
   context = cryptoAllocMem(sizeof(Md2Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the MD2 context
      md2Init(context);
      //Digest the message
      md2Update(context, data, length);
      //Finalize the MD2 message digest
      md2Final(context, digest);

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
 * @brief Initialize MD2 message digest context
 * @param[in] context Pointer to the MD2 context to initialize
 **/

void md2Init(Md2Context *context)
{
   //Initialize the 48-byte buffer X
   osMemset(context->x, 0, 48);
   //Clear checksum
   osMemset(context->c, 0, 16);
   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update the MD2 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD2 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void md2Update(Md2Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 16 bytes
      n = MIN(length, 16 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->m + context->size, data, n);

      //Update the MD2 context
      context->size += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 16-word blocks
      if(context->size == 16)
      {
         //Transform the 16-word block
         md2ProcessBlock(context->m, context->x, context->c);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the MD2 message digest
 * @param[in] context Pointer to the MD2 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void md2Final(Md2Context *context, uint8_t *digest)
{
   uint_t n;

   //Pad the message so that its length is congruent to 0 modulo 16
   n = 16 - context->size;

   //Append padding bytes
   osMemset(context->m + context->size, n, n);
   //Transform the 16-word block
   md2ProcessBlock(context->m, context->x, context->c);

   //Append the checksum
   osMemcpy(context->m, context->c, 16);
   //Transform the 16-word block
   md2ProcessBlock(context->m, context->x, context->c);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, MD2_DIGEST_SIZE);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] m 16-byte data block to process
 * @param[in,out] x 48-byte buffer
 * @param[in,out] c 16-byte checksum
 **/

void md2ProcessBlock(const uint8_t *m, uint8_t *x, uint8_t *c)
{
   uint_t j;
   uint_t k;
   uint8_t t;

   //Update checksum
   for(t = c[15], j = 0; j < 16; j++)
   {
      c[j] ^= s[m[j] ^ t];
      t = c[j];
   }

   //Copy current block into X
   for(j = 0; j < 16; j++)
   {
      x[16 + j] = m[j];
      x[32 + j] = x[16 + j] ^ x[j];
   }

   //Encrypt block (18 rounds)
   for(t = 0, j = 0; j < 18; j++)
   {
      //Round j
      for(k = 0; k < 48; k++)
      {
         x[k] ^= s[t];
         t = x[k];
      }

      //Set t to (t + j) modulo 256
      t = (t + j) & 0xFF;
   }
}

#endif
