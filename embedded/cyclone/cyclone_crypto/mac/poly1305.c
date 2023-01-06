/**
 * @file poly1305.c
 * @brief Poly1305 message-authentication code
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
#include "mac/poly1305.h"
#include "debug.h"

//Check crypto library configuration
#if (POLY1305_SUPPORT == ENABLED)


/**
 * @brief Initialize Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context to initialize
 * @param[in] key Pointer to the 256-bit key
 **/

void poly1305Init(Poly1305Context *context, const uint8_t *key)
{
   //The 256-bit key is partitioned into two parts, called r and s
   context->r[0] = LOAD32LE(key);
   context->r[1] = LOAD32LE(key + 4);
   context->r[2] = LOAD32LE(key + 8);
   context->r[3] = LOAD32LE(key + 12);
   context->s[0] = LOAD32LE(key + 16);
   context->s[1] = LOAD32LE(key + 20);
   context->s[2] = LOAD32LE(key + 24);
   context->s[3] = LOAD32LE(key + 28);

   //Certain bits of r are required to be 0
   context->r[0] &= 0x0FFFFFFF;
   context->r[1] &= 0x0FFFFFFC;
   context->r[2] &= 0x0FFFFFFC;
   context->r[3] &= 0x0FFFFFFC;

   //The accumulator is set to zero
   context->a[0] = 0;
   context->a[1] = 0;
   context->a[2] = 0;
   context->a[3] = 0;
   context->a[4] = 0;
   context->a[5] = 0;
   context->a[6] = 0;
   context->a[7] = 0;

   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context
 * @param[in] data Pointer to the input message
 * @param[in] length Length of the input message
 **/

void poly1305Update(Poly1305Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 16 bytes
      n = MIN(length, 16 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the Poly1305 context
      context->size += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 16-byte blocks
      if(context->size == 16)
      {
         //Transform the 16-byte block
         poly1305ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finalize Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context
 * @param[out] tag Calculated message-authentication code
 **/

void poly1305Final(Poly1305Context *context, uint8_t *tag)
{
   uint32_t mask;
   uint32_t b[4];

   //Process the last block
   if(context->size != 0)
      poly1305ProcessBlock(context);

   //Save the accumulator
   b[0] = context->a[0] & 0xFFFFFFFF;
   b[1] = context->a[1] & 0xFFFFFFFF;
   b[2] = context->a[2] & 0xFFFFFFFF;
   b[3] = context->a[3] & 0xFFFFFFFF;

   //Compute a + 5
   context->a[0] += 5;

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;

   //If (a + 5) >= 2^130, form a mask with the value 0x00000000. Else,
   //form a mask with the value 0xffffffff
   mask = ((context->a[4] & 0x04) >> 2) - 1;

   //Select between ((a - (2^130 - 5)) % 2^128) and (a % 2^128)
   context->a[0] = (context->a[0] & ~mask) | (b[0] & mask);
   context->a[1] = (context->a[1] & ~mask) | (b[1] & mask);
   context->a[2] = (context->a[2] & ~mask) | (b[2] & mask);
   context->a[3] = (context->a[3] & ~mask) | (b[3] & mask);

   //Finally, the value of the secret key s is added to the accumulator
   context->a[0] += context->s[0];
   context->a[1] += context->s[1];
   context->a[2] += context->s[2];
   context->a[3] += context->s[3];

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;

   //We only consider the least significant bits
   b[0] = context->a[0] & 0xFFFFFFFF;
   b[1] = context->a[1] & 0xFFFFFFFF;
   b[2] = context->a[2] & 0xFFFFFFFF;
   b[3] = context->a[3] & 0xFFFFFFFF;

   //The result is serialized as a little-endian number, producing
   //the 16 byte tag
   STORE32LE(b[0], tag);
   STORE32LE(b[1], tag + 4);
   STORE32LE(b[2], tag + 8);
   STORE32LE(b[3], tag + 12);

   //Clear the accumulator
   context->a[0] = 0;
   context->a[1] = 0;
   context->a[2] = 0;
   context->a[3] = 0;
   context->a[4] = 0;
   context->a[5] = 0;
   context->a[6] = 0;
   context->a[7] = 0;

   //Clear r and s
   context->r[0] = 0;
   context->r[1] = 0;
   context->r[2] = 0;
   context->r[3] = 0;
   context->s[0] = 0;
   context->s[1] = 0;
   context->s[2] = 0;
   context->s[3] = 0;
}


/**
 * @brief Process message in 16-byte blocks
 * @param[in] context Pointer to the Poly1305 context
 **/

void poly1305ProcessBlock(Poly1305Context *context)
{
   uint32_t a[5];
   uint32_t r[4];
   uint_t n;

   //Retrieve the length of the last block
   n = context->size;

   //Add one bit beyond the number of octets. For a 16-byte block,
   //this is equivalent to adding 2^128 to the number. For the shorter
   //block, it can be 2^120, 2^112, or any power of two that is evenly
   //divisible by 8, all the way down to 2^8
   context->buffer[n++] = 0x01;

   //If the resulting block is not 17 bytes long (the last block),
   //pad it with zeros
   while(n < 17)
   {
      context->buffer[n++] = 0x00;
   }

   //Read the block as a little-endian number
   a[0] = LOAD32LE(context->buffer);
   a[1] = LOAD32LE(context->buffer + 4);
   a[2] = LOAD32LE(context->buffer + 8);
   a[3] = LOAD32LE(context->buffer + 12);
   a[4] = context->buffer[16];

   //Add this number to the accumulator
   context->a[0] += a[0];
   context->a[1] += a[1];
   context->a[2] += a[2];
   context->a[3] += a[3];
   context->a[4] += a[4];

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;

   //We only consider the least significant bits
   a[0] = context->a[0] & 0xFFFFFFFF;
   a[1] = context->a[1] & 0xFFFFFFFF;
   a[2] = context->a[2] & 0xFFFFFFFF;
   a[3] = context->a[3] & 0xFFFFFFFF;
   a[4] = context->a[4] & 0xFFFFFFFF;

   //Copy r
   r[0] = context->r[0];
   r[1] = context->r[1];
   r[2] = context->r[2];
   r[3] = context->r[3];

   //Multiply the accumulator by r
   context->a[0] = (uint64_t) a[0] * r[0];
   context->a[1] = (uint64_t) a[0] * r[1] + (uint64_t) a[1] * r[0];
   context->a[2] = (uint64_t) a[0] * r[2] + (uint64_t) a[1] * r[1] + (uint64_t) a[2] * r[0];
   context->a[3] = (uint64_t) a[0] * r[3] + (uint64_t) a[1] * r[2] + (uint64_t) a[2] * r[1] + (uint64_t) a[3] * r[0];
   context->a[4] = (uint64_t) a[1] * r[3] + (uint64_t) a[2] * r[2] + (uint64_t) a[3] * r[1] + (uint64_t) a[4] * r[0];
   context->a[5] = (uint64_t) a[2] * r[3] + (uint64_t) a[3] * r[2] + (uint64_t) a[4] * r[1];
   context->a[6] = (uint64_t) a[3] * r[3] + (uint64_t) a[4] * r[2];
   context->a[7] = (uint64_t) a[4] * r[3];

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;
   context->a[5] += context->a[4] >> 32;
   context->a[6] += context->a[5] >> 32;
   context->a[7] += context->a[6] >> 32;

   //Save the high part of the accumulator
   a[0] = context->a[4] & 0xFFFFFFFC;
   a[1] = context->a[5] & 0xFFFFFFFF;
   a[2] = context->a[6] & 0xFFFFFFFF;
   a[3] = context->a[7] & 0xFFFFFFFF;

   //We only consider the least significant bits
   context->a[0] &= 0xFFFFFFFF;
   context->a[1] &= 0xFFFFFFFF;
   context->a[2] &= 0xFFFFFFFF;
   context->a[3] &= 0xFFFFFFFF;
   context->a[4] &= 0x00000003;

   //Perform fast modular reduction (first pass)
   context->a[0] += a[0];
   context->a[0] += (a[0] >> 2) | (a[1] << 30);
   context->a[1] += a[1];
   context->a[1] += (a[1] >> 2) | (a[2] << 30);
   context->a[2] += a[2];
   context->a[2] += (a[2] >> 2) | (a[3] << 30);
   context->a[3] += a[3];
   context->a[3] += (a[3] >> 2);

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;

   //Save the high part of the accumulator
   a[0] = context->a[4] & 0xFFFFFFFC;

   //We only consider the least significant bits
   context->a[0] &= 0xFFFFFFFF;
   context->a[1] &= 0xFFFFFFFF;
   context->a[2] &= 0xFFFFFFFF;
   context->a[3] &= 0xFFFFFFFF;
   context->a[4] &= 0x00000003;

   //Perform fast modular reduction (second pass)
   context->a[0] += a[0];
   context->a[0] += a[0] >> 2;

   //Propagate the carry
   context->a[1] += context->a[0] >> 32;
   context->a[2] += context->a[1] >> 32;
   context->a[3] += context->a[2] >> 32;
   context->a[4] += context->a[3] >> 32;

   //We only consider the least significant bits
   context->a[0] &= 0xFFFFFFFF;
   context->a[1] &= 0xFFFFFFFF;
   context->a[2] &= 0xFFFFFFFF;
   context->a[3] &= 0xFFFFFFFF;
   context->a[4] &= 0x00000003;
}

#endif
