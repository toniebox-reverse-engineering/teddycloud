/**
 * @file keccak.c
 * @brief Keccak sponge function
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
#include "xof/keccak.h"

//Check crypto library configuration
#if (KECCAK_SUPPORT == ENABLED)

//Keccak round constants
static const keccak_lane_t rc[KECCAK_NR] =
{
   (keccak_lane_t) 0x0000000000000001,
   (keccak_lane_t) 0x0000000000008082,
   (keccak_lane_t) 0x800000000000808A,
   (keccak_lane_t) 0x8000000080008000,
   (keccak_lane_t) 0x000000000000808B,
   (keccak_lane_t) 0x0000000080000001,
   (keccak_lane_t) 0x8000000080008081,
   (keccak_lane_t) 0x8000000000008009,
   (keccak_lane_t) 0x000000000000008A,
   (keccak_lane_t) 0x0000000000000088,
   (keccak_lane_t) 0x0000000080008009,
   (keccak_lane_t) 0x000000008000000A,
   (keccak_lane_t) 0x000000008000808B,
   (keccak_lane_t) 0x800000000000008B,
   (keccak_lane_t) 0x8000000000008089,
   (keccak_lane_t) 0x8000000000008003,
   (keccak_lane_t) 0x8000000000008002,
   (keccak_lane_t) 0x8000000000000080,
#if (KECCAK_L >= 4)
   (keccak_lane_t) 0x000000000000800A,
   (keccak_lane_t) 0x800000008000000A,
#endif
#if (KECCAK_L >= 5)
   (keccak_lane_t) 0x8000000080008081,
   (keccak_lane_t) 0x8000000000008080,
#endif
#if (KECCAK_L >= 6)
   (keccak_lane_t) 0x0000000080000001,
   (keccak_lane_t) 0x8000000080008008
#endif
};


/**
 * @brief Apply theta transformation
 * @param[in,out] a State array
 **/

static void theta(keccak_lane_t a[5][5])
{
   keccak_lane_t c[5];
   keccak_lane_t d[5];

   //The effect of the theta transformation is to XOR each bit in the
   //state with the parities of two columns in the array
   c[0] = a[0][0] ^ a[1][0] ^ a[2][0] ^ a[3][0] ^ a[4][0];
   c[1] = a[0][1] ^ a[1][1] ^ a[2][1] ^ a[3][1] ^ a[4][1];
   c[2] = a[0][2] ^ a[1][2] ^ a[2][2] ^ a[3][2] ^ a[4][2];
   c[3] = a[0][3] ^ a[1][3] ^ a[2][3] ^ a[3][3] ^ a[4][3];
   c[4] = a[0][4] ^ a[1][4] ^ a[2][4] ^ a[3][4] ^ a[4][4];

   d[0] = c[4] ^ KECCAK_ROL(c[1], 1);
   d[1] = c[0] ^ KECCAK_ROL(c[2], 1);
   d[2] = c[1] ^ KECCAK_ROL(c[3], 1);
   d[3] = c[2] ^ KECCAK_ROL(c[4], 1);
   d[4] = c[3] ^ KECCAK_ROL(c[0], 1);

   a[0][0] ^= d[0];
   a[1][0] ^= d[0];
   a[2][0] ^= d[0];
   a[3][0] ^= d[0];
   a[4][0] ^= d[0];

   a[0][1] ^= d[1];
   a[1][1] ^= d[1];
   a[2][1] ^= d[1];
   a[3][1] ^= d[1];
   a[4][1] ^= d[1];

   a[0][2] ^= d[2];
   a[1][2] ^= d[2];
   a[2][2] ^= d[2];
   a[3][2] ^= d[2];
   a[4][2] ^= d[2];

   a[0][3] ^= d[3];
   a[1][3] ^= d[3];
   a[2][3] ^= d[3];
   a[3][3] ^= d[3];
   a[4][3] ^= d[3];

   a[0][4] ^= d[4];
   a[1][4] ^= d[4];
   a[2][4] ^= d[4];
   a[3][4] ^= d[4];
   a[4][4] ^= d[4];
}


/**
 * @brief Apply rho transformation
 * @param[in,out] a State array
 **/

static void rho(keccak_lane_t a[5][5])
{
   //The effect of the rho transformation is to rotate the bits of each lane by
   //an offset, which depends on the fixed x and y coordinates of the lane
   a[0][1] = KECCAK_ROL(a[0][1], 1   % KECCAK_W);
   a[0][2] = KECCAK_ROL(a[0][2], 190 % KECCAK_W);
   a[0][3] = KECCAK_ROL(a[0][3], 28  % KECCAK_W);
   a[0][4] = KECCAK_ROL(a[0][4], 91  % KECCAK_W);

   a[1][0] = KECCAK_ROL(a[1][0], 36  % KECCAK_W);
   a[1][1] = KECCAK_ROL(a[1][1], 300 % KECCAK_W);
   a[1][2] = KECCAK_ROL(a[1][2], 6   % KECCAK_W);
   a[1][3] = KECCAK_ROL(a[1][3], 55  % KECCAK_W);
   a[1][4] = KECCAK_ROL(a[1][4], 276 % KECCAK_W);

   a[2][0] = KECCAK_ROL(a[2][0], 3   % KECCAK_W);
   a[2][1] = KECCAK_ROL(a[2][1], 10  % KECCAK_W);
   a[2][2] = KECCAK_ROL(a[2][2], 171 % KECCAK_W);
   a[2][3] = KECCAK_ROL(a[2][3], 153 % KECCAK_W);
   a[2][4] = KECCAK_ROL(a[2][4], 231 % KECCAK_W);

   a[3][0] = KECCAK_ROL(a[3][0], 105 % KECCAK_W);
   a[3][1] = KECCAK_ROL(a[3][1], 45  % KECCAK_W);
   a[3][2] = KECCAK_ROL(a[3][2], 15  % KECCAK_W);
   a[3][3] = KECCAK_ROL(a[3][3], 21  % KECCAK_W);
   a[3][4] = KECCAK_ROL(a[3][4], 136 % KECCAK_W);

   a[4][0] = KECCAK_ROL(a[4][0], 210 % KECCAK_W);
   a[4][1] = KECCAK_ROL(a[4][1], 66  % KECCAK_W);
   a[4][2] = KECCAK_ROL(a[4][2], 253 % KECCAK_W);
   a[4][3] = KECCAK_ROL(a[4][3], 120 % KECCAK_W);
   a[4][4] = KECCAK_ROL(a[4][4], 78  % KECCAK_W);
}


/**
 * @brief Apply pi transformation
 * @param[in,out] a State array
 **/

static void pi(keccak_lane_t a[5][5])
{
   keccak_lane_t temp;

   //The effect of the pi transformation is to rearrange the
   //positions of the lanes
   temp = a[0][1];
   a[0][1] = a[1][1];
   a[1][1] = a[1][4];
   a[1][4] = a[4][2];
   a[4][2] = a[2][4];
   a[2][4] = a[4][0];
   a[4][0] = a[0][2];
   a[0][2] = a[2][2];
   a[2][2] = a[2][3];
   a[2][3] = a[3][4];
   a[3][4] = a[4][3];
   a[4][3] = a[3][0];
   a[3][0] = a[0][4];
   a[0][4] = a[4][4];
   a[4][4] = a[4][1];
   a[4][1] = a[1][3];
   a[1][3] = a[3][1];
   a[3][1] = a[1][0];
   a[1][0] = a[0][3];
   a[0][3] = a[3][3];
   a[3][3] = a[3][2];
   a[3][2] = a[2][1];
   a[2][1] = a[1][2];
   a[1][2] = a[2][0];
   a[2][0] = temp;
}


/**
 * @brief Apply chi transformation
 * @param[in,out] a State array
 **/

static void chi(keccak_lane_t a[5][5])
{
   keccak_lane_t temp1;
   keccak_lane_t temp2;

   //The effect of the chi transformation is to XOR each bit with
   //a non linear function of two other bits in its row
   temp1 = a[0][0];
   temp2 = a[0][1];
   a[0][0] ^= ~a[0][1] & a[0][2];
   a[0][1] ^= ~a[0][2] & a[0][3];
   a[0][2] ^= ~a[0][3] & a[0][4];
   a[0][3] ^= ~a[0][4] & temp1;
   a[0][4] ^= ~temp1 & temp2;

   temp1 = a[1][0];
   temp2 = a[1][1];
   a[1][0] ^= ~a[1][1] & a[1][2];
   a[1][1] ^= ~a[1][2] & a[1][3];
   a[1][2] ^= ~a[1][3] & a[1][4];
   a[1][3] ^= ~a[1][4] & temp1;
   a[1][4] ^= ~temp1 & temp2;

   temp1 = a[2][0];
   temp2 = a[2][1];
   a[2][0] ^= ~a[2][1] & a[2][2];
   a[2][1] ^= ~a[2][2] & a[2][3];
   a[2][2] ^= ~a[2][3] & a[2][4];
   a[2][3] ^= ~a[2][4] & temp1;
   a[2][4] ^= ~temp1 & temp2;

   temp1 = a[3][0];
   temp2 = a[3][1];
   a[3][0] ^= ~a[3][1] & a[3][2];
   a[3][1] ^= ~a[3][2] & a[3][3];
   a[3][2] ^= ~a[3][3] & a[3][4];
   a[3][3] ^= ~a[3][4] & temp1;
   a[3][4] ^= ~temp1 & temp2;

   temp1 = a[4][0];
   temp2 = a[4][1];
   a[4][0] ^= ~a[4][1] & a[4][2];
   a[4][1] ^= ~a[4][2] & a[4][3];
   a[4][2] ^= ~a[4][3] & a[4][4];
   a[4][3] ^= ~a[4][4] & temp1;
   a[4][4] ^= ~temp1 & temp2;
}


/**
 * @brief Apply iota transformation
 * @param[in,out] a State array
 * @param[index] round Round index
 **/

static void iota(keccak_lane_t a[5][5], uint_t index)
{
   //The iota transformation is parameterized by the round index
   a[0][0] ^= rc[index];
}


/**
 * @brief Initialize Keccak context
 * @param[in] context Pointer to the Keccak context to initialize
 * @param[in] capacity Capacity of the sponge function
 **/

error_t keccakInit(KeccakContext *context, uint_t capacity)
{
   uint_t rate;

   //Make sure the Keccak context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear Keccak context
   osMemset(context, 0, sizeof(KeccakContext));

   //The capacity cannot exceed the width of a Keccak-p permutation
   if(capacity >= KECCAK_B)
      return ERROR_INVALID_PARAMETER;

   //The rate depends on the capacity of the sponge function
   rate = KECCAK_B - capacity;

   //The rate must be multiple of the lane size
   if((rate % KECCAK_W) != 0)
      return ERROR_INVALID_PARAMETER;

   //Save the block size, in bytes
   context->blockSize = rate / 8;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the Keccak context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void keccakAbsorb(KeccakContext *context, const void *input, size_t length)
{
   uint_t i;
   size_t n;
   keccak_lane_t *a;

   //Point to the state array
   a = (keccak_lane_t *) context->a;

   //Absorbing phase
   while(length > 0)
   {
      //Limit the number of bytes to process at a time
      n = MIN(length, context->blockSize - context->length);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->length, input, n);

      //Number of data bytes that have been buffered
      context->length += n;

      //Advance the data pointer
      input = (uint8_t *) input + n;
      //Remaining bytes to process
      length -= n;

      //Absorb the message block by block
      if(context->length == context->blockSize)
      {
         //Absorb the current block
         for(i = 0; i < context->blockSize / sizeof(keccak_lane_t); i++)
         {
            a[i] ^= KECCAK_LETOH(context->block[i]);
         }

         //Apply block permutation function
         keccakPermutBlock(context);

         //The input buffer is empty
         context->length = 0;
      }
   }
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the Keccak context
 * @param[in] pad Padding byte used for domain separation
 **/

void keccakFinal(KeccakContext *context, uint8_t pad)
{
   uint_t i;
   size_t q;
   keccak_lane_t *a;

   //Point to the state array
   a = (keccak_lane_t *) context->a;

   //Compute the number of padding bytes
   q = context->blockSize - context->length;

   //Append padding
   osMemset(context->buffer + context->length, 0, q);
   context->buffer[context->length] |= pad;
   context->buffer[context->blockSize - 1] |= 0x80;

   //Absorb the final block
   for(i = 0; i < context->blockSize / sizeof(keccak_lane_t); i++)
   {
      a[i] ^= KECCAK_LETOH(context->block[i]);
   }

   //Apply block permutation function
   keccakPermutBlock(context);

   //Convert lanes to little-endian byte order
   for(i = 0; i < context->blockSize / sizeof(keccak_lane_t); i++)
   {
      a[i] = KECCAK_HTOLE(a[i]);
   }

   //Number of bytes available in the output buffer
   context->length = context->blockSize;
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the Keccak context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void keccakSqueeze(KeccakContext *context, uint8_t *output, size_t length)
{
   uint_t i;
   size_t n;
   keccak_lane_t *a;

   //Point to the state array
   a = (keccak_lane_t *) context->a;

   //An arbitrary number of output bits can be squeezed out of the state
   while(length > 0)
   {
      //Check whether more data is required
      if(context->length == 0)
      {
         //Convert lanes to host byte order
         for(i = 0; i < context->blockSize / sizeof(keccak_lane_t); i++)
         {
            a[i] = KECCAK_LETOH(a[i]);
         }

         //Apply block permutation function
         keccakPermutBlock(context);

         //Convert lanes to little-endian byte order
         for(i = 0; i < context->blockSize / sizeof(keccak_lane_t); i++)
         {
            a[i] = KECCAK_HTOLE(a[i]);
         }

         //Number of bytes available in the output buffer
         context->length = context->blockSize;
      }

      //Compute the number of bytes to process at a time
      n = MIN(length, context->length);

      //Copy the output string
      if(output != NULL)
      {
         osMemcpy(output, context->digest + context->blockSize -
            context->length, n);
      }

      //Number of bytes available in the output buffer
      context->length -= n;

      //Advance the data pointer
      output = (uint8_t *) output + n;
      //Number of bytes that remains to be written
      length -= n;
   }
}


/**
 * @brief Block permutation
 * @param[in] context Pointer to the Keccak context
 **/

void keccakPermutBlock(KeccakContext *context)
{
   uint_t i;

   //Each round consists of a sequence of five transformations,
   //which are called the step mappings
   for(i = 0; i < KECCAK_NR; i++)
   {
      //Apply theta step mapping
      theta(context->a);
      //Apply rho step mapping
      rho(context->a);
      //Apply pi step mapping
      pi(context->a);
      //Apply chi step mapping
      chi(context->a);
      //Apply iota step mapping
      iota(context->a, i);
   }
}

#endif
