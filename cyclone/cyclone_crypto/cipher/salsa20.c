/**
 * @file salsa20.c
 * @brief Salsa20 encryption algorithm
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
#include "cipher/salsa20.h"

//Check crypto library configuration
#if (SALSA20_SUPPORT == ENABLED)

//Salsa20 quarter-round function
#define QUARTER_ROUND(a, b, c, d) \
{ \
   b ^= ROL32(a + d, 7); \
   c ^= ROL32(b + a, 9); \
   d ^= ROL32(c + b, 13); \
   a ^= ROL32(d + c, 18); \
}


/**
 * @brief Salsa20 core function
 * @param[in] input Pointer to the 64-octet input block
 * @param[out] output Pointer to the 64-octet output block
 * @param[in] nr Number of rounds to be applied (8, 12 or 20)
 **/

void salsa20ProcessBlock(const uint8_t *input, uint8_t *output, uint_t nr)
{
   uint_t i;
   uint32_t x[16];

   //Copy the input words to the working state
   for(i = 0; i < 16; i++)
   {
      x[i] = LOAD32LE(input + i * 4);
   }

   //The Salsa20 core function alternates between column rounds and row rounds
   for(i = 0; i < nr; i += 2)
   {
      //The column round function modifies the columns of the matrix in parallel
      //by feeding a permutation of each column through the quarter round function
      QUARTER_ROUND(x[0], x[4], x[8], x[12]);
      QUARTER_ROUND(x[5], x[9], x[13], x[1]);
      QUARTER_ROUND(x[10], x[14], x[2], x[6]);
      QUARTER_ROUND(x[15], x[3], x[7], x[11]);

      //The row round function modifies the rows of the matrix in parallel by
      //feeding a permutation of each row through the quarter round function
      QUARTER_ROUND(x[0], x[1], x[2], x[3]);
      QUARTER_ROUND(x[5], x[6], x[7], x[4]);
      QUARTER_ROUND(x[10], x[11], x[8], x[9]);
      QUARTER_ROUND(x[15], x[12], x[13], x[14]);
   }

   //Add the original input words to the output words
   for(i = 0; i < 16; i++)
   {
      x[i] += LOAD32LE(input + i * 4);
      STORE32LE(x[i], output + i * 4);
   }
}

#endif
