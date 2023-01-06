/**
 * @file x25519.c
 * @brief X25519 function implementation
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
#include "ecc/ec_curves.h"
#include "ecc/curve25519.h"
#include "ecc/x25519.h"
#include "debug.h"

//Check crypto library configuration
#if (X25519_SUPPORT == ENABLED)


/**
 * @brief X25519 function (scalar multiplication on Curve25519)
 * @param[out] r Output u-coordinate
 * @param[in] k Input scalar
 * @param[in] u Input u-coordinate
 * @return Error code
 **/

error_t x25519(uint8_t *r, const uint8_t *k, const uint8_t *u)
{
   int_t i;
   uint32_t b;
   uint32_t swap;
   X25519State *state;

   //Check parameters
   if(r == NULL || k == NULL || u == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(X25519State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy scalar
   curve25519Import(state->k, k);

   //Set the three least significant bits of the first byte and the most
   //significant bit of the last to zero, set the second most significant
   //bit of the last byte to 1
   state->k[0] &= 0xFFFFFFF8;
   state->k[7] &= 0x7FFFFFFF;
   state->k[7] |= 0x40000000;

   //Copy input u-coordinate
   curve25519Import(state->u, u);

   //Implementations must mask the most significant bit in the final byte
   state->u[7] &= 0x7FFFFFFF;

   //Implementations must accept non-canonical values and process them as
   //if they had been reduced modulo the field prime (refer to RFC 7748,
   //section 5)
   curve25519Red(state->u, state->u);

   //Set X1 = 1
   curve25519SetInt(state->x1, 1);
   //Set Z1 = 0
   curve25519SetInt(state->z1, 0);
   //Set X2 = U
   curve25519Copy(state->x2, state->u);
   //Set Z2 = 1
   curve25519SetInt(state->z2, 1);

   //Set swap = 0
   swap = 0;

   //Montgomery ladder
   for(i = CURVE25519_BIT_LEN - 1; i >= 0; i--)
   {
      //The scalar is processed in a left-to-right fashion
      b = (state->k[i / 32] >> (i % 32)) & 1;

      //Conditional swap
      curve25519Swap(state->x1, state->x2, swap ^ b);
      curve25519Swap(state->z1, state->z2, swap ^ b);

      //Save current bit value
      swap = b;

      //Compute T1 = X2 + Z2
      curve25519Add(state->t1, state->x2, state->z2);
      //Compute X2 = X2 - Z2
      curve25519Sub(state->x2, state->x2, state->z2);
      //Compute Z2 = X1 + Z1
      curve25519Add(state->z2, state->x1, state->z1);
      //Compute X1 = X1 - Z1
      curve25519Sub(state->x1, state->x1, state->z1);
      //Compute T1 = T1 * X1
      curve25519Mul(state->t1, state->t1, state->x1);
      //Compute X2 = X2 * Z2
      curve25519Mul(state->x2, state->x2, state->z2);
      //Compute Z2 = Z2 * Z2
      curve25519Sqr(state->z2, state->z2);
      //Compute X1 = X1 * X1
      curve25519Sqr(state->x1, state->x1);
      //Compute T2 = Z2 - X1
      curve25519Sub(state->t2, state->z2, state->x1);
      //Compute Z1 = T2 * a24
      curve25519MulInt(state->z1, state->t2, CURVE25519_A24);
      //Compute Z1 = Z1 + X1
      curve25519Add(state->z1, state->z1, state->x1);
      //Compute Z1 = Z1 * T2
      curve25519Mul(state->z1, state->z1, state->t2);
      //Compute X1 = X1 * Z2
      curve25519Mul(state->x1, state->x1, state->z2);
      //Compute Z2 = T1 - X2
      curve25519Sub(state->z2, state->t1, state->x2);
      //Compute Z2 = Z2 * Z2
      curve25519Sqr(state->z2, state->z2);
      //Compute Z2 = Z2 * U
      curve25519Mul(state->z2, state->z2, state->u);
      //Compute X2 = X2 + T1
      curve25519Add(state->x2, state->x2, state->t1);
      //Compute X2 = X2 * X2
      curve25519Sqr(state->x2, state->x2);
   }

   //Conditional swap
   curve25519Swap(state->x1, state->x2, swap);
   curve25519Swap(state->z1, state->z2, swap);

   //Retrieve affine representation
   curve25519Inv(state->u, state->z1);
   curve25519Mul(state->u, state->u, state->x1);

   //Copy output u-coordinate
   curve25519Export(state->u, r);

   //Erase working state
   osMemset(state, 0, sizeof(X25519State));
   //Release working state
   cryptoFreeMem(state);

   //Successful processing
   return NO_ERROR;
}

#endif
