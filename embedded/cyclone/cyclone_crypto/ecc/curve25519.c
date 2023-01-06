/**
 * @file curve25519.c
 * @brief Curve25519 elliptic curve (constant-time implementation)
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
#include "debug.h"

//Check crypto library configuration
#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

//Square root of -1 modulo p (constant)
static const uint32_t CURVE25519_SQRT_MINUS_1[8] =
{
   0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806,
   0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480
};


/**
 * @brief Set integer value
 * @param[out] a Pointer to the integer to be initialized
 * @param[in] b Initial value
 **/

void curve25519SetInt(uint32_t *a, uint32_t b)
{
   uint_t i;

   //Set the value of the least significant word
   a[0] = b;

   //Initialize the rest of the integer
   for(i = 1; i < 8; i++)
   {
      a[i] = 0;
   }
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Add(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform modular reduction
   curve25519Red(r, r);
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve25519AddInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = b, i = 0; i < 8; i++)
   {
      temp += a[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform modular reduction
   curve25519Red(r, r);
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Sub(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   int64_t temp;

   //Compute R = A - 19 - B
   for(temp = -19, i = 0; i < 8; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute R = A + (2^255 - 19) - B
   r[7] += 0x80000000;

   //Perform modular reduction
   curve25519Red(r, r);
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve25519SubInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   uint_t i;
   int64_t temp;

   //Set initial value
   temp = -19;
   temp -= b;

   //Compute R = A - 19 - B
   for(i = 0; i < 8; i++)
   {
      temp += a[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute R = A + (2^255 - 19) - B
   r[7] += 0x80000000;

   //Perform modular reduction
   curve25519Red(r, r);
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint_t j;
   uint64_t c;
   uint64_t temp;
   uint32_t u[16];

   //Initialize variables
   temp = 0;
   c = 0;

   //Comba's method is used to perform multiplication
   for(i = 0; i < 16; i++)
   {
      //The algorithm computes the products, column by column
      if(i < 8)
      {
         //Inner loop
         for(j = 0; j <= i; j++)
         {
            temp += (uint64_t) a[j] * b[i - j];
            c += temp >> 32;
            temp &= 0xFFFFFFFF;
         }
      }
      else
      {
         //Inner loop
         for(j = i - 7; j < 8; j++)
         {
            temp += (uint64_t) a[j] * b[i - j];
            c += temp >> 32;
            temp &= 0xFFFFFFFF;
         }
      }

      //At the bottom of each column, the final result is written to memory
      u[i] = temp & 0xFFFFFFFF;

      //Propagate the carry upwards
      temp = c & 0xFFFFFFFF;
      c >>= 32;
   }

   //Reduce bit 255 (2^255 = 19 mod p)
   temp = (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (first pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      temp += (uint64_t) u[i + 8] * 38;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce bit 256 (2^256 = 38 mod p)
   temp *= 38;
   //Reduce bit 255 (2^255 = 19 mod p)
   temp += (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (second pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve25519Red(r, u);
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve25519MulInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   int_t i;
   uint64_t temp;
   uint32_t u[8];

   //Compute R = A * B
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += (uint64_t) a[i] * b;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce bit 256 (2^256 = 38 mod p)
   temp *= 38;
   //Reduce bit 255 (2^255 = 19 mod p)
   temp += (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve25519Red(r, u);
}


/**
 * @brief Modular squaring
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

__weak_func void curve25519Sqr(uint32_t *r, const uint32_t *a)
{
   //Compute R = (A ^ 2) mod p
   curve25519Mul(r, a, a);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] n An integer such as n >= 1
 **/

void curve25519Pwr2(uint32_t *r, const uint32_t *a, uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod p
   curve25519Sqr(r, a);

   //Compute R = (A ^ (2^n)) mod p
   for(i = 1; i < n; i++)
   {
      curve25519Sqr(r, r);
   }
}


/**
 * @brief Modular reduction
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < (2 * p)
 **/

void curve25519Red(uint32_t *r, const uint32_t *a)
{
   uint_t i;
   uint64_t temp;
   uint32_t b[8];

   //Compute B = A + 19
   for(temp = 19, i = 0; i < 8; i++)
   {
      temp += a[i];
      b[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute B = A - (2^255 - 19)
   b[7] -= 0x80000000;

   //If B < (2^255 - 19) then R = B, else R = A
   curve25519Select(r, b, a, (b[7] & 0x80000000) >> 31);
}


/**
 * @brief Modular multiplicative inverse
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve25519Inv(uint32_t *r, const uint32_t *a)
{
   uint32_t u[8];
   uint32_t v[8];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   curve25519Sqr(u, a);
   curve25519Mul(u, u, a); //A^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); //A^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); //A^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); //A^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); //A^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); //A^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); //A^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a);
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a);
   curve25519Sqr(u, u);
   curve25519Mul(r, u, a); //A^(2^255 - 21)
}


/**
 * @brief Compute the square root of (A / B) modulo p
 * @param[out] r Resulting integer R = (A / B)^(1 / 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 < B < p
 * @return The function returns 0 if the square root exists, else 1
 **/

uint32_t curve25519Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint32_t res1;
   uint32_t res2;
   uint32_t c[8];
   uint32_t u[8];
   uint32_t v[8];

   //Compute the candidate root (A / B)^((p + 3) / 8). This can be done
   //with the following trick, using a single modular powering for both the
   //inversion of B and the square root: A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Sqr(v, v);
   curve25519Mul(v, v, b);

   //Compute C = A * B^7
   curve25519Mul(c, a, v);

   //Compute U = C^((p - 5) / 8)
   curve25519Sqr(u, c);
   curve25519Mul(u, u, c); //C^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); //C^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); //C^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); //C^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); //C^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); //C^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); //C^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, c); //C^(2^252 - 3)

   //The first candidate root is U = A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Mul(u, u, a);
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Mul(u, u, v);

   //The second candidate root is V = U * sqrt(-1)
   curve25519Mul(v, u, CURVE25519_SQRT_MINUS_1);

   //Calculate C = B * U^2
   curve25519Sqr(c, u);
   curve25519Mul(c, c, b);

   //Check whether B * U^2 = A
   res1 = curve25519Comp(c, a);

   //Calculate C = B * V^2
   curve25519Sqr(c, v);
   curve25519Mul(c, c, b);

   //Check whether B * V^2 = A
   res2 = curve25519Comp(c, a);

   //Select the first or the second candidate root
   curve25519Select(r, u, v, res1);

   //Return 0 if the square root exists
   return res1 & res2;
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 **/

void curve25519Copy(uint32_t *a, const uint32_t *b)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < 8; i++)
   {
      a[i] = b[i];
   }
}


/**
 * @brief Conditional swap
 * @param[in,out] a Pointer to the first integer
 * @param[in,out] b Pointer to the second integer
 * @param[in] c Condition variable
 **/

void curve25519Swap(uint32_t *a, uint32_t *b, uint32_t c)
{
   uint_t i;
   uint32_t mask;
   uint32_t dummy;

   //The mask is the all-1 or all-0 word
   mask = ~c + 1;

   //Conditional swap
   for(i = 0; i < 8; i++)
   {
      //Constant time implementation
      dummy = mask & (a[i] ^ b[i]);
      a[i] ^= dummy;
      b[i] ^= dummy;
   }
}


/**
 * @brief Select an integer
 * @param[out] r Pointer to the destination integer
 * @param[in] a Pointer to the first source integer
 * @param[in] b Pointer to the second source integer
 * @param[in] c Condition variable
 **/

void curve25519Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c)
{
   uint_t i;
   uint32_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < 8; i++)
   {
      //Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}


/**
 * @brief Compare integers
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @return The function returns 0 if the A = B, else 1
 **/

uint32_t curve25519Comp(const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < 8; i++)
   {
      //Constant time implementation
      mask |= a[i] ^ b[i];
   }

   //Return 0 if A = B, else 1
   return ((uint32_t) (mask | (~mask + 1))) >> 31;
}


/**
 * @brief Import an octet string
 * @param[out] a Pointer to resulting integer
 * @param[in] data Octet string to be converted
 **/

void curve25519Import(uint32_t *a, const uint8_t *data)
{
   uint_t i;

   //Import the octet string
   osMemcpy(a, data, 32);

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 8; i++)
   {
      a[i] = letoh32(a[i]);
   }
}


/**
 * @brief Export an octet string
 * @param[in] a Pointer to the integer to be exported
 * @param[out] data Octet string resulting from the conversion
 **/

void curve25519Export(uint32_t *a, uint8_t *data)
{
   uint_t i;

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 8; i++)
   {
      a[i] = htole32(a[i]);
   }

   //Export the octet string
   osMemcpy(data, a, 32);
}

#endif
