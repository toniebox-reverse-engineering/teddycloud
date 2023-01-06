/**
 * @file curve448.c
 * @brief Curve448 elliptic curve (constant-time implementation)
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
#include "ecc/curve448.h"
#include "debug.h"

//Check crypto library configuration
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)


/**
 * @brief Set integer value
 * @param[out] a Pointer to the integer to be initialized
 * @param[in] b Initial value
 **/

void curve448SetInt(uint32_t *a, uint32_t b)
{
   uint_t i;

   //Set the value of the least significant word
   a[0] = b;

   //Initialize the rest of the integer
   for(i = 1; i < 14; i++)
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

void curve448Add(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < 14; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform modular reduction
   curve448Red(r, r, (uint32_t) temp);
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve448AddInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = b, i = 0; i < 14; i++)
   {
      temp += a[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform modular reduction
   curve448Red(r, r, (uint32_t) temp);
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Sub(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   int64_t temp;

   //Compute R = A + (2^448 - 2^224 - 1) - B
   for(temp = -1, i = 0; i < 7; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp -= 1, i = 7; i < 14; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute the highest term of the result
   temp += 1;

   //Perform modular reduction
   curve448Red(r, r, (uint32_t) temp);
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve448SubInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   uint_t i;
   int64_t temp;

   //Set initial value
   temp = -1;
   temp -= b;

   //Compute R = A + (2^448 - 2^224 - 1) - B
   for(i = 0; i < 7; i++)
   {
      temp += a[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp -= 1, i = 7; i < 14; i++)
   {
      temp += a[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute the highest term of the result
   temp += 1;

   //Perform modular reduction
   curve448Red(r, r, (uint32_t) temp);
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint_t j;
   uint64_t c;
   uint64_t temp;
   uint32_t u[28];

   //Initialize variables
   temp = 0;
   c = 0;

   //Comba's method is used to perform multiplication
   for(i = 0; i < 28; i++)
   {
      //The algorithm computes the products, column by column
      if(i < 14)
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
         for(j = i - 13; j < 14; j++)
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

   //Perform fast modular reduction (first pass)
   for(temp = 0, i = 0; i < 7; i++)
   {
      temp += u[i];
      temp += u[i + 14];
      temp += u[i + 21];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(i = 7; i < 14; i++)
   {
      temp += u[i];
      temp += u[i + 7];
      temp += u[i + 14];
      temp += u[i + 14];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform fast modular reduction (second pass)
   for(c = temp, i = 0; i < 7; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp += c, i = 7; i < 14; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve448Red(r, u, (uint32_t) temp);
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve448MulInt(uint32_t *r, const uint32_t *a, uint32_t b)
{
   int_t i;
   uint64_t c;
   uint64_t temp;
   uint32_t u[14];

   //Compute R = A * B
   for(temp = 0, i = 0; i < 14; i++)
   {
      temp += (uint64_t) a[i] * b;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform fast modular reduction
   for(c = temp, i = 0; i < 7; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp += c, i = 7; i < 14; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve448Red(r, u, (uint32_t) temp);
}


/**
 * @brief Modular squaring
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve448Sqr(uint32_t *r, const uint32_t *a)
{
   //Compute R = (A ^ 2) mod p
   curve448Mul(r, a, a);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] n An integer such as n >= 1
 **/

void curve448Pwr2(uint32_t *r, const uint32_t *a, uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod p
   curve448Sqr(r, a);

   //Compute R = (A ^ (2^n)) mod p
   for(i = 1; i < n; i++)
   {
      curve448Sqr(r, r);
   }
}


/**
 * @brief Modular reduction
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < (2 * p)
 * @param[in] h The highest term of A
 **/

void curve448Red(uint32_t *r, const uint32_t *a, uint32_t h)
{
   uint_t i;
   uint64_t temp;
   uint32_t b[14];

   //Compute B = A - (2^448 - 2^224 - 1)
   for(temp = 1, i = 0; i < 7; i++)
   {
      temp += a[i];
      b[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp += 1, i = 7; i < 14; i++)
   {
      temp += a[i];
      b[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Compute the highest term of the result
   h += (uint32_t) temp - 1;

   //If B < (2^448 - 2^224 + 1) then R = B, else R = A
   curve448Select(r, b, a, h & 1);
}


/**
 * @brief Modular multiplicative inverse
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve448Inv(uint32_t *r, const uint32_t *a)
{
   uint32_t u[14];
   uint32_t v[14];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   curve448Sqr(u, a);
   curve448Mul(u, u, a); //A^(2^2 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^3 - 1)
   curve448Pwr2(u, v, 3);
   curve448Mul(v, u, v); //A^(2^6 - 1)
   curve448Pwr2(u, v, 6);
   curve448Mul(u, u, v); //A^(2^12 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^13 - 1)
   curve448Pwr2(u, v, 13);
   curve448Mul(u, u, v); //A^(2^26 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^27 - 1)
   curve448Pwr2(u, v, 27);
   curve448Mul(u, u, v); //A^(2^54 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^55 - 1)
   curve448Pwr2(u, v, 55);
   curve448Mul(u, u, v); //A^(2^110 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^111 - 1)
   curve448Pwr2(u, v, 111);
   curve448Mul(v, u, v); //A^(2^222 - 1)
   curve448Sqr(u, v);
   curve448Mul(u, u, a); //A^(2^223 - 1)
   curve448Pwr2(u, u, 223);
   curve448Mul(u, u, v); //A^(2^446 - 2^222 - 1)
   curve448Sqr(u, u);
   curve448Sqr(u, u);
   curve448Mul(r, u, a); //A^(2^448 - 2^224 - 3)
}


/**
 * @brief Compute the square root of (A / B) modulo p
 * @param[out] r Resulting integer R = (A / B)^(1 / 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 < B < p
 * @return The function returns 0 if the square root exists, else 1
 **/

uint32_t curve448Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint32_t res;
   uint32_t c[14];
   uint32_t u[14];
   uint32_t v[14];

   //Compute the candidate root (A / B)^((p + 1) / 4). This can be done
   //with the following trick, using a single modular powering for both the
   //inversion of B and the square root: A^3 * B * (A^5 * B^3)^((p - 3) / 4)
   curve448Sqr(u, a);
   curve448Sqr(u, u);
   curve448Mul(u, u, a);
   curve448Sqr(v, b);
   curve448Mul(v, v, b);

   //Compute C = A^5 * B^3
   curve448Mul(c, u, v);

   //Compute U = C^((p - 3) / 4)
   curve448Sqr(u, c);
   curve448Mul(u, u, c); //C^(2^2 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^3 - 1)
   curve448Pwr2(u, v, 3);
   curve448Mul(v, u, v); //C^(2^6 - 1)
   curve448Pwr2(u, v, 6);
   curve448Mul(u, u, v); //C^(2^12 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^13 - 1)
   curve448Pwr2(u, v, 13);
   curve448Mul(u, u, v); //C^(2^26 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^27 - 1)
   curve448Pwr2(u, v, 27);
   curve448Mul(u, u, v); //C^(2^54 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^55 - 1)
   curve448Pwr2(u, v, 55);
   curve448Mul(u, u, v); //C^(2^110 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^111 - 1)
   curve448Pwr2(u, v, 111);
   curve448Mul(v, u, v); //C^(2^222 - 1)
   curve448Sqr(u, v);
   curve448Mul(u, u, c); //C^(2^223 - 1)
   curve448Pwr2(u, u, 223);
   curve448Mul(u, u, v); //C^(2^446 - 2^222 - 1)

   //The candidate root is U = A^3 * B * (A^5 * B^3)^((p - 3) / 4)
   curve448Sqr(v, a);
   curve448Mul(v, v, a);
   curve448Mul(u, u, v);
   curve448Mul(u, u, b);

   //Calculate C = B * U^2
   curve448Sqr(c, u);
   curve448Mul(c, c, b);

   //Check whether B * U^2 = A
   res = curve448Comp(c, a);

   //Copy the candidate root
   curve448Copy(r, u);

   //Return 0 if the square root exists
   return res;
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 **/

void curve448Copy(uint32_t *a, const uint32_t *b)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < 14; i++)
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

void curve448Swap(uint32_t *a, uint32_t *b, uint32_t c)
{
   uint_t i;
   uint32_t mask;
   uint32_t dummy;

   //The mask is the all-1 or all-0 word
   mask = ~c + 1;

   //Conditional swap
   for(i = 0; i < 14; i++)
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

void curve448Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c)
{
   uint_t i;
   uint32_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < 14; i++)
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

uint32_t curve448Comp(const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < 14; i++)
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

void curve448Import(uint32_t *a, const uint8_t *data)
{
   uint_t i;

   //Import the octet string
   osMemcpy(a, data, 56);

   //Convert from little-endian byte order to host byte order
   for(i = 0; i < 14; i++)
   {
      a[i] = letoh32(a[i]);
   }
}


/**
 * @brief Export an octet string
 * @param[in] a Pointer to the integer to be exported
 * @param[out] data Octet string resulting from the conversion
 **/

void curve448Export(uint32_t *a, uint8_t *data)
{
   uint_t i;

   //Convert from host byte order to little-endian byte order
   for(i = 0; i < 14; i++)
   {
      a[i] = htole32(a[i]);
   }

   //Export the octet string
   osMemcpy(data, a, 56);
}

#endif
