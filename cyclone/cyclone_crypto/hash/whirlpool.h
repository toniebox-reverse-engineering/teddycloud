/**
 * @file whirlpool.h
 * @brief Whirlpool hash function
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

#ifndef _WHIRLPOOL_H
#define _WHIRLPOOL_H

//Dependencies
#include "core/crypto.h"

//Whirlpool block size
#define WHIRLPOOL_BLOCK_SIZE 64
//Whirlpool digest size
#define WHIRLPOOL_DIGEST_SIZE 64
//Minimum length of the padding string
#define WHIRLPOOL_MIN_PAD_SIZE 33
//Whirlpool algorithm object identifier
#define WHIRLPOOL_OID whirlpoolOid
//Common interface for hash algorithms
#define WHIRLPOOL_HASH_ALGO (&whirlpoolHashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Whirlpool algorithm context
 **/

typedef struct
{
   union
   {
      uint64_t h[8];
      uint8_t digest[64];
   };
   union
   {
      uint64_t x[8];
      uint8_t buffer[64];
   };

   uint64_t k[8];
   uint64_t l[8];
   uint64_t state[8];

   size_t size;
   uint64_t totalSize;
} WhirlpoolContext;


//Whirlpool related constants
extern const uint8_t whirlpoolOid[6];
extern const HashAlgo whirlpoolHashAlgo;

//Whirlpool related functions
error_t whirlpoolCompute(const void *data, size_t length, uint8_t *digest);
void whirlpoolInit(WhirlpoolContext *context);
void whirlpoolUpdate(WhirlpoolContext *context, const void *data, size_t length);
void whirlpoolFinal(WhirlpoolContext *context, uint8_t *digest);
void whirlpoolProcessBlock(WhirlpoolContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
