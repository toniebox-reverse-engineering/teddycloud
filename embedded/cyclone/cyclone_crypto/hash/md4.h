/**
 * @file md4.h
 * @brief MD4 (Message-Digest Algorithm)
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

#ifndef _MD4_H
#define _MD4_H

//Dependencies
#include "core/crypto.h"

//MD4 block size
#define MD4_BLOCK_SIZE 64
//MD4 digest size
#define MD4_DIGEST_SIZE 16
//Minimum length of the padding string
#define MD4_MIN_PAD_SIZE 9
//MD4 algorithm object identifier
#define MD4_OID md4Oid
//Common interface for hash algorithms
#define MD4_HASH_ALGO (&md4HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MD4 algorithm context
 **/

typedef struct
{
   union
   {
      uint32_t h[4];
      uint8_t digest[16];
   };
   union
   {
      uint32_t x[16];
      uint8_t buffer[64];
   };
   size_t size;
   uint64_t totalSize;
} Md4Context;


//MD4 related constants
extern const uint8_t md4Oid[8];
extern const HashAlgo md4HashAlgo;

//MD4 related functions
error_t md4Compute(const void *data, size_t length, uint8_t *digest);
void md4Init(Md4Context *context);
void md4Update(Md4Context *context, const void *data, size_t length);
void md4Final(Md4Context *context, uint8_t *digest);
void md4ProcessBlock(Md4Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
