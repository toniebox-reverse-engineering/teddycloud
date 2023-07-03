/**
 * @file md5.h
 * @brief MD5 (Message-Digest Algorithm)
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

#ifndef _MD5_H
#define _MD5_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef MD5_PRIVATE_CONTEXT
   #define MD5_PRIVATE_CONTEXT
#endif

//MD5 block size
#define MD5_BLOCK_SIZE 64
//MD5 digest size
#define MD5_DIGEST_SIZE 16
//Minimum length of the padding string
#define MD5_MIN_PAD_SIZE 9
//MD5 algorithm object identifier
#define MD5_OID md5Oid
//Common interface for hash algorithms
#define MD5_HASH_ALGO (&md5HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MD5 algorithm context
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
   MD5_PRIVATE_CONTEXT
} Md5Context;


//MD5 related constants
extern const uint8_t md5Oid[8];
extern const HashAlgo md5HashAlgo;

//MD5 related functions
error_t md5Compute(const void *data, size_t length, uint8_t *digest);
void md5Init(Md5Context *context);
void md5Update(Md5Context *context, const void *data, size_t length);
void md5Final(Md5Context *context, uint8_t *digest);
void md5FinalRaw(Md5Context *context, uint8_t *digest);
void md5ProcessBlock(Md5Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
