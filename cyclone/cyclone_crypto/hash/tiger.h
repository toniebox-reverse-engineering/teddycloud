/**
 * @file tiger.h
 * @brief Tiger hash function
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

#ifndef _TIGER_H
#define _TIGER_H

//Dependencies
#include "core/crypto.h"

//Tiger block size
#define TIGER_BLOCK_SIZE 64
//Tiger digest size
#define TIGER_DIGEST_SIZE 24
//Minimum length of the padding string
#define TIGER_MIN_PAD_SIZE 9
//Tiger algorithm object identifier
#define TIGER_OID tigerOid
//Common interface for hash algorithms
#define TIGER_HASH_ALGO (&tigerHashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Tiger algorithm context
 **/

typedef struct
{
   union
   {
      uint64_t h[3];
      uint8_t digest[24];
   };
   union
   {
      uint64_t x[8];
      uint8_t buffer[64];
   };
   size_t size;
   uint64_t totalSize;
} TigerContext;


//Tiger related constants
extern const uint8_t tigerOid[9];
extern const HashAlgo tigerHashAlgo;

//Tiger related functions
error_t tigerCompute(const void *data, size_t length, uint8_t *digest);
void tigerInit(TigerContext *context);
void tigerUpdate(TigerContext *context, const void *data, size_t length);
void tigerFinal(TigerContext *context, uint8_t *digest);
void tigerProcessBlock(TigerContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
