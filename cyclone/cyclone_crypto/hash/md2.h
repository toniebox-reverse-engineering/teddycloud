/**
 * @file md2.h
 * @brief MD2 (Message-Digest Algorithm)
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

#ifndef _MD2_H
#define _MD2_H

//Dependencies
#include "core/crypto.h"

//MD2 block size
#define MD2_BLOCK_SIZE 16
//MD2 digest size
#define MD2_DIGEST_SIZE 16
//Minimum length of the padding string
#define MD2_MIN_PAD_SIZE 1
//MD2 algorithm object identifier
#define MD2_OID md2Oid
//Common interface for hash algorithms
#define MD2_HASH_ALGO (&md2HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MD2 algorithm context
 **/

typedef struct
{

   union
   {
      uint8_t x[48];
      uint8_t digest[16];
   };
   uint8_t m[16];
   uint8_t c[16];
   size_t size;
} Md2Context;


//MD2 related constants
extern const uint8_t md2Oid[8];
extern const HashAlgo md2HashAlgo;

//MD2 related functions
error_t md2Compute(const void *data, size_t length, uint8_t *digest);
void md2Init(Md2Context *context);
void md2Update(Md2Context *context, const void *data, size_t length);
void md2Final(Md2Context *context, uint8_t *digest);
void md2ProcessBlock(const uint8_t *m, uint8_t *x, uint8_t *c);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
