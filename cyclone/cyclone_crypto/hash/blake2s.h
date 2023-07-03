/**
 * @file blake2s.h
 * @brief BLAKE2 cryptographic hash and MAC (BLAKE2s variant)
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

#ifndef _BLAKE2S_H
#define _BLAKE2S_H

//Dependencies
#include "core/crypto.h"

//BLAKE2s block size
#define BLAKE2S_BLOCK_SIZE 64

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BLAKE2s algorithm context
 **/

typedef struct
{
   union
   {
      uint32_t h[8];
      uint8_t digest[32];
   };
   union
   {
      uint32_t m[16];
      uint8_t buffer[64];
   };
   size_t size;
   uint32_t totalSize[2];
   size_t digestSize;
} Blake2sContext;


//BLAKE2s related functions
error_t blake2sCompute(const void *key, size_t keyLen, const void *data,
   size_t dataLen, uint8_t *digest, size_t digestLen);

error_t blake2sInit(Blake2sContext *context, const void *key,
   size_t keyLen, size_t digestLen);

void blake2sUpdate(Blake2sContext *context, const void *data, size_t length);
void blake2sFinal(Blake2sContext *context, uint8_t *digest);
void blake2sProcessBlock(Blake2sContext *context, bool_t last);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
