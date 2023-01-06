/**
 * @file blake2b.h
 * @brief BLAKE2 cryptographic hash and MAC (BLAKE2b variant)
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

#ifndef _BLAKE2B_H
#define _BLAKE2B_H

//Dependencies
#include "core/crypto.h"

//BLAKE2b block size
#define BLAKE2B_BLOCK_SIZE 128

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BLAKE2b algorithm context
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
      uint64_t m[16];
      uint8_t buffer[128];
   };
   size_t size;
   uint64_t totalSize[2];
   size_t digestSize;
} Blake2bContext;


//BLAKE2b related functions
error_t blake2bCompute(const void *key, size_t keyLen, const void *data,
   size_t dataLen, uint8_t *digest, size_t digestLen);

error_t blake2bInit(Blake2bContext *context, const void *key,
   size_t keyLen, size_t digestLen);

void blake2bUpdate(Blake2bContext *context, const void *data, size_t length);
void blake2bFinal(Blake2bContext *context, uint8_t *digest);
void blake2bProcessBlock(Blake2bContext *context, bool_t last);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
