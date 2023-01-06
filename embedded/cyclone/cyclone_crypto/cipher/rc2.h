/**
 * @file rc2.h
 * @brief RC2 block cipher
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

#ifndef _RC2_H
#define _RC2_H

//Dependencies
#include "core/crypto.h"

//RC2 block size
#define RC2_BLOCK_SIZE 8
//Common interface for encryption algorithms
#define RC2_CIPHER_ALGO (&rc2CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RC2 algorithm context
 **/

typedef struct
{
   union
   {
      uint16_t k[64];
      uint8_t l[128];
   };
} Rc2Context;


//RC2 related constants
extern const CipherAlgo rc2CipherAlgo;

//RC2 related functions
error_t rc2Init(Rc2Context *context, const uint8_t *key, size_t keyLen);

error_t rc2InitEx(Rc2Context *context, const uint8_t *key, size_t keyLen,
   uint_t effectiveKeyLen);

void rc2EncryptBlock(Rc2Context *context, const uint8_t *input,
   uint8_t *output);

void rc2DecryptBlock(Rc2Context *context, const uint8_t *input,
   uint8_t *output);

void rc2Deinit(Rc2Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
