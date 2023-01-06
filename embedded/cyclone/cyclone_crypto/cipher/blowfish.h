/**
 * @file blowfish.h
 * @brief Blowfish encryption algorithm
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

#ifndef _BLOWFISH_H
#define _BLOWFISH_H

//Dependencies
#include "core/crypto.h"

//Blowfish block size
#define BLOWFISH_BLOCK_SIZE 8
//Common interface for encryption algorithms
#define BLOWFISH_CIPHER_ALGO (&blowfishCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Blowfish algorithm context
 **/

typedef struct
{
   uint32_t p[18];
   uint32_t s1[256];
   uint32_t s2[256];
   uint32_t s3[256];
   uint32_t s4[256];
} BlowfishContext;


//Blowfish related constants
extern const CipherAlgo blowfishCipherAlgo;

//Blowfish related functions
error_t blowfishInit(BlowfishContext *context, const uint8_t *key,
   size_t keyLen);

error_t blowfishInitState(BlowfishContext *context);

error_t blowfishExpandKey(BlowfishContext *context, const uint8_t *salt,
   size_t saltLen, const uint8_t *key, size_t keyLen);

void blowfishEncryptBlock(BlowfishContext *context, const uint8_t *input,
   uint8_t *output);

void blowfishDecryptBlock(BlowfishContext *context, const uint8_t *input,
   uint8_t *output);

void blowfishXorBlock(uint8_t *data, const uint8_t *salt, size_t saltLen,
   size_t *saltIndex);

void blowfishDeinit(BlowfishContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
