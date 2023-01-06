/**
 * @file twofish.h
 * @brief Twofish encryption algorithm
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

#ifndef _TWOFISH_H
#define _TWOFISH_H

//Dependencies
#include "core/crypto.h"

//Twofish block size
#define TWOFISH_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define TWOFISH_CIPHER_ALGO (&twofishCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Twofish algorithm context
 **/

typedef struct
{
   uint32_t k[40];
   uint32_t s1[256];
   uint32_t s2[256];
   uint32_t s3[256];
   uint32_t s4[256];
} TwofishContext;


//Twofish related constants
extern const CipherAlgo twofishCipherAlgo;

//Twofish related functions
error_t twofishInit(TwofishContext *context, const uint8_t *key, size_t keyLen);

void twofishEncryptBlock(TwofishContext *context, const uint8_t *input,
   uint8_t *output);

void twofishDecryptBlock(TwofishContext *context, const uint8_t *input,
   uint8_t *output);

void twofishDeinit(TwofishContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
