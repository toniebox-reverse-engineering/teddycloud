/**
 * @file rc6.h
 * @brief RC6-32/20 block cipher
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

#ifndef _RC6_H
#define _RC6_H

//Dependencies
#include "core/crypto.h"

//RC6 block size
#define RC6_BLOCK_SIZE 16
//Maximum length of the encryption key in bytes
#define RC6_MAX_KEY_SIZE 32
//Number of rounds
#define RC6_NB_ROUNDS 20

//Common interface for encryption algorithms
#define RC6_CIPHER_ALGO (&rc6CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RC6 algorithm context
 **/

typedef struct
{
   uint32_t l[RC6_MAX_KEY_SIZE / 4];
   uint32_t s[2 * RC6_NB_ROUNDS + 4];
} Rc6Context;


//RC6 related constants
extern const CipherAlgo rc6CipherAlgo;

//RC6 related functions
error_t rc6Init(Rc6Context *context, const uint8_t *key, size_t keyLen);

void rc6EncryptBlock(Rc6Context *context, const uint8_t *input,
   uint8_t *output);

void rc6DecryptBlock(Rc6Context *context, const uint8_t *input,
   uint8_t *output);

void rc6Deinit(Rc6Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
