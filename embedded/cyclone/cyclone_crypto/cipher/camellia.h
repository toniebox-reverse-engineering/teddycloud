/**
 * @file camellia.h
 * @brief Camellia encryption algorithm
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

#ifndef _CAMELLIA_H
#define _CAMELLIA_H

//Dependencies
#include "core/crypto.h"

//Camellia block size
#define CAMELLIA_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define CAMELLIA_CIPHER_ALGO (&camelliaCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Structure describing subkey generation
 **/

typedef struct
{
   uint8_t index;
   uint8_t key;
   uint8_t shift;
   uint8_t position;
} CamelliaSubkey;


/**
 * @brief Camellia algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t k[16];
   uint32_t ks[68];
} CamelliaContext;


//Camellia related constants
extern const CipherAlgo camelliaCipherAlgo;

//Camellia related functions
error_t camelliaInit(CamelliaContext *context, const uint8_t *key,
   size_t keyLen);

void camelliaEncryptBlock(CamelliaContext *context, const uint8_t *input,
   uint8_t *output);

void camelliaDecryptBlock(CamelliaContext *context, const uint8_t *input,
   uint8_t *output);

void camelliaDeinit(CamelliaContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
