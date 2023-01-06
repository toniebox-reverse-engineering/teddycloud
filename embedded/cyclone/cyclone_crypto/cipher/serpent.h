/**
 * @file serpent.h
 * @brief Serpent encryption algorithm
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

#ifndef _SERPENT_H
#define _SERPENT_H

//Dependencies
#include "core/crypto.h"

//Serpent block size
#define SERPENT_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define SERPENT_CIPHER_ALGO (&serpentCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Serpent algorithm context
 **/

typedef struct
{
   uint32_t k[33][4];
} SerpentContext;


//Serpent related constants
extern const CipherAlgo serpentCipherAlgo;

//Serpent related functions
error_t serpentInit(SerpentContext *context, const uint8_t *key, size_t keyLen);

void serpentEncryptBlock(SerpentContext *context, const uint8_t *input,
   uint8_t *output);

void serpentDecryptBlock(SerpentContext *context, const uint8_t *input,
   uint8_t *output);

void serpentDeinit(SerpentContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
