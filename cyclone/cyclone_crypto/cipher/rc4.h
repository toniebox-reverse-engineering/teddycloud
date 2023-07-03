/**
 * @file rc4.h
 * @brief RC4 encryption algorithm
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

#ifndef _RC4_H
#define _RC4_H

//Dependencies
#include "core/crypto.h"

//Common interface for encryption algorithms
#define RC4_CIPHER_ALGO (&rc4CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RC4 algorithm context
 **/

typedef struct
{
   uint_t i;
   uint_t j;
   uint8_t s[256];
} Rc4Context;


//RC4 related constants
extern const CipherAlgo rc4CipherAlgo;

//RC4 related functions
error_t rc4Init(Rc4Context *context, const uint8_t *key, size_t length);

void rc4Cipher(Rc4Context *context, const uint8_t *input, uint8_t *output,
   size_t length);

void rc4Deinit(Rc4Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
