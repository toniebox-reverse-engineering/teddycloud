/**
 * @file chacha.h
 * @brief ChaCha encryption algorithm
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

#ifndef _CHACHA_H
#define _CHACHA_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ChaCha algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t state[16];
   uint32_t block[16];
   size_t pos;
} ChachaContext;


//ChaCha related functions
error_t chachaInit(ChachaContext *context, uint_t nr, const uint8_t *key,
   size_t keyLen, const uint8_t *nonce, size_t nonceLen);

void chachaCipher(ChachaContext *context, const uint8_t *input,
   uint8_t *output, size_t length);

void chachaProcessBlock(ChachaContext *context);

void chachaDeinit(ChachaContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
