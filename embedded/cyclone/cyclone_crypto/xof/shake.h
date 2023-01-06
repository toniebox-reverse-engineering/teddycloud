/**
 * @file shake.h
 * @brief SHAKE128 and SHAKE256 extendable-output functions
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

#ifndef _SHAKE_H
#define _SHAKE_H

//Dependencies
#include "core/crypto.h"
#include "xof/keccak.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHAKE algorithm context
 **/

typedef struct
{
   KeccakContext keccakContext;
} ShakeContext;


//SHAKE related constants
extern const uint8_t shake128Oid[9];
extern const uint8_t shake256Oid[9];

//SHAKE related functions
error_t shakeCompute(uint_t strength, const void *input, size_t inputLen,
   uint8_t *output, size_t outputLen);

error_t shakeInit(ShakeContext *context, uint_t strength);
void shakeAbsorb(ShakeContext *context, const void *input, size_t length);
void shakeFinal(ShakeContext *context);
void shakeSqueeze(ShakeContext *context, uint8_t *output, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
