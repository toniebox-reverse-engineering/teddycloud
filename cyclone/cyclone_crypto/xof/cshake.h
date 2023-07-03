/**
 * @file cshake.h
 * @brief cSHAKE128 and cSHAKE256 (customizable SHAKE function)
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

#ifndef _CSHAKE_H
#define _CSHAKE_H

//Dependencies
#include "core/crypto.h"
#include "xof/keccak.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief cSHAKE algorithm context
 **/

typedef struct
{
   size_t nameLen;
   size_t customLen;
   KeccakContext keccakContext;
} CshakeContext;


//cSHAKE related functions
error_t cshakeCompute(uint_t strength, const void *input, size_t inputLen,
   const char_t *name, size_t nameLen, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen);

error_t cshakeInit(CshakeContext *context, uint_t strength, const char_t *name,
   size_t nameLen, const char_t *custom, size_t customLen);

void cshakeAbsorb(CshakeContext *context, const void *input, size_t length);
void cshakeFinal(CshakeContext *context);
void cshakeSqueeze(CshakeContext *context, uint8_t *output, size_t length);

void cshakeLeftEncode(size_t value, uint8_t *buffer, size_t *length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
