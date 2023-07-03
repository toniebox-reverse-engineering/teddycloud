/**
 * @file xts.h
 * @brief XEX-based tweaked-codebook mode with ciphertext stealing (XTS)
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

#ifndef _XTS_H
#define _XTS_H

//Dependencies
#include "core/crypto.h"
#include "cipher/cipher_algorithms.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief XTS context
 **/

typedef struct
{
   const CipherAlgo *cipherAlgo;
   CipherContext cipherContext1;
   CipherContext cipherContext2;
} XtsContext;


//XTS related functions
error_t xtsInit(XtsContext *context, const CipherAlgo *cipherAlgo,
   const void *key, size_t keyLen);

error_t xtsEncrypt(XtsContext *context, const uint8_t *i, const uint8_t *p,
   uint8_t *c, size_t length);

error_t xtsDecrypt(XtsContext *context, const uint8_t *i, const uint8_t *c,
   uint8_t *p, size_t length);

void xtsMul(uint8_t *x, const uint8_t *a);
void xtsXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
