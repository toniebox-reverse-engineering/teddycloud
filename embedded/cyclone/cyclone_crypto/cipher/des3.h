/**
 * @file des3.h
 * @brief Triple DES (Triple Data Encryption Algorithm)
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

#ifndef _DES3_H
#define _DES3_H

//Dependencies
#include "core/crypto.h"
#include "cipher/des.h"

//Application specific context
#ifndef DES3_PRIVATE_CONTEXT
   #define DES3_PRIVATE_CONTEXT
#endif

//Triple DES block size
#define DES3_BLOCK_SIZE 8
//Common interface for encryption algorithms
#define DES3_CIPHER_ALGO (&des3CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Triple DES algorithm context
 **/

typedef struct
{
   DesContext k1;
   DesContext k2;
   DesContext k3;
   DES3_PRIVATE_CONTEXT
} Des3Context;


//Triple DES related constants
extern const CipherAlgo des3CipherAlgo;

//Triple DES related functions
error_t des3Init(Des3Context *context, const uint8_t *key, size_t keyLen);

void des3EncryptBlock(Des3Context *context, const uint8_t *input,
   uint8_t *output);

void des3DecryptBlock(Des3Context *context, const uint8_t *input,
   uint8_t *output);

void des3Deinit(Des3Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
