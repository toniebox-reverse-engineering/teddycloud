/**
 * @file idea.h
 * @brief IDEA encryption algorithm
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

#ifndef _IDEA_H
#define _IDEA_H

//Dependencies
#include "core/crypto.h"

//IDEA block size
#define IDEA_BLOCK_SIZE 8
//Common interface for encryption algorithms
#define IDEA_CIPHER_ALGO (&ideaCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IDEA algorithm context
 **/

typedef struct
{
   uint16_t ek[52];
   uint16_t dk[52];
} IdeaContext;


//IDEA related constants
extern const CipherAlgo ideaCipherAlgo;

//IDEA related functions
error_t ideaInit(IdeaContext *context, const uint8_t *key, size_t keyLen);

void ideaEncryptBlock(IdeaContext *context, const uint8_t *input,
   uint8_t *output);

void ideaDecryptBlock(IdeaContext *context, const uint8_t *input,
   uint8_t *output);

void ideaDeinit(IdeaContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
