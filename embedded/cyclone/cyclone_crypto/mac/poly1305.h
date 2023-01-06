/**
 * @file poly1305.h
 * @brief Poly1305 message-authentication code
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

#ifndef _POLY1305_H
#define _POLY1305_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Poly1305 context
 **/

typedef struct
{
   uint32_t r[4];
   uint32_t s[4];
   uint64_t a[8];
   uint8_t buffer[17];
   size_t size;
} Poly1305Context;


//Poly1305 related functions
void poly1305Init(Poly1305Context *context, const uint8_t *key);
void poly1305Update(Poly1305Context *context, const void *data, size_t length);
void poly1305Final(Poly1305Context *context, uint8_t *tag);

void poly1305ProcessBlock(Poly1305Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
