/**
 * @file x25519.h
 * @brief X25519 function implementation
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

#ifndef _X25519_H
#define _X25519_H

//Dependencies
#include "core/crypto.h"
#include "ecc/curve25519.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief X25519 working state
 **/

typedef struct
{
   uint32_t k[8];
   uint32_t u[8];
   uint32_t x1[8];
   uint32_t z1[8];
   uint32_t x2[8];
   uint32_t z2[8];
   uint32_t t1[8];
   uint32_t t2[8];
} X25519State;


//X25519 related functions
error_t x25519(uint8_t *r, const uint8_t *k, const uint8_t *u);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
