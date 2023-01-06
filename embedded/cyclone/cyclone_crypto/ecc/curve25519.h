/**
 * @file curve25519.h
 * @brief Curve25519 elliptic curve (constant-time implementation)
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

#ifndef _CURVE25519_H
#define _CURVE25519_H

//Dependencies
#include "core/crypto.h"

//Length of the elliptic curve
#define CURVE25519_BIT_LEN 255
#define CURVE25519_BYTE_LEN 32
#define CURVE25519_WORD_LEN 8

//A24 constant
#define CURVE25519_A24 121666

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Curve25519 related functions
void curve25519SetInt(uint32_t *a, uint32_t b);
void curve25519Add(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519AddInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Sub(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519SubInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519MulInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Red(uint32_t *r, const uint32_t *a);
void curve25519Sqr(uint32_t *r, const uint32_t *a);
void curve25519Pwr2(uint32_t *r, const uint32_t *a, uint_t n);
void curve25519Inv(uint32_t *r, const uint32_t *a);

uint32_t curve25519Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b);

void curve25519Copy(uint32_t *a, const uint32_t *b);
void curve25519Swap(uint32_t *a, uint32_t *b, uint32_t c);

void curve25519Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c);

uint32_t curve25519Comp(const uint32_t *a, const uint32_t *b);

void curve25519Import(uint32_t *a, const uint8_t *data);
void curve25519Export(uint32_t *a, uint8_t *data);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
