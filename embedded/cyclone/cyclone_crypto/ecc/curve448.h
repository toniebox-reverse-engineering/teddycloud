/**
 * @file curve448.h
 * @brief Curve448 elliptic curve (constant-time implementation)
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

#ifndef _CURVE448_H
#define _CURVE448_H

//Dependencies
#include "core/crypto.h"

//Length of the elliptic curve
#define CURVE448_BIT_LEN 448
#define CURVE448_BYTE_LEN 56
#define CURVE448_WORD_LEN 14

//A24 constant
#define CURVE448_A24 39082

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Curve448 related functions
void curve448SetInt(uint32_t *a, uint32_t b);
void curve448Add(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448AddInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Sub(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448SubInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448MulInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Red(uint32_t *r, const uint32_t *a, uint32_t h);
void curve448Sqr(uint32_t *r, const uint32_t *a);
void curve448Pwr2(uint32_t *r, const uint32_t *a, uint_t n);
void curve448Inv(uint32_t *r, const uint32_t *a);

uint32_t curve448Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b);

void curve448Copy(uint32_t *a, const uint32_t *b);
void curve448Swap(uint32_t *a, uint32_t *b, uint32_t c);

void curve448Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c);

uint32_t curve448Comp(const uint32_t *a, const uint32_t *b);

void curve448Import(uint32_t *a, const uint8_t *data);
void curve448Export(uint32_t *a, uint8_t *data);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
