/**
 * @file scrypt.h
 * @brief scrypt PBKDF (Password-Based Key Derivation Function)
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

#ifndef _SCRYPT_H
#define _SCRYPT_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//scrypt related functions
error_t scrypt(const char_t *password, const uint8_t *salt, size_t saltLen,
   uint_t n, uint_t r, uint_t p, uint8_t *dk, size_t dkLen);

void scryptRoMix(uint_t r, uint8_t *b, uint_t n, uint8_t *v, uint8_t *y);
void scryptBlockMix(uint_t r, uint8_t *b, uint8_t *y);
void scryptXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
