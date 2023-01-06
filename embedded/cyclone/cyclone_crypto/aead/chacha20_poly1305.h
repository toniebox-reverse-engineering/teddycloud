/**
 * @file chacha20_poly1305.h
 * @brief ChaCha20Poly1305 AEAD
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

#ifndef _CHACHA20_POLY1305_H
#define _CHACHA20_POLY1305_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ChaCha20Poly1305 related functions
error_t chacha20Poly1305Encrypt(const uint8_t *k, size_t kLen,
   const uint8_t *n, size_t nLen, const uint8_t *a, size_t aLen,
   const uint8_t *p, uint8_t *c, size_t length, uint8_t *t, size_t tLen);

error_t chacha20Poly1305Decrypt(const uint8_t *k, size_t kLen,
   const uint8_t *n, size_t nLen, const uint8_t *a, size_t aLen,
   const uint8_t *c, uint8_t *p, size_t length, const uint8_t *t, size_t tLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
