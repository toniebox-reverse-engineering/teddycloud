/**
 * @file bcrypt.h
 * @brief bcrypt password hashing function
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

#ifndef _BCRYPT_H
#define _BCRYPT_H

//Dependencies
#include "core/crypto.h"
#include "cipher/blowfish.h"

//Minimum acceptable value for cost parameter
#ifndef BCRYPT_MIN_COST
   #define BCRYPT_MIN_COST 3
#elif (BCRYPT_MIN_COST < 3)
   #error BCRYPT_MIN_COST parameter is not valid
#endif

//Maximum acceptable value for cost parameter
#ifndef BCRYPT_MAX_COST
   #define BCRYPT_MAX_COST 31
#elif (BCRYPT_MAX_COST < BCRYPT_MIN_COST || BCRYPT_MAX_COST > 31)
   #error BCRYPT_MAX_COST parameter is not valid
#endif

//Length of bcrypt hash string
#define BCRYPT_HASH_STRING_LEN 60

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//bcrypt related functions
error_t bcryptHashPassword(const PrngAlgo *prngAlgo, void *prngContext,
   uint_t cost, const char_t *password, char_t *hash, size_t *hashLen);

error_t bcryptVerifyPassword(const char_t *password, const char_t *hash);

error_t bcrypt(uint_t cost, const uint8_t *salt, const char_t *password,
   char_t *hash, size_t *hashLen);

error_t eksBlowfishSetup(BlowfishContext *context, uint_t cost,
   const uint8_t *salt, size_t saltLen, const char_t *password,
   size_t passwordLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
