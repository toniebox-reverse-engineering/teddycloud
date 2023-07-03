/**
 * @file sam4l_crypto_cipher.h
 * @brief SAM4L cipher hardware accelerator
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

#ifndef _SAM4L_CRYPTO_CIPHER_H
#define _SAM4L_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef SAM4L_CRYPTO_CIPHER_SUPPORT
   #define SAM4L_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (SAM4L_CRYPTO_CIPHER_SUPPORT != ENABLED && SAM4L_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error SAM4L_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//CFBS bitfield
#define AESA_MODE_CFBS_128BIT AESA_MODE_CFBS(0)
#define AESA_MODE_CFBS_64BIT  AESA_MODE_CFBS(1)
#define AESA_MODE_CFBS_32BIT  AESA_MODE_CFBS(2)
#define AESA_MODE_CFBS_16BIT  AESA_MODE_CFBS(3)
#define AESA_MODE_CFBS_8BIT   AESA_MODE_CFBS(4)

//OPMODE bitfield
#define AESA_MODE_OPMODE_ECB  AESA_MODE_OPMODE(0)
#define AESA_MODE_OPMODE_CBC  AESA_MODE_OPMODE(1)
#define AESA_MODE_OPMODE_CFB  AESA_MODE_OPMODE(2)
#define AESA_MODE_OPMODE_OFB  AESA_MODE_OPMODE(3)
#define AESA_MODE_OPMODE_CTR  AESA_MODE_OPMODE(4)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
