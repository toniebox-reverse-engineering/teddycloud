/**
 * @file esp32_crypto_pkc.h
 * @brief ESP32 public-key hardware accelerator
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

#ifndef _ESP32_CRYPTO_PKC_H
#define _ESP32_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef ESP32_CRYPTO_PKC_SUPPORT
   #define ESP32_CRYPTO_PKC_SUPPORT DISABLED
#elif (ESP32_CRYPTO_PKC_SUPPORT != ENABLED && ESP32_CRYPTO_PKC_SUPPORT != DISABLED)
   #error ESP32_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKC related functions
void esp32RsaInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
