/**
 * @file esp32_c3_crypto.c
 * @brief ESP32-C3 hardware cryptographic accelerator
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "driver/periph_ctrl.h"
#include "core/crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto_trng.h"
#include "hardware/esp32_c3/esp32_c3_crypto_hash.h"
#include "hardware/esp32_c3/esp32_c3_crypto_cipher.h"
#include "hardware/esp32_c3/esp32_c3_crypto_pkc.h"
#include "debug.h"

//Global variables
OsMutex esp32c3CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t esp32c3CryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&esp32c3CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(!error)
   {
#if (ESP32_C3_CRYPTO_TRNG_SUPPORT == ENABLED)
      //Initialize RNG module
      esp32c3RngInit();
#endif

#if (ESP32_C3_CRYPTO_HASH_SUPPORT == ENABLED)
      //Initialize SHA module
      esp32c3ShaInit();
#endif

#if (ESP32_C3_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
      //Initialize AES module
      esp32c3AesInit();
#endif

#if (ESP32_C3_CRYPTO_PKC_SUPPORT == ENABLED)
      //Initialize RSA module
      esp32c3RsaInit();
#endif
   }

   //Return status code
   return error;
}
