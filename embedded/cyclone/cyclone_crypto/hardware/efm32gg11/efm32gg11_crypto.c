/**
 * @file efm32gg11_crypto.c
 * @brief EFM32 Giant Gecko 11 hardware cryptographic accelerator
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
#include "em_device.h"
#include "em_cmu.h"
#include "core/crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto_trng.h"
#include "hardware/efm32gg11/efm32gg11_crypto_hash.h"
#include "hardware/efm32gg11/efm32gg11_crypto_cipher.h"
#include "hardware/efm32gg11/efm32gg11_crypto_pkc.h"
#include "debug.h"

//Global variables
OsMutex efm32gg11CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t efm32gg11CryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&efm32gg11CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (EFM32GG11_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

#if (EFM32GG11_CRYPTO_HASH_SUPPORT == ENABLED || \
   EFM32GG11_CRYPTO_CIPHER_SUPPORT == ENABLED || \
   EFM32GG11_CRYPTO_PKC_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Enable CRYPTO clock
      CMU_ClockEnable(cmuClock_CRYPTO0, true);
   }
#endif

   //Return status code
   return error;
}
