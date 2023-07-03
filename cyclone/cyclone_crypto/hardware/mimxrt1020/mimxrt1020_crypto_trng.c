/**
 * @file mimxrt1020_crypto_trng.c
 * @brief i.MX RT1020 true random number generator
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
#include "fsl_device_registers.h"
#include "fsl_trng.h"
#include "core/crypto.h"
#include "hardware/mimxrt1020/mimxrt1020_crypto.h"
#include "hardware/mimxrt1020/mimxrt1020_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1020_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   status_t status;
   trng_config_t trngConfig;

   //Enable TRNG peripheral clock
   CLOCK_EnableClock(kCLOCK_Trng);

   //Get default TRNG configuration
   TRNG_GetDefaultConfig(&trngConfig);
   //Initialize TRNG
   status = TRNG_Init(TRNG, &trngConfig);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   status_t status;

   //Acquire exclusive access to the TRNG module
   osAcquireMutex(&mimxrt1020CryptoMutex);

   //Generate random data
   status = TRNG_GetRandomData(TRNG, data, length);

   //Release exclusive access to the TRNG module
   osReleaseMutex(&mimxrt1020CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
