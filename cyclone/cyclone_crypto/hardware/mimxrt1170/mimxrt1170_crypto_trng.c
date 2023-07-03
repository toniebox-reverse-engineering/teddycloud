/**
 * @file mimxrt1170_crypto_trng.c
 * @brief i.MX RT1170 true random number generator
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
#include "fsl_caam.h"
#include "core/crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1170_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   status_t status;
   caam_handle_t caamHandle;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1170CryptoMutex);

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Generate random data
   status = CAAM_RNG_GetRandomData(CAAM, &caamHandle, kCAAM_RngStateHandle0,
      data, length, kCAAM_RngDataAny, NULL);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1170CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
