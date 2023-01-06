/**
 * @file stm32f4xx_crypto_trng.c
 * @brief STM32F4 true random number generator
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
#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32f4xx/stm32f4xx_crypto.h"
#include "hardware/stm32f4xx/stm32f4xx_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32F4XX_CRYPTO_TRNG_SUPPORT == ENABLED)

//Global variable
static RNG_HandleTypeDef RNG_Handle;


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   HAL_StatusTypeDef status;

   //Enable RNG peripheral clock
   __HAL_RCC_RNG_CLK_ENABLE();

   //Set instance
   RNG_Handle.Instance = RNG;

   //Reset RNG module
   status = HAL_RNG_DeInit(&RNG_Handle);

   //Check status code
   if(status == HAL_OK)
   {
      //Initialize RNG module
      status = HAL_RNG_Init(&RNG_Handle);
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   uint32_t value;
   HAL_StatusTypeDef status;

   //Initialize status code
   status = HAL_OK;

   //Acquire exclusive access to the RNG module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Generate random data
   for(i = 0; i < length; i++)
   {
      //Generate a new 32-bit random value when necessary
      if((i % 4) == 0)
      {
         //Get 32-bit random value
         status = HAL_RNG_GenerateRandomNumber(&RNG_Handle, &value);
         //Check status code
         if(status != HAL_OK)
         {
            break;
         }
      }

      //Copy random byte
      data[i] = value & 0xFF;
      //Shift the 32-bit random value
      value >>= 8;
   }

   //Release exclusive access to the RNG module
   osReleaseMutex(&stm32f4xxCryptoMutex);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}

#endif
