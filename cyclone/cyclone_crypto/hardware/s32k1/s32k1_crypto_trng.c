/**
 * @file s32k1_crypto_trng.c
 * @brief S32K1 true random number generator
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
#include "core/crypto.h"
#include "hardware/s32k1/s32k1_crypto.h"
#include "hardware/s32k1/s32k1_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (S32K1_CRYPTO_TRNG_SUPPORT == ENABLED)

//Global variables
static uint8_t buffer[16];
static size_t index;


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   uint32_t status;

   //Mark the buffer as empty
   index = sizeof(buffer);

   //Check for the previous CSEq command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Clear error flags
   FTFC->FSTAT = FTFC_FSTAT_FPVIOL_MASK | FTFC_FSTAT_ACCERR_MASK;

   //Start CSEq command
   CSE_PRAM->RAMn[0].DATA_32 = CSEQ_CMD_INIT_RNG;

   //Wait for the CSEq command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Retrieve status code
   status = CSE_PRAM->RAMn[1].DATA_32 >> 16;

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   uint32_t temp;
   uint32_t status;

   //Initialize status code
   status = CSEQ_ERC_NO_ERROR;

   //Acquire exclusive access to the RNG module
   osAcquireMutex(&s32k1CryptoMutex);

   //Generate random data
   for(i = 0; i < length && status == CSEQ_ERC_NO_ERROR; i++)
   {
      //Generate a new 128-bit random value when necessary
      if(index >= sizeof(buffer))
      {
         //Check for the previous CSEq command to complete
         while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
         {
         }

         //Clear error flags
         FTFC->FSTAT = FTFC_FSTAT_FPVIOL_MASK | FTFC_FSTAT_ACCERR_MASK;

         //Start CSEq command
         CSE_PRAM->RAMn[0].DATA_32 = CSEQ_CMD_RND;

         //Wait for the CSEq command to complete
         while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
         {
         }

         //Retrieve status code
         status = CSE_PRAM->RAMn[1].DATA_32 >> 16;

         //Check status code
         if(status == CSEQ_ERC_NO_ERROR)
         {
            //Save the 128-bit random value
            temp = CSE_PRAM->RAMn[4].DATA_32;
            STORE32BE(temp, buffer);
            temp = CSE_PRAM->RAMn[5].DATA_32;
            STORE32BE(temp, buffer + 4);
            temp = CSE_PRAM->RAMn[6].DATA_32;
            STORE32BE(temp, buffer + 8);
            temp = CSE_PRAM->RAMn[7].DATA_32;
            STORE32BE(temp, buffer + 12);
         }

         //Rewind to the beginning of the buffer
         index = 0;
      }

      //Extract a random byte
      data[i] = buffer[index++];
   }

   //Release exclusive access to the RNG module
   osReleaseMutex(&s32k1CryptoMutex);

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
}

#endif
