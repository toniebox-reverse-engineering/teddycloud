/**
 * @file ra6_crypto.c
 * @brief RA6 hardware cryptographic accelerator (SCE7 / SCE9)
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
#include "hw_sce_private.h"
#include "core/crypto.h"
#include "hardware/ra6/ra6_crypto.h"
#include "debug.h"

//Global variables
OsMutex ra6CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t ra6CryptoInit(void)
{
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&ra6CryptoMutex))
   {
      //Failed to create mutex
      status = FSP_ERR_CRYPTO_NOT_OPEN;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Initialize SCE module
      status = HW_SCE_McuSpecificInit();
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}
