/**
 * @file rx65n_crypto.c
 * @brief RX65N hardware cryptographic accelerator (TSIP)
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
#include "r_tsip_rx_if.h"
#include "core/crypto.h"
#include "hardware/rx65n/rx65n_crypto.h"
#include "debug.h"

//Global variables
OsMutex rx65nCryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t rx65nCryptoInit(void)
{
   e_tsip_err_t status;

   //Initialize status code
   status = TSIP_SUCCESS;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&rx65nCryptoMutex))
   {
      //Failed to create mutex
      status = TSIP_ERR_FAIL;
   }

   //Check status code
   if(status == TSIP_SUCCESS)
   {
      //Initialize TSIP module
      status = R_TSIP_Open(NULL, NULL);
   }

   //Return status code
   return (status == TSIP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}
