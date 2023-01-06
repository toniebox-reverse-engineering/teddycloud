/**
 * @file mimxrt1160_crypto.c
 * @brief i.MX RT1160 hardware cryptographic accelerator (CAAM)
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
#include "hardware/mimxrt1160/mimxrt1160_crypto.h"
#include "debug.h"

//Global variables
OsMutex mimxrt1160CryptoMutex;

//CAAM job ring interfaces
static caam_job_ring_interface_t caamJobRingInterface[4];


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t mimxrt1160CryptoInit(void)
{
   status_t status;
   caam_config_t caamConfig;

   //Initialize status code
   status = kStatus_Success;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&mimxrt1160CryptoMutex))
   {
      //Failed to create mutex
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Get default configuration
      CAAM_GetDefaultConfig(&caamConfig);

      //Set job ring interfaces
      caamConfig.jobRingInterface[0] = &caamJobRingInterface[0];
      caamConfig.jobRingInterface[1] = &caamJobRingInterface[1];
      caamConfig.jobRingInterface[2] = &caamJobRingInterface[2];
      caamConfig.jobRingInterface[3] = &caamJobRingInterface[3];

      //Initialize CAAM module
      status = CAAM_Init(CAAM, &caamConfig);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}
