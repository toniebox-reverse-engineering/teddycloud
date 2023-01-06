/**
 * @file mimxrt1060_crypto_hash.c
 * @brief i.MX RT1060 hash hardware accelerator
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
#include "fsl_dcp.h"
#include "core/crypto.h"
#include "hardware/mimxrt1060/mimxrt1060_crypto.h"
#include "hardware/mimxrt1060/mimxrt1060_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1060_CRYPTO_HASH_SUPPORT == ENABLED)

//IAR EWARM compiler?
#if defined(__ICCARM__)

//DCP buffer
#pragma data_alignment = 16
#pragma location = MIMXRT1060_DCP_RAM_SECTION
static uint8_t dcpBuffer[MIMXRT1060_DCP_BUFFER_SIZE];

//DCP hash context
#pragma data_alignment = 16
#pragma location = MIMXRT1060_DCP_RAM_SECTION
static dcp_hash_ctx_t dcpHashContext;

//ARM or GCC compiler?
#else

//DCP buffer
static uint8_t dcpBuffer[MIMXRT1060_DCP_BUFFER_SIZE]
   __attribute__((aligned(16), __section__(MIMXRT1060_DCP_RAM_SECTION)));

//DCP hash context
static dcp_hash_ctx_t dcpHashContext
   __attribute__((aligned(16), __section__(MIMXRT1060_DCP_RAM_SECTION)));

#endif

#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   status_t status;
   dcp_handle_t dcpHandle;

   //Set DCP parameters
   dcpHandle.channel = kDCP_Channel0;
   dcpHandle.keySlot = kDCP_KeySlot0;
   dcpHandle.swapConfig = kDCP_NoSwap;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Initialize hash computation
   status = DCP_HASH_Init(DCP, &dcpHandle, &dcpHashContext, kDCP_Sha1);

   //Digest the message
   while(length > 0 && status == kStatus_Success)
   {
      //Limit the number of data to process at a time
      n = MIN(length, MIMXRT1060_DCP_BUFFER_SIZE);
      //Copy the data to the buffer
      osMemcpy(dcpBuffer, data, n);

      //Update hash value
      status = DCP_HASH_Update(DCP, &dcpHashContext, dcpBuffer, n);

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA1_DIGEST_SIZE;
      //Finalize hash computation
      status = DCP_HASH_Finish(DCP, &dcpHashContext, digest, &n);
   }

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

void sha1Init(Sha1Context *context)
{
   dcp_handle_t *dcpHandle;

   //Point to the DCP handle
   dcpHandle = &context->dcpHandle;

   //Set DCP parameters
   dcpHandle->channel = kDCP_Channel0;
   dcpHandle->keySlot = kDCP_KeySlot0;
   dcpHandle->swapConfig = kDCP_NoSwap;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Initialize hash computation
   DCP_HASH_Init(DCP, dcpHandle, &dcpHashContext, kDCP_Sha1);
   //Save hash context
   context->dcpContext = dcpHashContext;

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);
}


/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Restore hash context
   dcpHashContext = context->dcpContext;

   //Digest the message
   while(length > 0)
   {
      //Limit the number of data to process at a time
      n = MIN(length, MIMXRT1060_DCP_BUFFER_SIZE);
      //Copy the data to the buffer
      osMemcpy(dcpBuffer, data, n);

      //Update hash value
      DCP_HASH_Update(DCP, &dcpHashContext, dcpBuffer, n);

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }

   //Save hash context
   context->dcpContext = dcpHashContext;

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha1Final(Sha1Context *context, uint8_t *digest)
{
   size_t n;

   //Specify the size of the output buffer
   n = SHA1_DIGEST_SIZE;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Restore hash context
   dcpHashContext = context->dcpContext;
   //Finalize hash computation
   DCP_HASH_Finish(DCP, &dcpHashContext, context->digest, &n);

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA1_DIGEST_SIZE);
   }
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   status_t status;
   dcp_handle_t dcpHandle;

   //Set DCP parameters
   dcpHandle.channel = kDCP_Channel0;
   dcpHandle.keySlot = kDCP_KeySlot0;
   dcpHandle.swapConfig = kDCP_NoSwap;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Initialize hash computation
   status = DCP_HASH_Init(DCP, &dcpHandle, &dcpHashContext, kDCP_Sha256);

   //Digest the message
   while(length > 0 && status == kStatus_Success)
   {
      //Limit the number of data to process at a time
      n = MIN(length, MIMXRT1060_DCP_BUFFER_SIZE);
      //Copy the data to the buffer
      osMemcpy(dcpBuffer, data, n);

      //Update hash value
      status = DCP_HASH_Update(DCP, &dcpHashContext, dcpBuffer, n);

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA256_DIGEST_SIZE;
      //Finalize hash computation
      status = DCP_HASH_Finish(DCP, &dcpHashContext, digest, &n);
   }

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   dcp_handle_t *dcpHandle;

   //Point to the DCP handle
   dcpHandle = &context->dcpHandle;

   //Set DCP parameters
   dcpHandle->channel = kDCP_Channel0;
   dcpHandle->keySlot = kDCP_KeySlot0;
   dcpHandle->swapConfig = kDCP_NoSwap;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Initialize hash computation
   DCP_HASH_Init(DCP, dcpHandle, &dcpHashContext, kDCP_Sha256);
   //Save hash context
   context->dcpContext = dcpHashContext;

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);
}


/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Restore hash context
   dcpHashContext = context->dcpContext;

   //Digest the message
   while(length > 0)
   {
      //Limit the number of data to process at a time
      n = MIN(length, MIMXRT1060_DCP_BUFFER_SIZE);
      //Copy the data to the buffer
      osMemcpy(dcpBuffer, data, n);

      //Update hash value
      DCP_HASH_Update(DCP, &dcpHashContext, dcpBuffer, n);

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }

   //Save hash context
   context->dcpContext = dcpHashContext;

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   size_t n;

   //Specify the size of the output buffer
   n = SHA256_DIGEST_SIZE;

   //Acquire exclusive access to the DCP module
   osAcquireMutex(&mimxrt1060CryptoMutex);

   //Restore hash context
   dcpHashContext = context->dcpContext;
   //Finalize hash computation
   DCP_HASH_Finish(DCP, &dcpHashContext, context->digest, &n);

   //Release exclusive access to the DCP module
   osReleaseMutex(&mimxrt1060CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
   }
}

#endif
#endif
