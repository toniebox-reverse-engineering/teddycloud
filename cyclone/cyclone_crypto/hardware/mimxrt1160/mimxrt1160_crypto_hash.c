/**
 * @file mimxrt1160_crypto_hash.c
 * @brief i.MX RT1160 hash hardware accelerator
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
#include "hardware/mimxrt1160/mimxrt1160_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1160_CRYPTO_HASH_SUPPORT == ENABLED)

//CAAM hash context
static caam_hash_ctx_t caamHashContext;


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
   caam_handle_t caamHandle;

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   status = CAAM_HASH_Init(CAAM, &caamHandle, &caamHashContext, kCAAM_Sha1,
      NULL, 0);

   //Check status code
   if(status == kStatus_Success)
   {
      //Digest message
      status = CAAM_HASH_Update(&caamHashContext, data, length);
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA1_DIGEST_SIZE;
      //Finalize hash computation
      status = CAAM_HASH_Finish(&caamHashContext, digest, &n);
   }

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

void sha1Init(Sha1Context *context)
{
   caam_handle_t *caamHandle;

   //Point to the CAAM handle
   caamHandle = &context->caamHandle;
   //Set CAAM job ring
   caamHandle->jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   CAAM_HASH_Init(CAAM, caamHandle, &caamHashContext, kCAAM_Sha1, NULL, 0);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Digest the message
   CAAM_HASH_Update(&caamHashContext, data, length);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
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

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Finalize hash computation
   CAAM_HASH_Finish(&caamHashContext, context->digest, &n);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA1_DIGEST_SIZE);
   }
}

#endif
#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   status_t status;
   caam_handle_t caamHandle;

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   status = CAAM_HASH_Init(CAAM, &caamHandle, &caamHashContext, kCAAM_Sha224,
      NULL, 0);

   //Check status code
   if(status == kStatus_Success)
   {
      //Digest message
      status = CAAM_HASH_Update(&caamHashContext, data, length);
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA224_DIGEST_SIZE;
      //Finalize hash computation
      status = CAAM_HASH_Finish(&caamHashContext, digest, &n);
   }

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   caam_handle_t *caamHandle;

   //Point to the CAAM handle
   caamHandle = &context->caamHandle;
   //Set CAAM job ring
   caamHandle->jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   CAAM_HASH_Init(CAAM, caamHandle, &caamHashContext, kCAAM_Sha224, NULL, 0);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Update the SHA-224 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-224 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha224Update(Sha224Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Digest the message
   CAAM_HASH_Update(&caamHashContext, data, length);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Finish the SHA-224 message digest
 * @param[in] context Pointer to the SHA-224 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha224Final(Sha224Context *context, uint8_t *digest)
{
   size_t n;

   //Specify the size of the output buffer
   n = SHA224_DIGEST_SIZE;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Finalize hash computation
   CAAM_HASH_Finish(&caamHashContext, context->digest, &n);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA224_DIGEST_SIZE);
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
   caam_handle_t caamHandle;

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   status = CAAM_HASH_Init(CAAM, &caamHandle, &caamHashContext, kCAAM_Sha256,
      NULL, 0);

   //Check status code
   if(status == kStatus_Success)
   {
      //Digest message
      status = CAAM_HASH_Update(&caamHashContext, data, length);
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA256_DIGEST_SIZE;
      //Finalize hash computation
      status = CAAM_HASH_Finish(&caamHashContext, digest, &n);
   }

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   caam_handle_t *caamHandle;

   //Point to the CAAM handle
   caamHandle = &context->caamHandle;
   //Set CAAM job ring
   caamHandle->jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   CAAM_HASH_Init(CAAM, caamHandle, &caamHashContext, kCAAM_Sha256, NULL, 0);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Digest the message
   CAAM_HASH_Update(&caamHashContext, data, length);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
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

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Finalize hash computation
   CAAM_HASH_Finish(&caamHashContext, context->digest, &n);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
   }
}

#endif
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-384
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha384Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   status_t status;
   caam_handle_t caamHandle;

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   status = CAAM_HASH_Init(CAAM, &caamHandle, &caamHashContext, kCAAM_Sha384,
      NULL, 0);

   //Check status code
   if(status == kStatus_Success)
   {
      //Digest message
      status = CAAM_HASH_Update(&caamHashContext, data, length);
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA384_DIGEST_SIZE;
      //Finalize hash computation
      status = CAAM_HASH_Finish(&caamHashContext, digest, &n);
   }

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-384 message digest context
 * @param[in] context Pointer to the SHA-384 context to initialize
 **/

void sha384Init(Sha384Context *context)
{
   caam_handle_t *caamHandle;

   //Point to the CAAM handle
   caamHandle = &context->caamHandle;
   //Set CAAM job ring
   caamHandle->jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   CAAM_HASH_Init(CAAM, caamHandle, &caamHashContext, kCAAM_Sha384, NULL, 0);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Update the SHA-384 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-384 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha384Update(Sha384Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Digest the message
   CAAM_HASH_Update(&caamHashContext, data, length);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Finish the SHA-384 message digest
 * @param[in] context Pointer to the SHA-384 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha384Final(Sha384Context *context, uint8_t *digest)
{
   size_t n;

   //Specify the size of the output buffer
   n = SHA384_DIGEST_SIZE;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Finalize hash computation
   CAAM_HASH_Finish(&caamHashContext, context->digest, &n);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA384_DIGEST_SIZE);
   }
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha512Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   status_t status;
   caam_handle_t caamHandle;

   //Set CAAM job ring
   caamHandle.jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   status = CAAM_HASH_Init(CAAM, &caamHandle, &caamHashContext, kCAAM_Sha512,
      NULL, 0);

   //Check status code
   if(status == kStatus_Success)
   {
      //Digest message
      status = CAAM_HASH_Update(&caamHashContext, data, length);
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Specify the size of the output buffer
      n = SHA512_DIGEST_SIZE;
      //Finalize hash computation
      status = CAAM_HASH_Finish(&caamHashContext, digest, &n);
   }

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-512 message digest context
 * @param[in] context Pointer to the SHA-512 context to initialize
 **/

void sha512Init(Sha512Context *context)
{
   caam_handle_t *caamHandle;

   //Point to the CAAM handle
   caamHandle = &context->caamHandle;
   //Set CAAM job ring
   caamHandle->jobRing = kCAAM_JobRing0;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Initialize hash computation
   CAAM_HASH_Init(CAAM, caamHandle, &caamHashContext, kCAAM_Sha512, NULL, 0);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Update the SHA-512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512Update(Sha512Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Digest the message
   CAAM_HASH_Update(&caamHashContext, data, length);
   //Save hash context
   osMemcpy(context->caamContext, &caamHashContext, sizeof(caam_hash_ctx_t));

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);
}


/**
 * @brief Finish the SHA-512 message digest
 * @param[in] context Pointer to the SHA-512 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha512Final(Sha512Context *context, uint8_t *digest)
{
   size_t n;

   //Specify the size of the output buffer
   n = SHA512_DIGEST_SIZE;

   //Acquire exclusive access to the CAAM module
   osAcquireMutex(&mimxrt1160CryptoMutex);

   //Restore hash context
   osMemcpy(&caamHashContext, context->caamContext, sizeof(caam_hash_ctx_t));
   //Finalize hash computation
   CAAM_HASH_Finish(&caamHashContext, context->digest, &n);

   //Release exclusive access to the CAAM module
   osReleaseMutex(&mimxrt1160CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA512_DIGEST_SIZE);
   }
}

#endif
#endif
