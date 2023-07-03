/**
 * @file tls_key_material.c
 * @brief Key material generation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_key_material.h"
#include "tls_transcript_hash.h"
#include "tls13_key_material.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Generate session keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGenerateSessionKeys(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   size_t keyBlockLen;
   TlsCipherSuiteInfo *cipherSuite;

   //Point to the negotiated cipher suite
   cipherSuite = &context->cipherSuite;

   //Length of necessary key material
   keyBlockLen = 2 * (cipherSuite->macKeyLen + cipherSuite->encKeyLen +
      cipherSuite->fixedIvLen);

   //Make sure that the key block is large enough
   if(keyBlockLen > sizeof(context->keyBlock))
      return ERROR_FAILURE;

   //Debug message
   TRACE_DEBUG("Generating session keys...\r\n");
   TRACE_DEBUG("  Client random bytes:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->clientRandom, 32);
   TRACE_DEBUG("  Server random bytes:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->serverRandom, 32);

   //If a full handshake is being performed, the premaster secret shall be
   //first converted to the master secret
   if(!context->resume)
   {
      //Debug message
      TRACE_DEBUG("  Premaster secret:\r\n");
      TRACE_DEBUG_ARRAY("    ", context->premasterSecret, context->premasterSecretLen);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //If both the ClientHello and ServerHello contain the ExtendedMasterSecret
      //extension, the new session uses the extended master secret computation
      if(context->emsExtReceived)
      {
         //Extended master secret computation
         error = tlsGenerateExtendedMasterSecret(context);
      }
      else
#endif
      {
         //Legacy master secret computation
         error = tlsGenerateMasterSecret(context);
      }

      //Failed to generate master secret?
      if(error)
         return error;

      //The premaster secret should be deleted from memory once the master
      //secret has been computed
      osMemset(context->premasterSecret, 0, TLS_PREMASTER_SECRET_SIZE);
   }

   //Debug message
   TRACE_DEBUG("  Master secret:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->masterSecret, TLS_MASTER_SECRET_SIZE);

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Log master secret
   tlsDumpSecret(context, "CLIENT_RANDOM", context->masterSecret,
      TLS_MASTER_SECRET_SIZE);
#endif

   //The master secret is used as an entropy source to generate the key material
   error = tlsGenerateKeyBlock(context, keyBlockLen);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Key block:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->keyBlock, keyBlockLen);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Master secret computation
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

__weak_func error_t tlsGenerateMasterSecret(TlsContext *context)
{
   error_t error;
   uint8_t random[2 * TLS_RANDOM_SIZE];

   //Concatenate client_random and server_random values
   osMemcpy(random, context->clientRandom, TLS_RANDOM_SIZE);
   osMemcpy(random + 32, context->serverRandom, TLS_RANDOM_SIZE);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //TLS 1.0 and 1.1 use a PRF that combines MD5 and SHA-1
      error = tlsPrf(context->premasterSecret, context->premasterSecretLen,
         "master secret", random, sizeof(random), context->masterSecret,
         TLS_MASTER_SECRET_SIZE);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //TLS 1.2 PRF uses SHA-256 or a stronger hash algorithm as the core
      //function in its construction
      error = tls12Prf(context->cipherSuite.prfHashAlgo,
         context->premasterSecret, context->premasterSecretLen,
         "master secret", random, sizeof(random), context->masterSecret,
         TLS_MASTER_SECRET_SIZE);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Extended master secret computation
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGenerateExtendedMasterSecret(TlsContext *context)
{
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //A temporary buffer is needed to concatenate MD5 and SHA-1 hash
      //values before computing the extended master secret
      uint8_t sessionHash[MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE];

      //Finalize MD5 hash computation
      error = tlsFinalizeTranscriptHash(context, MD5_HASH_ALGO,
         context->transcriptMd5Context, "", sessionHash);

      //Check status code
      if(!error)
      {
         //Finalize SHA-1 hash computation
         error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
            context->transcriptSha1Context, "", sessionHash + MD5_DIGEST_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Compute the extended master secret (refer to RFC 7627, section 4)
         error = tlsPrf(context->premasterSecret, context->premasterSecretLen,
            "extended master secret", sessionHash, sizeof(sessionHash),
            context->masterSecret, TLS_MASTER_SECRET_SIZE);
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Point to the hash algorithm to be used
      hashAlgo = context->cipherSuite.prfHashAlgo;

      //Allocate hash algorithm context
      hashContext = tlsAllocMem(hashAlgo->contextSize);

      //Successful memory allocation?
      if(hashContext != NULL)
      {
         //The original hash context must be preserved
         osMemcpy(hashContext, context->transcriptHashContext,
            hashAlgo->contextSize);

         //Finalize hash computation
         hashAlgo->final(hashContext, NULL);

         //Compute the extended master secret (refer to RFC 7627, section 4)
         error = tls12Prf(hashAlgo, context->premasterSecret,
            context->premasterSecretLen, "extended master secret",
            hashContext->digest, hashAlgo->digestSize,
            context->masterSecret, TLS_MASTER_SECRET_SIZE);

         //Release previously allocated memory
         tlsFreeMem(hashContext);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
#else
   //Extended master secret computation is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Premaster secret generation (for PSK cipher suites)
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGeneratePskPremasterSecret(TlsContext *context)
{
   error_t error;

#if (TLS_PSK_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK)
   {
      size_t n;

      //Let N be the length of pre-shared key
      n = context->pskLen;

      //Check whether the output buffer is large enough to hold the premaster
      //secret
      if((n * 2 + 4) <= TLS_PREMASTER_SECRET_SIZE)
      {
         //The premaster secret is formed as follows: if the PSK is N octets
         //long, concatenate a uint16 with the value N, N zero octets, a second
         //uint16 with the value N, and the PSK itself
         STORE16BE(n, context->premasterSecret);
         osMemset(context->premasterSecret + 2, 0, n);
         STORE16BE(n, context->premasterSecret + n + 2);
         osMemcpy(context->premasterSecret + n + 4, context->psk, n);

         //Save the length of the premaster secret
         context->premasterSecretLen = n * 2 + 4;

         //Premaster secret successfully generated
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   else
#endif
#if (TLS_RSA_PSK_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //RSA_PSK, DHE_PSK or ECDHE_PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;

      //Let N be the length of pre-shared key
      n = context->pskLen;

      //Check whether the output buffer is large enough to hold the premaster
      //secret
      if((context->premasterSecretLen + n + 4) <= TLS_PREMASTER_SECRET_SIZE)
      {
         //The "other_secret" field comes from the Diffie-Hellman, ECDH or
         //RSA exchange (DHE_PSK, ECDH_PSK and RSA_PSK, respectively)
         osMemmove(context->premasterSecret + 2, context->premasterSecret,
            context->premasterSecretLen);

         //The "other_secret" field is preceded by a 2-byte length field
         STORE16BE(context->premasterSecretLen, context->premasterSecret);

         //if the PSK is N octets long, concatenate a uint16 with the value N
         STORE16BE(n, context->premasterSecret + context->premasterSecretLen + 2);

         //Concatenate the PSK itself
         osMemcpy(context->premasterSecret + context->premasterSecretLen + 4,
            context->psk, n);

         //Adjust the length of the premaster secret
         context->premasterSecretLen += n + 4;

         //Premaster secret successfully generated
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Key expansion function
 * @param[in] context Pointer to the TLS context
 * @param[in] keyBlockLen Desired length for the resulting key block
 * @return Error code
 **/

__weak_func error_t tlsGenerateKeyBlock(TlsContext *context, size_t keyBlockLen)
{
   error_t error;
   uint8_t random[2 * TLS_RANDOM_SIZE];

   //Concatenate server_random and client_random values
   osMemcpy(random, context->serverRandom, TLS_RANDOM_SIZE);
   osMemcpy(random + 32, context->clientRandom, TLS_RANDOM_SIZE);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //TLS 1.0 and 1.1 use a PRF that combines MD5 and SHA-1
      error = tlsPrf(context->masterSecret, TLS_MASTER_SECRET_SIZE,
         "key expansion", random, sizeof(random), context->keyBlock,
         keyBlockLen);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //TLS 1.2 PRF uses SHA-256 or a stronger hash algorithm as the core
      //function in its construction
      error = tls12Prf(context->cipherSuite.prfHashAlgo,
         context->masterSecret, TLS_MASTER_SECRET_SIZE, "key expansion",
         random, sizeof(random), context->keyBlock, keyBlockLen);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Export keying material per RFC 5705 standard
 * @param[in] context Pointer to the TLS context
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] useContextValue Specifies whether upper-layer context should
 *   be used when exporting keying material
 * @param[in] contextValue Pointer to the upper-layer context
 * @param[in] contextValueLen Length of the upper-layer context
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tlsExportKeyingMaterial(TlsContext *context, const char_t *label,
   bool_t useContextValue, const uint8_t *contextValue,
   size_t contextValueLen, uint8_t *output, size_t outputLen)
{
   error_t error;
   size_t n;
   uint8_t *seed;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(label == NULL || output == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the upper-layer context is valid
   if(contextValue == NULL && contextValueLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Calculate the length of the seed
   n = 2 * TLS_RANDOM_SIZE;

   //Check whether a context is provided
   if(useContextValue)
      n += contextValueLen + 2;

   //Allocate a memory buffer to hold the seed
   seed = tlsAllocMem(n);
   //Failed to allocate memory?
   if(seed == NULL)
      return ERROR_OUT_OF_RESOURCES;

   //Concatenate client_random and server_random values
   osMemcpy(seed, context->clientRandom, TLS_RANDOM_SIZE);
   osMemcpy(seed + 32, context->serverRandom, TLS_RANDOM_SIZE);

   //Check whether a context is provided
   if(useContextValue)
   {
      //The context_value_length is encoded as an unsigned, 16-bit quantity
      //representing the length of the context value
      STORE16BE(contextValueLen, seed + 64);

      //Copy the context value provided by the application using the exporter
      osMemcpy(seed + 66, contextValue, contextValueLen);
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //TLS 1.0 and 1.1 use a PRF that combines MD5 and SHA-1
      error = tlsPrf(context->masterSecret, TLS_MASTER_SECRET_SIZE,
         label, seed, n, output, outputLen);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //Make sure the PRF hash algorithm is valid
      if(context->cipherSuite.prfHashAlgo != NULL)
      {
         //TLS 1.2 PRF uses SHA-256 or a stronger hash algorithm as the core
         //function in its construction
         error = tls12Prf(context->cipherSuite.prfHashAlgo, context->masterSecret,
            TLS_MASTER_SECRET_SIZE, label, seed, n, output, outputLen);
      }
      else
      {
         //Invalid PRF hash algorithm
         error = ERROR_FAILURE;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      const HashAlgo *hash;
      uint8_t secret[TLS_MAX_HKDF_DIGEST_SIZE];
      uint8_t digest[TLS_MAX_HKDF_DIGEST_SIZE];

      //The hash function used by HKDF is the cipher suite hash algorithm
      hash = context->cipherSuite.prfHashAlgo;

      //Make sure the HKDF hash algorithm is valid
      if(hash != NULL)
      {
         //Derive exporter master secret
         error = tls13DeriveSecret(context, context->exporterMasterSecret,
            hash->digestSize, label, "", 0, secret, hash->digestSize);

         //Check status code
         if(!error)
         {
            //Hash context_value input
            error = hash->compute(contextValue, contextValueLen, digest);
         }

         //Check status code
         if(!error)
         {
            //Export keying material
            error = tls13HkdfExpandLabel(context->transportProtocol, hash,
               secret, hash->digestSize, "exporter", digest, hash->digestSize,
               output, outputLen);
         }
      }
      else
      {
         //Invalid HKDF hash algorithm
         error = ERROR_FAILURE;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Release previously allocated memory
   tlsFreeMem(seed);

   //Return status code
   return error;
}


/**
 * @brief Pseudorandom function (TLS 1.0 and 1.1)
 *
 * The pseudorandom function (PRF) takes as input a secret, a seed, and
 * an identifying label and produces an output of arbitrary length. This
 * function is used to expand secrets into blocks of data for the purpose
 * of key generation
 *
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] seed Pointer to the seed
 * @param[in] seedLen Length of the seed
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tlsPrf(const uint8_t *secret, size_t secretLen, const char_t *label,
   const uint8_t *seed, size_t seedLen, uint8_t *output, size_t outputLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   error_t error;
   uint_t i;
   uint_t j;
   size_t labelLen;
   size_t sLen;
   const uint8_t *s1;
   const uint8_t *s2;
   HmacContext *hmacContext;
   uint8_t a[SHA1_DIGEST_SIZE];

   //Allocate a memory buffer to hold the HMAC context
   hmacContext = tlsAllocMem(sizeof(HmacContext));

   //Successful memory allocation?
   if(hmacContext != NULL)
   {
      //Retrieve the length of the label
      labelLen = osStrlen(label);

      //The secret is partitioned into two halves S1 and S2
      //with the possibility of one shared byte
      sLen = (secretLen + 1) / 2;
      //S1 is taken from the first half of the secret
      s1 = secret;
      //S2 is taken from the second half
      s2 = secret + secretLen - sLen;

      //First compute A(1) = HMAC_MD5(S1, label + seed)
      hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, a);

      //Apply the data expansion function P_MD5
      for(i = 0; i < outputLen; )
      {
         //Compute HMAC_MD5(S1, A(i) + label + seed)
         hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
         hmacUpdate(hmacContext, a, MD5_DIGEST_SIZE);
         hmacUpdate(hmacContext, label, labelLen);
         hmacUpdate(hmacContext, seed, seedLen);
         hmacFinal(hmacContext, NULL);

         //Copy the resulting digest
         for(j = 0; i < outputLen && j < MD5_DIGEST_SIZE; i++, j++)
         {
            output[i] = hmacContext->digest[j];
         }

         //Compute A(i + 1) = HMAC_MD5(S1, A(i))
         hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
         hmacUpdate(hmacContext, a, MD5_DIGEST_SIZE);
         hmacFinal(hmacContext, a);
      }

      //First compute A(1) = HMAC_SHA1(S2, label + seed)
      hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, a);

      //Apply the data expansion function P_SHA1
      for(i = 0; i < outputLen; )
      {
         //Compute HMAC_SHA1(S2, A(i) + label + seed)
         hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
         hmacUpdate(hmacContext, a, SHA1_DIGEST_SIZE);
         hmacUpdate(hmacContext, label, labelLen);
         hmacUpdate(hmacContext, seed, seedLen);
         hmacFinal(hmacContext, NULL);

         //Copy the resulting digest
         for(j = 0; i < outputLen && j < SHA1_DIGEST_SIZE; i++, j++)
         {
            output[i] ^= hmacContext->digest[j];
         }

         //Compute A(i + 1) = HMAC_SHA1(S2, A(i))
         hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
         hmacUpdate(hmacContext, a, SHA1_DIGEST_SIZE);
         hmacFinal(hmacContext, a);
      }

      //Free previously allocated memory
      tlsFreeMem(hmacContext);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Pseudorandom function (TLS 1.2)
 *
 * The pseudorandom function (PRF) takes as input a secret, a seed, and
 * an identifying label and produces an output of arbitrary length. This
 * function is used to expand secrets into blocks of data for the purpose
 * of key generation
 *
 * @param[in] hash Hash function used to compute PRF
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] seed Pointer to the seed
 * @param[in] seedLen Length of the seed
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tls12Prf(const HashAlgo *hash, const uint8_t *secret, size_t secretLen,
   const char_t *label, const uint8_t *seed, size_t seedLen, uint8_t *output,
   size_t outputLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   size_t n;
   size_t labelLen;
   HmacContext *hmacContext;
   uint8_t a[MAX_HASH_DIGEST_SIZE];

   //Allocate a memory buffer to hold the HMAC context
   hmacContext = tlsAllocMem(sizeof(HmacContext));

   //Successful memory allocation?
   if(hmacContext != NULL)
   {
      //Retrieve the length of the label
      labelLen = osStrlen(label);

      //First compute A(1) = HMAC_hash(secret, label + seed)
      hmacInit(hmacContext, hash, secret, secretLen);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, a);

      //Apply the data expansion function P_hash
      while(outputLen > 0)
      {
         //Compute HMAC_hash(secret, A(i) + label + seed)
         hmacInit(hmacContext, hash, secret, secretLen);
         hmacUpdate(hmacContext, a, hash->digestSize);
         hmacUpdate(hmacContext, label, labelLen);
         hmacUpdate(hmacContext, seed, seedLen);
         hmacFinal(hmacContext, NULL);

         //Calculate the number of bytes to copy
         n = MIN(outputLen, hash->digestSize);
         //Copy the resulting digest
         osMemcpy(output, hmacContext->digest, n);

         //Compute A(i + 1) = HMAC_hash(secret, A(i))
         hmacInit(hmacContext, hash, secret, secretLen);
         hmacUpdate(hmacContext, a, hash->digestSize);
         hmacFinal(hmacContext, a);

         //Advance data pointer
         output += n;
         //Decrement byte counter
         outputLen -= n;
      }

      //Free previously allocated memory
      tlsFreeMem(hmacContext);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Dump secret key (for debugging purpose only)
 * @param[in] context Pointer to the TLS context
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] secret Pointer to the secret key
 * @param[in] secretLen Length of the secret key, in bytes
 **/

void tlsDumpSecret(TlsContext *context, const char_t *label,
   const uint8_t *secret, size_t secretLen)
{
#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->keyLogCallback != NULL)
   {
      size_t i;
      size_t n;
      char_t buffer[194];

      //Retrieve the length of the label
      n = osStrlen(label);

      //Sanity check
      if((n + 2 * secretLen + 67) <= sizeof(buffer))
      {
         //Copy the identifying label
         osStrncpy(buffer, label, n);

         //Append a space character
         buffer[n++] = ' ';

         //Convert the client random value to a hex string
         for(i = 0; i < 32; i++)
         {
            //Format current byte
            n += osSprintf(buffer + n, "%02" PRIX8, context->clientRandom[i]);
         }

         //Append a space character
         buffer[n++] = ' ';

         //Convert the secret key to a hex string
         for(i = 0; i < secretLen; i++)
         {
            //Format current byte
            n += osSprintf(buffer + n, "%02" PRIX8, secret[i]);
         }

         //Properly terminate the string with a NULL character
         buffer[n] = '\0';

         //Invoke user callback function
         context->keyLogCallback(context, buffer);
      }
   }
#endif
}

#endif
