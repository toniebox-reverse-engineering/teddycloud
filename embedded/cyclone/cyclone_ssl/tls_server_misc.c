/**
 * @file tls_server_misc.c
 * @brief Helper functions for TLS server
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
#include "tls_cipher_suites.h"
#include "tls_server.h"
#include "tls_server_extensions.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_extensions.h"
#include "tls_certificate.h"
#include "tls_signature.h"
#include "tls_cache.h"
#include "tls_ffdhe.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Format PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentityHint(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //Any PSK identity hint defined?
   if(context->pskIdentityHint != NULL)
   {
      //Determine the length of the PSK identity hint
      n = osStrlen(context->pskIdentityHint);
      //Copy PSK identity hint
      osMemcpy(pskIdentityHint->value, context->pskIdentityHint, n);
   }
   else
#endif
   {
      //No PSK identity hint is provided
      n = 0;
   }

   //The PSK identity hint is preceded by a 2-byte length field
   pskIdentityHint->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerKeyParams(TlsContext *context,
   uint8_t *p, size_t *written)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_DH_ANON_KE_SUPPORT == ENABLED || TLS_DHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_DHE_DSS_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      size_t n;

#if (TLS_FFDHE_SUPPORT == ENABLED)
      const TlsFfdheGroup *ffdheGroup;

      //Get the FFDHE parameters that match the specified named group
      ffdheGroup = tlsGetFfdheGroup(context, context->namedGroup);

      //Valid FFDHE group?
      if(ffdheGroup != NULL)
      {
         //Load FFDHE parameters
         error = tlsLoadFfdheParameters(&context->dhContext.params, ffdheGroup);
      }
#endif

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = dhGenerateKeyPair(&context->dhContext, context->prngAlgo,
            context->prngContext);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("Diffie-Hellman parameters:\r\n");
         TRACE_DEBUG("  Prime modulus:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.params.p);
         TRACE_DEBUG("  Generator:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.params.g);
         TRACE_DEBUG("  Server public value:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.ya);

         //Encode the prime modulus to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.p, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the generator to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.g, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the server's public value to an opaque vector
         error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Adjust the length of the key exchange parameters
         *written += n;
      }
   }
   else
#endif
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;
      const EcCurveInfo *curveInfo;

      //Retrieve the elliptic curve to be used
      curveInfo = tlsGetCurveInfo(context, context->namedGroup);

      //Make sure the elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);

         //Check status code
         if(!error)
         {
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
            //Any registered callback?
            if(context->ecdhCallback != NULL)
            {
               //Invoke user callback function
               error = context->ecdhCallback(context);
            }
            else
#endif
            {
               //No callback function defined
               error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
            }

            //Check status code
            if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
            {
               //Generate an ephemeral key pair
               error = ecdhGenerateKeyPair(&context->ecdhContext,
                  context->prngAlgo, context->prngContext);
            }
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  Server public key X:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.q.x);
            TRACE_DEBUG("  Server public key Y:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.q.y);

            //Set the type of the elliptic curve domain parameters
            *p = TLS_EC_CURVE_TYPE_NAMED_CURVE;

            //Advance data pointer
            p += sizeof(uint8_t);
            //Total number of bytes that have been written
            *written += sizeof(uint8_t);

            //Write elliptic curve identifier
            STORE16BE(context->namedGroup, p);

            //Advance data pointer
            p += sizeof(uint16_t);
            //Total number of bytes that have been written
            *written += sizeof(uint16_t);

            //Write server's public key
            error = tlsWriteEcPoint(&context->ecdhContext.params,
               &context->ecdhContext.qa.q, p, &n);
         }

         //Check status code
         if(!error)
         {
            //Advance data pointer
            p +=n;
            //Total number of bytes that have been written
            *written += n;
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_FAILURE;
      }
   }
   else
#endif
   //Any other exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_FAILURE;
   }
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Sign server's key exchange parameters (TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Output stream where to write the digital signature
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsGenerateServerKeySignature(TlsContext *context,
   TlsDigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(context->cert->type == TLS_CERT_RSA_SIGN)
   {
      Md5Context *md5Context;
      Sha1Context *sha1Context;
      RsaPrivateKey privateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Allocate a memory buffer to hold the MD5 context
      md5Context = tlsAllocMem(sizeof(Md5Context));

      //Successful memory allocation?
      if(md5Context != NULL)
      {
         //Compute MD5(ClientHello.random + ServerHello.random +
         //ServerKeyExchange.params)
         md5Init(md5Context);
         md5Update(md5Context, context->clientRandom, TLS_RANDOM_SIZE);
         md5Update(md5Context, context->serverRandom, TLS_RANDOM_SIZE);
         md5Update(md5Context, params, paramsLen);
         md5Final(md5Context, context->serverVerifyData);

         //Release previously allocated memory
         tlsFreeMem(md5Context);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }

      //Check status code
      if(!error)
      {
         //Allocate a memory buffer to hold the SHA-1 context
         sha1Context = tlsAllocMem(sizeof(Sha1Context));

         //Successful memory allocation?
         if(sha1Context != NULL)
         {
            //Compute SHA(ClientHello.random + ServerHello.random +
            //ServerKeyExchange.params)
            sha1Init(sha1Context);
            sha1Update(sha1Context, context->clientRandom, TLS_RANDOM_SIZE);
            sha1Update(sha1Context, context->serverRandom, TLS_RANDOM_SIZE);
            sha1Update(sha1Context, params, paramsLen);
            sha1Final(sha1Context, context->serverVerifyData + MD5_DIGEST_SIZE);

            //Release previously allocated memory
            tlsFreeMem(sha1Context);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }

      //Check status code
      if(!error)
      {
         //Decode the PEM structure that holds the RSA private key
         error = pemImportRsaPrivateKey(context->cert->privateKey,
            context->cert->privateKeyLen, &privateKey);
      }

      //Check status code
      if(!error)
      {
         //Sign the key exchange parameters using RSA
         error = tlsGenerateRsaSignature(&privateKey,
            context->serverVerifyData, signature->value, written);
      }

      //Release previously allocated resources
      rsaFreePrivateKey(&privateKey);
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(context->cert->type == TLS_CERT_DSS_SIGN)
   {
      Sha1Context *sha1Context;

      //Allocate a memory buffer to hold the SHA-1 context
      sha1Context = tlsAllocMem(sizeof(Sha1Context));

      //Successful memory allocation?
      if(sha1Context != NULL)
      {
         //Compute SHA(ClientHello.random + ServerHello.random +
         //ServerKeyExchange.params)
         sha1Init(sha1Context);
         sha1Update(sha1Context, context->clientRandom, TLS_RANDOM_SIZE);
         sha1Update(sha1Context, context->serverRandom, TLS_RANDOM_SIZE);
         sha1Update(sha1Context, params, paramsLen);
         sha1Final(sha1Context, context->serverVerifyData);

         //Release previously allocated memory
         tlsFreeMem(sha1Context);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }

      //Check status code
      if(!error)
      {
         //Sign the key exchange parameters using DSA
         error = tlsGenerateDsaSignature(context, context->serverVerifyData,
            SHA1_DIGEST_SIZE, signature->value, written);
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(context->cert->type == TLS_CERT_ECDSA_SIGN)
   {
      Sha1Context *sha1Context;

      //Allocate a memory buffer to hold the SHA-1 context
      sha1Context = tlsAllocMem(sizeof(Sha1Context));

      //Successful memory allocation?
      if(sha1Context != NULL)
      {
         //Compute SHA(ClientHello.random + ServerHello.random +
         //ServerKeyExchange.params)
         sha1Init(sha1Context);
         sha1Update(sha1Context, context->clientRandom, TLS_RANDOM_SIZE);
         sha1Update(sha1Context, context->serverRandom, TLS_RANDOM_SIZE);
         sha1Update(sha1Context, params, paramsLen);
         sha1Final(sha1Context, context->serverVerifyData);

         //Release previously allocated memory
         tlsFreeMem(sha1Context);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }

      //Check status code
      if(!error)
      {
         //Sign the key exchange parameters using ECDSA
         error = tlsGenerateEcdsaSignature(context, context->serverVerifyData,
            SHA1_DIGEST_SIZE, signature->value, written);
      }
   }
   else
#endif
   //Invalid certificate?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(!error)
   {
      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the signature
      *written += sizeof(TlsDigitalSignature);
   }
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Sign server's key exchange parameters (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Output stream where to write the digital signature
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls12GenerateServerKeySignature(TlsContext *context,
   Tls12DigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //RSA, DSA or ECDSA signature scheme?
   if(context->signAlgo == TLS_SIGN_ALGO_RSA ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256 ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384 ||
      context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512 ||
      context->signAlgo == TLS_SIGN_ALGO_DSA ||
      context->signAlgo == TLS_SIGN_ALGO_ECDSA)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Retrieve the hash algorithm used for signing
      if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256)
      {
         //The hashing is intrinsic to the signature algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      }
      else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384)
      {
         //The hashing is intrinsic to the signature algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      }
      else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
      {
         //The hashing is intrinsic to the signature algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      }
      else
      {
         //Select the relevant hash algorithm
         hashAlgo = tlsGetHashAlgo(context->signHashAlgo);
      }

      //Make sure the hash algorithm is supported
      if(hashAlgo != NULL)
      {
         //Allocate a memory buffer to hold the hash context
         hashContext = tlsAllocMem(hashAlgo->contextSize);

         //Successful memory allocation?
         if(hashContext != NULL)
         {
            //Compute hash(ClientHello.random + ServerHello.random +
            //ServerKeyExchange.params)
            hashAlgo->init(hashContext);
            hashAlgo->update(hashContext, context->clientRandom, TLS_RANDOM_SIZE);
            hashAlgo->update(hashContext, context->serverRandom, TLS_RANDOM_SIZE);
            hashAlgo->update(hashContext, params, paramsLen);
            hashAlgo->final(hashContext, NULL);

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
            //RSA signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_RSA)
            {
               RsaPrivateKey privateKey;

               //Initialize RSA private key
               rsaInitPrivateKey(&privateKey);

               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Decode the PEM structure that holds the RSA private key
               error = pemImportRsaPrivateKey(context->cert->privateKey,
                  context->cert->privateKeyLen, &privateKey);

               //Check status code
               if(!error)
               {
                  //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
                  error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                     hashContext->digest, signature->value, written);
               }

               //Release previously allocated resources
               rsaFreePrivateKey(&privateKey);
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSA-PSS signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
            {
               RsaPrivateKey privateKey;

               //Initialize RSA private key
               rsaInitPrivateKey(&privateKey);

               //Set the relevant signature algorithm
               signature->algorithm.signature = context->signAlgo;
               signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;

               //Decode the PEM structure that holds the RSA private key
               error = pemImportRsaPrivateKey(context->cert->privateKey,
                  context->cert->privateKeyLen, &privateKey);

               //Check status code
               if(!error)
               {
                  //Generate RSA signature (RSASSA-PSS signature scheme)
                  error = rsassaPssSign(context->prngAlgo, context->prngContext,
                     &privateKey, hashAlgo, hashAlgo->digestSize,
                     hashContext->digest, signature->value, written);
               }

               //Release previously allocated resources
               rsaFreePrivateKey(&privateKey);
            }
            else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_DSA)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_DSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using DSA
               error = tlsGenerateDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
            }
            else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_ECDSA)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_ECDSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using ECDSA
               error = tlsGenerateEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
            }
            else
#endif
            //Invalid signature scheme?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }

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
      {
         //Hash algorithm not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED)
   //EdDSA signature scheme?
   if(context->signAlgo == TLS_SIGN_ALGO_ED25519 ||
      context->signAlgo == TLS_SIGN_ALGO_ED448)
   {
      EddsaMessageChunk messageChunks[4];

      //Data to be signed is run through the EdDSA algorithm without
      //pre-hashing
      messageChunks[0].buffer = context->clientRandom;
      messageChunks[0].length = TLS_RANDOM_SIZE;
      messageChunks[1].buffer = context->serverRandom;
      messageChunks[1].length = TLS_RANDOM_SIZE;
      messageChunks[2].buffer = params;
      messageChunks[2].length = paramsLen;
      messageChunks[3].buffer = NULL;
      messageChunks[3].length = 0;

#if (TLS_ED25519_SUPPORT == ENABLED)
      //Ed25519 signature scheme?
      if(context->signAlgo == TLS_SIGN_ALGO_ED25519)
      {
         //The hashing is intrinsic to the signature algorithm
         signature->algorithm.signature = TLS_SIGN_ALGO_ED25519;
         signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;

         //Sign the key exchange parameters using EdDSA
         error = tlsGenerateEddsaSignature(context, messageChunks,
            signature->value, written);
      }
      else
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
      //Ed448 signature scheme?
      if(context->signAlgo == TLS_SIGN_ALGO_ED448)
      {
         //The hashing is intrinsic to the signature algorithm
         signature->algorithm.signature = TLS_SIGN_ALGO_ED448;
         signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;

         //Sign the key exchange parameters using EdDSA
         error = tlsGenerateEddsaSignature(context, messageChunks,
            signature->value, written);
      }
      else
#endif
      //Invalid signature scheme?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
   //Invalid signature scheme?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(!error)
   {
      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the message
      *written += sizeof(Tls12DigitalSignature);
   }
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Check whether the ClientHello includes any SCSV cipher suites
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @return Error code
 **/

error_t tlsCheckSignalingCipherSuiteValues(TlsContext *context,
   const TlsCipherSuites *cipherSuites)
{
   error_t error;
   uint_t i;
   uint_t n;
   uint16_t serverVersion;

   //Initialize status code
   error = NO_ERROR;

   //Get the highest version supported by the implementation (legacy version)
   serverVersion = MIN(context->versionMax, TLS_VERSION_1_2);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Translate TLS version into DTLS version
      serverVersion = dtlsTranslateVersion(serverVersion);
   }
#endif

   //Get the number of cipher suite identifiers present in the list
   n = ntohs(cipherSuites->length) / 2;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Loop through the list of cipher suite identifiers
   for(i = 0; i < n; i++)
   {
      //Debug message
      TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", ntohs(cipherSuites->value[i]),
         tlsGetCipherSuiteName(ntohs(cipherSuites->value[i])));

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
      {
         //Initial handshake?
         if(context->clientVerifyDataLen == 0)
         {
            //Set the secure_renegotiation flag to TRUE
            context->secureRenegoFlag = TRUE;
         }
         //Secure renegotiation?
         else
         {
            //When a ClientHello is received, the server must verify that it
            //does not contain the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If
            //the SCSV is present, the server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
            break;
         }
      }
      else
#endif
      //TLS_FALLBACK_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_FALLBACK_SCSV)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Test if the highest protocol version supported by the server is
            //higher than the version indicated by the client
            if(serverVersion < context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               error = ERROR_INAPPROPRIATE_FALLBACK;
               break;
            }
         }
         else
#endif
         //TLS protocol?
         {
            //Test if the highest protocol version supported by the server is
            //higher than the version indicated by the client
            if(serverVersion > context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               error = ERROR_INAPPROPRIATE_FALLBACK;
               break;
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Resume TLS session via session ID
 * @param[in] context Pointer to the TLS context
 * @param[in] sessionId Pointer to the session ID offered by the client
 * @param[in] sessionIdLen Length of the session ID, in bytes
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsResumeStatefulSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, const TlsCipherSuites *cipherSuites,
   const TlsHelloExtensions *extensions)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2 && \
   TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether session caching is supported
   if(context->cache != NULL)
   {
      uint_t i;
      uint_t n;
      TlsSessionState *session;

      //If the session ID was non-empty, the server will look in its session
      //cache for a match
      session = tlsFindCache(context->cache, sessionId, sessionIdLen);

      //Matching session found?
      if(session != NULL)
      {
         //Whenever a client already knows the highest protocol version known
         //to a server (for example, when resuming a session), it should
         //initiate the connection in that native protocol
         if(session->version != context->version)
         {
            session = NULL;
         }
      }

      //Matching session found?
      if(session != NULL)
      {
         //Get the total number of cipher suites offered by the client
         n = ntohs(cipherSuites->length) / 2;

         //Loop through the list of cipher suite identifiers
         for(i = 0; i < n; i++)
         {
            //Matching cipher suite?
            if(ntohs(cipherSuites->value[i]) == session->cipherSuite)
            {
               break;
            }
         }

         //If the cipher suite is not present in the list cipher suites offered
         //by the client, the server must not perform the abbreviated handshake
         if(i >= n)
         {
            session = NULL;
         }
      }

#if (TLS_SNI_SUPPORT == ENABLED)
      //Matching session found?
      if(session != NULL)
      {
         //ServerName extension found?
         if(session->serverName != NULL && context->serverName != NULL)
         {
            //A server that implements this extension must not accept the
            //request to resume the session if the ServerName extension contains
            //a different name (refer to RFC 6066, section 3)
            if(osStrcmp(session->serverName, context->serverName))
            {
               //Instead, the server proceeds with a full handshake to establish
               //a new session
               session = NULL;
            }
         }
         else if(session->serverName == NULL && context->serverName == NULL)
         {
            //The ServerName extension is not present
         }
         else
         {
            //The server proceeds with a full handshake to establish a new
            //session
            session = NULL;
         }
      }
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //Matching session found?
      if(session != NULL)
      {
         //ExtendedMasterSecret extension found?
         if(extensions->extendedMasterSecret != NULL)
         {
            //If the original session did not use the ExtendedMasterSecret
            //extension but the new ClientHello contains the extension, then
            //the server must not perform the abbreviated handshake
            if(!session->extendedMasterSecret)
            {
               session = NULL;
            }
         }
      }
#endif

      //Check whether the server has decided to resume a previous session
      if(session != NULL)
      {
         //Perform abbreviated handshake
         context->resume = TRUE;

         //Restore cached session parameters
         error = tlsRestoreSessionId(context, session);

         //Check status code
         if(!error)
         {
            //Select the relevant cipher suite
            error = tlsSelectCipherSuite(context, session->cipherSuite);
         }
      }
      else
      {
         //Perform a full handshake
         context->resume = FALSE;

         //Generate a new random session ID
         error = tlsGenerateSessionId(context, 32);
      }
   }
   else
#endif
   {
      //Perform a full handshake
      context->resume = FALSE;
      //The session cannot be resumed
      context->sessionIdLen = 0;
   }

   //Return status code
   return error;
}


/**
 * @brief Resume TLS session via session ticket
 * @param[in] context Pointer to the TLS context
 * @param[in] sessionId Pointer to the session ID offered by the client
 * @param[in] sessionIdLen Length of the session ID, in bytes
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsResumeStatelessSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, const TlsCipherSuites *cipherSuites,
   const TlsHelloExtensions *extensions)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2 && \
   TLS_TICKET_SUPPORT == ENABLED)
   //The client indicates that it supports the ticket mechanism by including
   //a SessionTicket extension in the ClientHello message
   if(context->sessionTicketExtReceived)
   {
      uint_t i;
      uint_t n;
      size_t length;
      systime_t serverTicketAge;
      TlsPlaintextSessionState *state;

      //Retrieve the length of the ticket
      length = ntohs(extensions->sessionTicket->length);

      //Check the length of the ticket
      if(length > 0 && length <= TLS_MAX_TICKET_SIZE)
      {
         //Allocate a buffer to store the decrypted state information
         state = tlsAllocMem(length);

         //Successful memory allocation?
         if(state != NULL)
         {
            //Make sure a valid callback has been registered
            if(context->ticketDecryptCallback != NULL)
            {
               //Decrypt the received ticket
               error = context->ticketDecryptCallback(context,
                  extensions->sessionTicket->value, length, (uint8_t *) state,
                  &length, context->ticketParam);
            }
            else
            {
               //Report an error
               error = ERROR_FAILURE;
            }

            //Valid ticket?
            if(!error)
            {
               //Check the length of the decrypted ticket
               if(length == sizeof(TlsPlaintextSessionState))
               {
                  //The ticket mechanism applies to TLS 1.0, TLS 1.1 and TLS 1.2
                  if(state->version != context->version)
                  {
                     //The ticket is not valid
                     error = ERROR_INVALID_TICKET;
                  }

                  //Compute the time since the ticket was issued
                  serverTicketAge = osGetSystemTime() - state->ticketTimestamp;

                  //Verify ticket's validity
                  if(serverTicketAge >= (state->ticketLifetime * 1000))
                  {
                     //The ticket is not valid
                     error = ERROR_INVALID_TICKET;
                  }

                  //Get the total number of cipher suites offered by the client
                  n = ntohs(cipherSuites->length) / 2;

                  //Loop through the list of cipher suite identifiers
                  for(i = 0; i < n; i++)
                  {
                     //Matching cipher suite?
                     if(ntohs(cipherSuites->value[i]) == state->cipherSuite)
                     {
                        break;
                     }
                  }

                  //If the cipher suite is not present in the list cipher suites
                  //offered by the client, the server must not perform the
                  //abbreviated handshake
                  if(i >= n)
                  {
                     //The ticket is not valid
                     error = ERROR_INVALID_TICKET;
                  }

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
                  //ExtendedMasterSecret extension found?
                  if(extensions->extendedMasterSecret != NULL)
                  {
                     //If the original session did not use the ExtendedMasterSecret
                     //extension but the new ClientHello contains the extension,
                     //then the server must not perform the abbreviated handshake
                     if(!state->extendedMasterSecret)
                     {
                        //The ticket is not valid
                        error = ERROR_INVALID_TICKET;
                     }
                  }
#endif
               }
               else
               {
                  //The ticket is malformed
                  error = ERROR_INVALID_TICKET;
               }
            }

            //Check status code
            if(!error)
            {
               //The ticket mechanism may be used with any TLS ciphersuite
               error = tlsSelectCipherSuite(context, state->cipherSuite);
            }

            //Check status code
            if(!error)
            {
               //Restore master secret
               osMemcpy(context->masterSecret, state->secret,
                  TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
               //Extended master secret computation
               context->emsExtReceived = state->extendedMasterSecret;
#endif
            }

            //Release state information
            osMemset(state, 0, length);
            tlsFreeMem(state);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else
      {
         //The extension will be empty if the client does not already possess
         //a ticket for the server (refer to RFC 5077, section 3.1)
         error = ERROR_INVALID_TICKET;
      }

      //Valid ticket?
      if(!error)
      {
         //Perform abbreviated handshake
         context->resume = TRUE;

         //If the server accepts the ticket and the session ID is not empty,
         //then it must respond with the same session ID present in the
         //ClientHello. This allows the client to easily differentiate when
         //the server is resuming a session from when it is falling back to
         //a full handshake (refer to RFC 5077, section 3.4)
         osMemcpy(context->sessionId, sessionId, sessionIdLen);
         context->sessionIdLen = sessionIdLen;

         //If the server successfully verifies the client's ticket, then it may
         //renew the ticket by including a NewSessionTicket handshake message
         //after the ServerHello
         context->sessionTicketExtSent = FALSE;
      }
      else
      {
         //If a server is planning on issuing a session ticket to a client that
         //does not present one, it should include an empty Session ID in the
         //ServerHello
         context->sessionIdLen = 0;

         //The server uses a zero-length SessionTicket extension to indicate to the
         //client that it will send a new session ticket using the NewSessionTicket
         //handshake message
         context->sessionTicketExtSent = TRUE;
      }
   }
   else
#endif
   {
      //No valid ticket received
      error = ERROR_NO_TICKET;
   }

   //Return status code
   return error;
}


/**
 * @brief Version negotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] clientVersion Highest version number supported by the client (legacy version)
 * @param[in] supportedVersionList Pointer to the SupportedVersions extensions
 * @return Error code
 **/

error_t tlsNegotiateVersion(TlsContext *context, uint16_t clientVersion,
   const TlsSupportedVersionList *supportedVersionList)
{
   error_t error;
   uint16_t serverVersion;

   //Get the highest version supported by the implementation
   serverVersion = context->versionMax;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //In DTLS 1.2, the client can indicate its version preferences in the
      //SupportedVersions extension
      if(supportedVersionList != NULL && context->versionMax >= TLS_VERSION_1_2)
      {
         //If the SupportedVersions extension is present in the ClientHello,
         //servers must only select a version of DTLS present in that extension
         error = dtlsParseClientSupportedVersionsExtension(context,
            (DtlsSupportedVersionList *) supportedVersionList);
      }
      else
      {
         //If the SupportedVersions extension is not present, servers must
         //negotiate DTLS 1.2 or prior
         serverVersion = MIN(serverVersion, TLS_VERSION_1_2);

         //Translate TLS version into DTLS version
         serverVersion = dtlsTranslateVersion(serverVersion);

         //If a DTLS server receives a ClientHello containing a version number
         //greater than the highest version supported by the server, it must
         //reply according to the highest version supported by the server
         serverVersion = MAX(serverVersion, clientVersion);

         //Set the DTLS version to be used
         error = dtlsSelectVersion(context, serverVersion);
      }
   }
   else
#endif
   //TLS protocol?
   {
      //In TLS 1.2, the client can indicate its version preferences in the
      //SupportedVersions extension
      if(supportedVersionList != NULL && context->versionMax >= TLS_VERSION_1_2)
      {
         //If the SupportedVersions extension is present in the ClientHello,
         //servers must only select a version of TLS present in that extension
         error = tlsParseClientSupportedVersionsExtension(context,
            supportedVersionList);

         //Check status code
         if(!error)
         {
            //Check whether TLS 1.3 has been negotiated
            if(context->version == TLS_VERSION_1_3)
            {
               //The legacy_version field must be set to 0x0303, which is the
               //version number for TLS 1.2
               if(clientVersion < TLS_VERSION_1_2)
               {
                  error = ERROR_VERSION_NOT_SUPPORTED;
               }
            }
         }
      }
      else
      {
         //If the SupportedVersions extension is not present, servers must
         //negotiate TLS 1.2 or prior, even if the legacy_version of the
         //ClientHello is 0x0304 or later (refer to RFC 8446, section 4.2.1)
         serverVersion = MIN(serverVersion, TLS_VERSION_1_2);

         //If a TLS server receives a ClientHello containing a version number
         //greater than the highest version supported by the server, it must
         //reply according to the highest version supported by the server
         serverVersion = MIN(serverVersion, clientVersion);

         //Set the TLS version to be used
         error = tlsSelectVersion(context, serverVersion);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Cipher suite negotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] hashAlgo Desired KDF hash algorithm
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsNegotiateCipherSuite(TlsContext *context, const HashAlgo *hashAlgo,
   const TlsCipherSuites *cipherSuites, TlsHelloExtensions *extensions)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t k;
   uint_t n;

   //Initialize status code
   error = ERROR_HANDSHAKE_FAILED;

   //If no SignatureAlgorithmsCert extension is present in the ClientHello
   //message, then the SignatureAlgorithms extension also applies to signatures
   //appearing in certificates (RFC 8446, section 4.2.3)
   if(extensions->certSignAlgoList == NULL)
   {
      extensions->certSignAlgoList = extensions->signAlgoList;
   }

   //Get the total number of cipher suites offered by the client
   n = ntohs(cipherSuites->length) / 2;

   //Select the most appropriate cipher suite (2-pass process)
   for(k = 0; k < 2 && error; k++)
   {
      //Any preferred cipher suites?
      if(context->numCipherSuites > 0)
      {
         //Loop through the list of allowed cipher suites (most preferred first)
         for(i = 0; i < context->numCipherSuites && error; i++)
         {
            //Loop through the list of cipher suites offered by the client
            for(j = 0; j < n && error; j++)
            {
               //If the list contains cipher suites the server does not
               //recognize, support, or wish to use, the server must ignore
               //those cipher suites, and process the remaining ones as usual
               if(context->cipherSuites[i] == ntohs(cipherSuites->value[j]))
               {
                  //Select current cipher suite
                  error = tlsSelectCipherSuite(context, context->cipherSuites[i]);

                  //If a KDF hash algorithm has been specified, the server must
                  //select a compatible cipher suite
                  if(!error && hashAlgo != NULL)
                  {
                     //Make sure the selected cipher suite is compatible
                     if(context->cipherSuite.prfHashAlgo != hashAlgo)
                     {
                        error = ERROR_HANDSHAKE_FAILED;
                     }
                  }

                  //Check status code
                  if(!error)
                  {
                     //Select the group to be used when performing (EC)DHE key
                     //exchange
                     error = tlsSelectGroup(context, extensions->supportedGroupList);
                  }

                  //Check status code
                  if(!error)
                  {
                     //Select the appropriate certificate
                     error = tlsSelectCertificate(context, extensions);
                  }
               }
            }
         }
      }
      else
      {
         //The cipher suite list contains the combinations of cryptographic
         //algorithms supported by the client in order of the client's preference
         for(j = 0; j < n && error; j++)
         {
            //If the list contains cipher suites the server does not recognize,
            //support, or wish to use, the server must ignore those cipher suites,
            //and process the remaining ones as usual
            error = tlsSelectCipherSuite(context, ntohs(cipherSuites->value[j]));

            //If a KDF hash algorithm has been specified, the server must select
            //a compatible cipher suite
            if(!error && hashAlgo != NULL)
            {
               //Make sure the selected cipher suite is compatible
               if(context->cipherSuite.prfHashAlgo != hashAlgo)
               {
                  error = ERROR_HANDSHAKE_FAILED;
               }
            }

            //Check status code
            if(!error)
            {
               //Select the group to be used when performing (EC)DHE key exchange
               error = tlsSelectGroup(context, extensions->supportedGroupList);
            }

            //Check status code
            if(!error)
            {
               //Select the appropriate certificate
               error = tlsSelectCertificate(context, extensions);
            }
         }
      }

      //The second pass relaxes the constraints
      extensions->certSignAlgoList = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the group to be used when performing (EC)DHE key exchange
 * @param[in] context Pointer to the TLS context
 * @param[in] groupList List of named groups supported by the client
 * @return Error code
 **/

error_t tlsSelectGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      //ECC cipher suite?
      if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
      {
         //One of the proposed ECC cipher suites must be negotiated only if the
         //server can successfully complete the handshake while using the curves
         //and point formats supported by the client
         error = tlsSelectEcdheGroup(context, groupList);
      }
#if (TLS_FFDHE_SUPPORT == ENABLED)
      //FFDHE cipher suite?
      else if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
      {
         //If none of the client-proposed FFDHE groups are known and acceptable
         //to the server, then the server must not select an FFDHE cipher suite
         error = tlsSelectFfdheGroup(context, groupList);
      }
#endif
      else
      {
         //The selected cipher suite does not provide forward secrecy
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Select the named curve to be used when performing ECDHE key exchange
 * @param[in] context Pointer to the TLS context
 * @param[in] groupList List of named groups supported by the peer
 * @return Error code
 **/

error_t tlsSelectEcdheGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;
   uint16_t namedGroup;

   //Initialize status code
   error = ERROR_HANDSHAKE_FAILED;

   //Reset the named group to its default value
   context->namedGroup = TLS_GROUP_NONE;

   //Check whether a list of named groups is offered by the client
   if(groupList != NULL)
   {
      //Get the number of named groups present in the list
      n = ntohs(groupList->length) / sizeof(uint16_t);

      //Any preferred groups?
      if(context->numSupportedGroups > 0)
      {
         //Loop through the list of allowed groups (most preferred first)
         for(i = 0; i < context->numSupportedGroups && error; i++)
         {
            //Loop through the list of named groups the client supports
            for(j = 0; j < n && error; j++)
            {
               //Convert the named group to host byte order
               namedGroup = ntohs(groupList->value[j]);

               //The named group to be used when performing ECDH key exchange
               //must be one of those present in the SupportedGroups extension
               if(context->supportedGroups[i] == namedGroup)
               {
                  //Acceptable elliptic curve found?
                  if(tlsGetCurveInfo(context, namedGroup) != NULL)
                  {
                     //Save the named curve
                     context->namedGroup = namedGroup;
                     error = NO_ERROR;
                  }
               }
            }
         }
      }
      else
      {
         //The named group to be used when performing ECDH key exchange must
         //be one of those present in the SupportedGroups extension
         for(j = 0; j < n && error; j++)
         {
            //Convert the named group to host byte order
            namedGroup = ntohs(groupList->value[j]);

            //Acceptable elliptic curve found?
            if(tlsGetCurveInfo(context, namedGroup) != NULL)
            {
               //Save the named curve
               context->namedGroup = namedGroup;
               error = NO_ERROR;
            }
         }
      }
   }
   else
   {
      //A client that proposes ECC cipher suites may choose not to include
      //the SupportedGroups extension. In this case, the server is free to
      //choose any one of the elliptic curves it supports
      if(tlsGetCurveInfo(context, TLS_GROUP_SECP256R1) != NULL)
      {
         //Select secp256r1 elliptic curve
         context->namedGroup = TLS_GROUP_SECP256R1;
         error = NO_ERROR;
      }
      else if(tlsGetCurveInfo(context, TLS_GROUP_SECP384R1) != NULL)
      {
         //Select secp384r1 elliptic curve
         context->namedGroup = TLS_GROUP_SECP384R1;
         error = NO_ERROR;
      }
      else
      {
         //Just for sanity
         context->namedGroup = TLS_GROUP_NONE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate selection process
 * @param[in] context Pointer to the TLS context
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsSelectCertificate(TlsContext *context,
   const TlsHelloExtensions *extensions)
{
   error_t error;
   uint_t i;
   uint_t n;
   bool_t acceptable;
   uint8_t certTypes[2];

   //Initialize status code
   error = NO_ERROR;

   //Number of certificate types
   n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      //The server requires a valid certificate whenever the agreed-upon key
      //exchange method uses certificates for authentication
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //RSA, DHE_RSA, ECDHE_RSA and RSA_PSK key exchange methods require
         //an RSA certificate
         certTypes[n++] = TLS_CERT_RSA_SIGN;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_DH_RSA)
      {
         //In DH_RSA, the server's certificate must contain a Diffie-Hellman
         //public key and be signed with RSA
         certTypes[n++] = TLS_CERT_RSA_FIXED_DH;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_RSA)
      {
         //In ECDH_RSA, the server's certificate must contain an ECDH-capable
         //public key and be signed with RSA
         certTypes[n++] = TLS_CERT_RSA_FIXED_ECDH;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
      {
         //DHE_DSS key exchange method requires a DSA certificate
         certTypes[n++] = TLS_CERT_DSS_SIGN;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_DH_DSS)
      {
         //In DH_DSS, the server's certificate must contain a Diffie-Hellman
         //public key and be signed with DSA
         certTypes[n++] = TLS_CERT_DSS_FIXED_DH;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
      {
         //ECDHE_ECDSA key exchange method requires an ECDSA certificate
         certTypes[n++] = TLS_CERT_ECDSA_SIGN;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ECDSA)
      {
         //In ECDH_ECDSA, the server's certificate must contain an ECDH-capable
         //public key and be signed with ECDSA
         certTypes[n++] = TLS_CERT_ECDSA_FIXED_ECDH;
      }
      else
      {
         //DH_anon and ECDH_anon key exchange methods do not require any
         //certificate
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //If PSK is not being used, then (EC)DHE and certificate-based
      //authentication are always used
      if(context->selectedIdentity < 0)
      {
         //TLS 1.3 removes support for DSA certificates
         certTypes[n++] = TLS_CERT_RSA_SIGN;
         certTypes[n++] = TLS_CERT_ECDSA_SIGN;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Abort certificate selection process
      error = ERROR_INVALID_VERSION;
   }

   //Check whether a certificate is required
   if(n > 0)
   {
      //Reset currently selected certificate
      context->cert = NULL;

      //Loop through the list of available certificates
      for(i = 0; i < context->numCerts && context->cert == NULL; i++)
      {
         //Check whether the current certificate is acceptable
         acceptable = tlsIsCertificateAcceptable(context, &context->certs[i],
            certTypes, n, extensions->signAlgoList, extensions->certSignAlgoList,
            extensions->supportedGroupList, NULL);

         //The certificate must be appropriate for the negotiated cipher
         //suite and any negotiated extensions
         if(acceptable)
         {
            //The hash algorithm to be used when generating signatures must
            //be one of those present in the SignatureAlgorithms extension
            error = tlsSelectSignatureScheme(context, &context->certs[i],
               extensions->signAlgoList);

            //Check status code
            if(!error)
            {
               //If all the requirements were met, the certificate can be
               //used in conjunction with the selected cipher suite
               context->cert = &context->certs[i];
            }
         }
      }

      //Do not accept the specified cipher suite unless a suitable
      //certificate has been found
      if(context->cert == NULL)
      {
         error = ERROR_NO_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse the list of compression methods supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] compressMethods List of compression methods
 * @return Error code
 **/

error_t tlsParseCompressMethods(TlsContext *context,
   const TlsCompressMethods *compressMethods)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = ERROR_ILLEGAL_PARAMETER;

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //The list of the compression methods supported by the client is sorted
      //by client preference
      for(i = 0; i < compressMethods->length && error; i++)
      {
         //The CRIME exploit takes advantage of TLS compression, so conservative
         //implementations do not accept compression at the TLS level
         if(compressMethods->value[i] == TLS_COMPRESSION_METHOD_NULL)
         {
            error = NO_ERROR;
         }
      }
   }
   else
   {
      //For every TLS 1.3 ClientHello, this vector must contain exactly one
      //byte, set to zero which corresponds to the null compression method
      if(compressMethods->length == 1)
      {
         //If a ClientHello is received with any other value in this field,
         //the server must abort the handshake with an illegal_parameter alert
         if(compressMethods->value[0] == TLS_COMPRESSION_METHOD_NULL)
         {
            error = NO_ERROR;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentity(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

   //Malformed ClientKeyExchange message?
   if(length < sizeof(TlsPskIdentity))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsPskIdentity) + ntohs(pskIdentity->length)))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the PSK identity
   n = ntohs(pskIdentity->length);

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //The server selects which key to use depending on the PSK identity
      //provided by the client
      error = context->pskCallback(context, pskIdentity->value, n);
      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the client's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseClientKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

#if (TLS_RSA_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      size_t n;
      uint32_t bad;
      uint16_t version;
      RsaPrivateKey privateKey;
      uint8_t randPremasterSecret[48];

      //Malformed ClientKeyExchange message?
      if(length < 2)
         return ERROR_DECODING_FAILED;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes
      n = LOAD16BE(p);

      //Check the length of the RSA-encrypted premaster secret
      if(n > (length - 2))
         return ERROR_DECODING_FAILED;

      //Save the length of the RSA-encrypted premaster secret
      length = n;
      //Advance the pointer over the length field
      p += 2;
      //Total number of bytes that have been consumed
      *consumed = length + 2;

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the RSA private key
      error = pemImportRsaPrivateKey(context->cert->privateKey,
         context->cert->privateKeyLen, &privateKey);

      //Check status code
      if(!error)
      {
         //Decrypt the premaster secret using the server private key
         error = rsaesPkcs1v15Decrypt(&privateKey, p, length,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }

      //Release RSA private key
      rsaFreePrivateKey(&privateKey);

      //Retrieve the latest version supported by the client. This is used
      //to detect version roll-back attacks
      version = LOAD16BE(context->premasterSecret);

      //The best way to avoid vulnerability to the Bleichenbacher attack is to
      //treat incorrectly formatted messages in a manner indistinguishable from
      //correctly formatted RSA blocks
      bad = CRYPTO_TEST_NZ_32(error);
      bad |= CRYPTO_TEST_NEQ_32(context->premasterSecretLen, 48);
      bad |= CRYPTO_TEST_NEQ_16(version, context->clientVersion);

      //Generate a random 48-byte value
      error = context->prngAlgo->read(context->prngContext,
         randPremasterSecret, 48);

      //When it receives an incorrectly formatted RSA block, the server should
      //proceed using the random 48-byte value as the premaster secret
      for(n = 0; n < 48; n++)
      {
         context->premasterSecret[n] = CRYPTO_SELECT_8(
            context->premasterSecret[n], randPremasterSecret[n], bad);
      }

      //Fix the length of the premaster secret
      context->premasterSecretLen = 48;
   }
   else
#endif
#if (TLS_DH_ANON_KE_SUPPORT == ENABLED || TLS_DHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_DHE_DSS_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      size_t n;

      //Convert the client's public value to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.yb, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public value
         error = dhCheckPublicKey(&context->dhContext.params,
            &context->dhContext.yb);
      }

      //Check status code
      if(!error)
      {
         //Calculate the negotiated key Z
         error = dhComputeSharedSecret(&context->dhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }

      //Check status code
      if(!error)
      {
         //Leading bytes of Z that contain all zero bits are stripped before
         //it is used as the premaster secret (RFC 4346, section 8.2.1)
         for(n = 0; n < context->premasterSecretLen; n++)
         {
            if(context->premasterSecret[n] != 0x00)
               break;
         }

         //Any leading zero bytes?
         if(n > 0)
         {
            //Strip leading zero bytes from the negotiated key
            osMemmove(context->premasterSecret, context->premasterSecret + n,
               context->premasterSecretLen - n);

            //Adjust the length of the premaster secret
            context->premasterSecretLen -= n;
         }
      }
   }
   else
#endif
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;

      //Decode client's public key
      error = tlsReadEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qb.q, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public key and make sure that it is on the same
         //elliptic curve as the server's ECDH key
         error = ecdhCheckPublicKey(&context->ecdhContext.params,
            &context->ecdhContext.qb.q);
      }

      //Check status code
      if(!error)
      {
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
         //Any registered callback?
         if(context->ecdhCallback != NULL)
         {
            //Invoke user callback function
            error = context->ecdhCallback(context);
         }
         else
#endif
         {
            //No callback function defined
            error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
         }

         //Check status code
         if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
         {
            //Calculate the shared secret Z. Leading zeros found in this octet
            //string must not be truncated (see RFC 4492, section 5.10)
            error = ecdhComputeSharedSecret(&context->ecdhContext,
               context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
               &context->premasterSecretLen);
         }
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}

#endif
