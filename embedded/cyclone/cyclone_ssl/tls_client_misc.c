/**
 * @file tls_client_misc.c
 * @brief Helper functions for TLS client
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
#include "tls_client.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_extensions.h"
#include "tls_signature.h"
#include "tls_cache.h"
#include "tls_ffdhe.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format initial ClientHello message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsFormatInitialClientHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsRecord *record;
   TlsHandshake *message;

   //Point to the buffer where to format the TLS record
   record = (TlsRecord *) context->txBuffer;
   //Point to the buffer where to format the handshake message
   message = (TlsHandshake *) record->data;

   //Format ClientHello message
   error = tlsFormatClientHello(context, (TlsClientHello *) message->data,
      &length);

   //Check status code
   if(!error)
   {
      //Set the type of the handshake message
      message->msgType = TLS_TYPE_CLIENT_HELLO;
      //Fix the length of the handshake message
      STORE24BE(length, message->length);

      //Total length of the handshake message
      length += sizeof(TlsHandshake);

      //Fix the length of the TLS record
      record->length = htons(length);
   }

   //Return status code
   return error;
}


/**
 * @brief Format session ID
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write session ID
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSessionId(TlsContext *context, uint8_t *p,
   size_t *written)
{
   size_t n;

   //TLS 1.3 supported by the client?
   if(context->versionMax >= TLS_VERSION_1_3 &&
      context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      //A client which has a cached session ID set by a pre-TLS 1.3 server
      //should set this field to that value
      osMemcpy(p, context->sessionId, context->sessionIdLen);
      n = context->sessionIdLen;
   }
   else
   {
#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
      //The session ID value identifies a session the client wishes to reuse
      //for this connection
      osMemcpy(p, context->sessionId, context->sessionIdLen);
      n = context->sessionIdLen;
#else
      //Session resumption is not supported
      n = 0;
#endif
   }

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Secure renegotiation?
   if(context->secureRenegoEnabled && context->secureRenegoFlag)
   {
      //Do not offer a session ID when renegotiating
      n = 0;
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of cipher suites supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[out] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the list of cipher suites
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCipherSuites(TlsContext *context, uint_t *cipherSuiteTypes,
   uint8_t *p, size_t *written)
{
   uint_t i;
   uint_t j;
   uint_t k;
   uint_t n;
   uint16_t identifier;
   TlsCipherSuites *cipherSuites;

   //Types of cipher suites proposed by the client
   *cipherSuiteTypes = TLS_CIPHER_SUITE_TYPE_UNKNOWN;

   //Point to the list of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;
   //Number of cipher suites in the array
   n = 0;

   //Determine the number of supported cipher suites
   k = tlsGetNumSupportedCipherSuites();

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Any preferred cipher suites?
   if(context->numCipherSuites > 0)
   {
      //Loop through the list of preferred cipher suites
      for(i = 0; i < context->numCipherSuites; i++)
      {
         //Loop through the list of supported cipher suites
         for(j = 0; j < k; j++)
         {
            //Retrieve cipher suite identifier
            identifier = tlsSupportedCipherSuites[j].identifier;

            //Supported cipher suite?
            if(identifier == context->cipherSuites[i])
            {
               //Check whether the cipher suite can be negotiated with the
               //current protocol version
               if(tlsIsCipherSuiteAcceptable(&tlsSupportedCipherSuites[j],
                  context->versionMin, context->versionMax,
                  context->transportProtocol))
               {
                  //Copy cipher suite identifier
                  cipherSuites->value[n++] = htons(identifier);

                  //Debug message
                  TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", identifier,
                     tlsGetCipherSuiteName(identifier));

                  //Check whether the identifier matches an ECC or FFDHE cipher
                  //suite
                  *cipherSuiteTypes |= tlsGetCipherSuiteType(identifier);
               }
            }
         }
      }
   }
   else
   {
      //Loop through the list of supported cipher suites
      for(j = 0; j < k; j++)
      {
         //Retrieve cipher suite identifier
         identifier = tlsSupportedCipherSuites[j].identifier;

         //Check whether the cipher suite can be negotiated with the
         //current protocol version
         if(tlsIsCipherSuiteAcceptable(&tlsSupportedCipherSuites[j],
            context->versionMin, context->versionMax,
            context->transportProtocol))
         {
            //Copy cipher suite identifier
            cipherSuites->value[n++] = htons(identifier);

            //Debug message
            TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", identifier,
               tlsGetCipherSuiteName(identifier));

            //Check whether the identifier matches an ECC or FFDHE cipher
            //suite
            *cipherSuiteTypes |= tlsGetCipherSuiteType(identifier);
         }
      }
   }

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //Initial handshake?
      if(context->clientVerifyDataLen == 0)
      {
         //The client includes the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling
         //cipher suite value in its ClientHello
         cipherSuites->value[n++] = HTONS(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
      }
   }
#endif

#if (TLS_FALLBACK_SCSV_SUPPORT == ENABLED)
   //Check whether support for FALLBACK_SCSV is enabled
   if(context->fallbackScsvEnabled)
   {
      //The TLS_FALLBACK_SCSV cipher suite value is meant for use by clients
      //that repeat a connection attempt with a downgraded protocol
      if(context->versionMax != TLS_MAX_VERSION)
      {
         //The client should put TLS_FALLBACK_SCSV after all cipher suites
         //that it actually intends to negotiate
         cipherSuites->value[n++] = HTONS(TLS_FALLBACK_SCSV);
      }
   }
#endif

   //Length of the array, in bytes
   cipherSuites->length = htons(n * 2);

   //Total number of bytes that have been written
   *written = sizeof(TlsCipherSuites) + n * 2;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of compression methods supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the list of compression methods
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCompressMethods(TlsContext *context, uint8_t *p,
   size_t *written)
{
   TlsCompressMethods *compressMethods;

   //List of compression algorithms supported by the client
   compressMethods = (TlsCompressMethods *) p;

   //The CRIME exploit takes advantage of TLS compression, so conservative
   //implementations do not enable compression at the TLS level
   compressMethods->length = 1;
   compressMethods->value[0] = TLS_COMPRESSION_METHOD_NULL;

   //Total number of bytes that have been written
   *written = sizeof(TlsCompressMethods) + compressMethods->length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentity(TlsContext *context, uint8_t *p,
   size_t *written)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //Any PSK identity defined?
   if(context->pskIdentity != NULL)
   {
      //Determine the length of the PSK identity
      n = osStrlen(context->pskIdentity);
      //Copy PSK identity
      osMemcpy(pskIdentity->value, context->pskIdentity, n);
   }
   else
#endif
   {
      //No PSK identity is provided
      n = 0;
   }

   //The PSK identity is preceded by a 2-byte length field
   pskIdentity->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the client's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

__weak_func error_t tlsFormatClientKeyParams(TlsContext *context, uint8_t *p,
   size_t *written)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   size_t n;

#if (TLS_RSA_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      //If RSA is being used for key agreement and authentication, the
      //client generates a 48-byte premaster secret
      context->premasterSecretLen = 48;

      //The first 2 bytes code the latest version supported by the client
      STORE16BE(context->clientVersion, context->premasterSecret);

      //The last 46 bytes contain securely-generated random bytes
      error = context->prngAlgo->read(context->prngContext,
         context->premasterSecret + 2, 46);
      //Any error to report?
      if(error)
         return error;

      //Encrypt the premaster secret using the server public key
      error = rsaesPkcs1v15Encrypt(context->prngAlgo, context->prngContext,
         &context->peerRsaPublicKey, context->premasterSecret, 48, p + 2, &n);
      //RSA encryption failed?
      if(error)
         return error;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes
      STORE16BE(n, p);

      //Total number of bytes that have been written
      *written = n + 2;
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
      //Generate an ephemeral key pair
      error = dhGenerateKeyPair(&context->dhContext,
         context->prngAlgo, context->prngContext);
      //Any error to report?
      if(error)
         return error;

      //Encode the client's public value to an opaque vector
      error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;

      //Calculate the negotiated key Z
      error = dhComputeSharedSecret(&context->dhContext,
         context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
         &context->premasterSecretLen);
      //Any error to report?
      if(error)
         return error;

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
         //Any error to report?
         if(error)
            return error;

         //Calculate the negotiated key Z
         error = ecdhComputeSharedSecret(&context->ecdhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
         //Any error to report?
         if(error)
            return error;
      }
      else if(error != NO_ERROR)
      {
         //Report an error
         return error;
      }

      //Encode the client's public key to an opaque vector
      error = tlsWriteEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qa.q, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;
   }
   else
#endif
   //Invalid key exchange method?
   {
      //Just for sanity
      (void) error;
      (void) n;

      //The specified key exchange method is not supported
      return ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentityHint(TlsContext *context, const uint8_t *p,
   size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

   //Malformed ServerKeyExchange message?
   if(length < sizeof(TlsPskIdentityHint))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsPskIdentityHint) + ntohs(pskIdentityHint->length)))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the PSK identity hint
   n = ntohs(pskIdentityHint->length);

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //The client selects which identity to use depending on the PSK identity
      //hint provided by the server
      error = context->pskCallback(context, pskIdentityHint->value, n);
      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the server's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseServerKeyParams(TlsContext *context, const uint8_t *p,
   size_t length, size_t *consumed)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   const uint8_t *params;

   //Initialize status code
   error = NO_ERROR;

   //Point to the server's key exchange parameters
   params = p;

#if (TLS_DH_ANON_KE_SUPPORT == ENABLED || TLS_DHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_DHE_DSS_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      uint_t k;
      size_t n;

      //Convert the prime modulus to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.params.p, p, length, &n);

      //Check status code
      if(!error)
      {
         //Get the length of the prime modulus, in bits
         k = mpiGetBitLength(&context->dhContext.params.p);

         //Make sure the prime modulus is acceptable
         if(k < TLS_MIN_DH_MODULUS_SIZE || k > TLS_MAX_DH_MODULUS_SIZE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the generator to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.params.g, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the server's public value to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.yb, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public value
         error = dhCheckPublicKey(&context->dhContext.params,
            &context->dhContext.yb);
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
         TRACE_DEBUG_MPI("    ", &context->dhContext.yb);
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
      uint8_t curveType;
      const EcCurveInfo *curveInfo;

      //Initialize curve parameters
      curveInfo = NULL;

      //Malformed ServerKeyExchange message?
      if(length < sizeof(curveType))
         error = ERROR_DECODING_FAILED;

      //Check status code
      if(!error)
      {
         //Retrieve the type of the elliptic curve domain parameters
         curveType = *p;

         //Advance data pointer
         p += sizeof(curveType);
         //Remaining bytes to process
         length -= sizeof(curveType);

         //Only named curves are supported
         if(curveType != TLS_EC_CURVE_TYPE_NAMED_CURVE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Malformed ServerKeyExchange message?
         if(length < sizeof(uint16_t))
            error = ERROR_DECODING_FAILED;
      }

      //Check status code
      if(!error)
      {
         //Get elliptic curve identifier
         context->namedGroup = LOAD16BE(p);

         //Advance data pointer
         p += sizeof(uint16_t);
         //Remaining bytes to process
         length -= sizeof(uint16_t);

         //Retrieve the corresponding EC domain parameters
         curveInfo = tlsGetCurveInfo(context, context->namedGroup);

         //Make sure the elliptic curve is supported
         if(curveInfo == NULL)
         {
            //The elliptic curve is not supported
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //Check status code
      if(!error)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);
      }

      //Check status code
      if(!error)
      {
         //Read server's public key
         error = tlsReadEcPoint(&context->ecdhContext.params,
            &context->ecdhContext.qb.q, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public key
         error = ecdhCheckPublicKey(&context->ecdhContext.params,
            &context->ecdhContext.qb.q);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Server public key X:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.q.x);
         TRACE_DEBUG("  Server public key Y:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.q.y);
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_UNEXPECTED_MESSAGE;
   }

   //Total number of bytes that have been consumed
   *consumed = p - params;

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify server's key exchange parameters signature (TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Pointer to the digital signature
 * @param[in] length Number of bytes available in the input stream
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsVerifyServerKeySignature(TlsContext *context,
   const TlsDigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Initialize status code
   error = NO_ERROR;

   //Check the length of the digitally-signed element
   if(length < sizeof(TlsDigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(context->peerCertType == TLS_CERT_RSA_SIGN)
   {
      Md5Context *md5Context;
      Sha1Context *sha1Context;

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
         //RSA signature verification
         error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
            context->serverVerifyData, signature->value, ntohs(signature->length));
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA signature algorithm?
   if(context->peerCertType == TLS_CERT_DSS_SIGN)
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
         //DSA signature verification
         error = tlsVerifyDsaSignature(context, context->serverVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
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

      //Check status code
      if(!error)
      {
         //ECDSA signature verification
         error = tlsVerifyEcdsaSignature(context, context->serverVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE;
   }

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsDigitalSignature) + ntohs(signature->length);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Verify server's key exchange parameters signature (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Pointer to the digital signature
 * @param[in] length Number of bytes available in the input stream
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

__weak_func error_t tls12VerifyServerKeySignature(TlsContext *context,
   const Tls12DigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

   //Check the length of the digitally-signed element
   if(length < sizeof(Tls12DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(Tls12DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //RSA, DSA or ECDSA signature scheme?
   if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_DSA ||
      signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Retrieve the hash algorithm used for signing
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
         signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256)
      {
         //The hashing is intrinsic to the signature algorithm
         if(signature->algorithm.hash == TLS_HASH_ALGO_INTRINSIC)
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
         else
            hashAlgo = NULL;
      }
      else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
         signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384)
      {
         //The hashing is intrinsic to the signature algorithm
         if(signature->algorithm.hash == TLS_HASH_ALGO_INTRINSIC)
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
         else
            hashAlgo = NULL;
      }
      else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
         signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
      {
         //The hashing is intrinsic to the signature algorithm
         if(signature->algorithm.hash == TLS_HASH_ALGO_INTRINSIC)
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
         else
            hashAlgo = NULL;
      }
      else
      {
         //This field indicates the hash algorithm that is used
         hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);
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
            //RSASSA-PKCS1-v1_5 signature scheme?
            if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA &&
               context->peerCertType == TLS_CERT_RSA_SIGN)
            {
               //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
               error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey,
                  hashAlgo, hashContext->digest, signature->value,
                  ntohs(signature->length));
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS signature scheme (with public key OID rsaEncryption)?
            if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
               signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
               signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
            {
               //Enforce the type of the certificate provided by the peer
               if(context->peerCertType == TLS_CERT_RSA_SIGN)
               {
                  //Verify RSA signature (RSASSA-PSS signature scheme)
                  error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
                     hashAlgo->digestSize, hashContext->digest,
                     signature->value, ntohs(signature->length));
               }
               else
               {
                  //Invalid certificate
                  error = ERROR_INVALID_SIGNATURE;
               }
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS signature scheme (with public key OID RSASSA-PSS)?
            if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256 ||
               signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384 ||
               signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
            {
               //Enforce the type of the certificate provided by the peer
               if(context->peerCertType == TLS_CERT_RSA_PSS_SIGN)
               {
                  //Verify RSA signature (RSASSA-PSS signature scheme)
                  error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
                     hashAlgo->digestSize, hashContext->digest,
                     signature->value, ntohs(signature->length));
               }
               else
               {
                  //Invalid certificate
                  error = ERROR_INVALID_SIGNATURE;
               }
            }
            else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature scheme?
            if(signature->algorithm.signature == TLS_SIGN_ALGO_DSA &&
               context->peerCertType == TLS_CERT_DSS_SIGN)
            {
               //DSA signature verification
               error = tlsVerifyDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value,
                  ntohs(signature->length));
            }
            else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature scheme?
            if(signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA &&
               context->peerCertType == TLS_CERT_ECDSA_SIGN)
            {
               //ECDSA signature verification
               error = tlsVerifyEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value,
                  ntohs(signature->length));
            }
            else
#endif
            //Invalid signature scheme?
            {
               //Report an error
               error = ERROR_INVALID_SIGNATURE;
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
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
#endif
#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED)
   //EdDSA signature scheme?
   if(signature->algorithm.signature == TLS_SIGN_ALGO_ED25519 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_ED448)
   {
      EddsaMessageChunk messageChunks[4];

      //Data to be verified is run through the EdDSA algorithm without
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
      if(signature->algorithm.signature == TLS_SIGN_ALGO_ED25519 &&
         context->peerCertType == TLS_CERT_ED25519_SIGN)
      {
         //EdDSA signature verification
         error = tlsVerifyEddsaSignature(context, messageChunks,
            signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
      //Ed448 signature scheme?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_ED448 &&
         context->peerCertType == TLS_CERT_ED448_SIGN)
      {
         //EdDSA signature verification
         error = tlsVerifyEddsaSignature(context, messageChunks,
            signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature scheme?
      {
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE;
   }

   //Total number of bytes that have been consumed
   *consumed = sizeof(Tls12DigitalSignature) + ntohs(signature->length);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Version selection
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the received ServerHello message
 * @param[in] extensions ServerHello extensions offered by the server
 * @return Error code
 **/

error_t tlsSelectClientVersion(TlsContext *context,
   const TlsServerHello *message, const TlsHelloExtensions *extensions)
{
   error_t error;
   uint16_t selectedVersion;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Clients must check for the SupportedVersions extension prior to
   //processing the rest of the ServerHello
   if(extensions->selectedVersion != NULL)
   {
      //If a client receives an extension type in the ServerHello that it did
      //not request in the associated ClientHello, it must abort the handshake
      //with an unsupported_extension fatal alert
      if(context->versionMax <= TLS_VERSION_1_2)
         return ERROR_UNSUPPORTED_EXTENSION;

      //The legacy_version field must be set to 0x0303, which is the version
      //number for TLS 1.2
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         if(ntohs(message->serverVersion) != DTLS_VERSION_1_2)
            return ERROR_VERSION_NOT_SUPPORTED;
      }
      else
      {
         if(ntohs(message->serverVersion) != TLS_VERSION_1_2)
            return ERROR_VERSION_NOT_SUPPORTED;
      }

      //If this extension is present, clients must ignore the legacy_version
      //value and must use only the SupportedVersions extension to determine
      //the selected version
      selectedVersion = LOAD16BE(extensions->selectedVersion->value);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //If the SupportedVersions extension contains a version prior to DTLS
         //1.3, the client must abort the handshake with an illegal_parameter
         //alert (refer to RFC 8446, section 4.2.1)
         if(selectedVersion >= DTLS_VERSION_1_2)
            return ERROR_ILLEGAL_PARAMETER;

         //Check whether the ServerHello message is received in response to an
         //updated ClientHello?
         if(context->state == TLS_STATE_SERVER_HELLO_2)
         {
            //The value of selected_version in the SupportedVersions extension
            //of the HelloRetryRequest must be retained in the ServerHello. A
            //client must abort the handshake with an illegal_parameter alert if
            //the value changes (refer to RFC 8446, section 4.1.4)
            if(selectedVersion != dtlsTranslateVersion(context->version))
               return ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
#endif
      //TLS protocol?
      {
         //If the SupportedVersions extension contains a version prior to TLS
         //1.3, the client must abort the handshake with an illegal_parameter
         //alert (refer to RFC 8446, section 4.2.1)
         if(selectedVersion <= TLS_VERSION_1_2)
            return ERROR_ILLEGAL_PARAMETER;

         //Check whether the ServerHello message is received in response to an
         //updated ClientHello?
         if(context->state == TLS_STATE_SERVER_HELLO_2)
         {
            //The value of selected_version in the SupportedVersions extension
            //of the HelloRetryRequest must be retained in the ServerHello. A
            //client must abort the handshake with an illegal_parameter alert if
            //the value changes (refer to RFC 8446, section 4.1.4)
            if(selectedVersion != context->version)
               return ERROR_ILLEGAL_PARAMETER;
         }
      }
   }
   else
#endif
   {
      //In previous versions of TLS, this field was used for version negotiation
      //and represented the selected version number for the connection
      selectedVersion = ntohs(message->serverVersion);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //A server which negotiates DTLS 1.3 must set the legacy_version field
         //to 0xFEFD (DTLS 1.2) and use the SupportedVersions extension instead
         if(selectedVersion < DTLS_VERSION_1_2)
            return ERROR_ILLEGAL_PARAMETER;
      }
      else
#endif
      //TLS protocol?
      {
         //A server which negotiates TLS 1.3 must set the legacy_version field
         //to 0x0303 (TLS 1.2) and use the SupportedVersions extension instead
         if(selectedVersion > TLS_VERSION_1_2)
            return ERROR_ILLEGAL_PARAMETER;
      }
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Set the DTLS version to be used
      error = dtlsSelectVersion(context, selectedVersion);
   }
   else
#endif
   //TLS protocol?
   {
      //Set the TLS version to be used
      error = tlsSelectVersion(context, selectedVersion);
   }

   //Specified TLS/DTLS version not supported?
   if(error)
      return error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //If the ServerHello indicates TLS 1.1 or below, TLS 1.3 client must and
   //1.2 clients should check that the last 8 bytes are not equal to the
   //bytes 44 4F 57 4E 47 52 44 00
   if(context->version <= TLS_VERSION_1_1 &&
      context->versionMax >= TLS_VERSION_1_2)
   {
      //If a match is found, the client must abort the handshake with an
      //illegal_parameter alert
      if(!osMemcmp(message->random + 24, tls11DowngradeRandom, 8))
         return ERROR_ILLEGAL_PARAMETER;
   }

   //If the ServerHello indicates TLS 1.2 or below, TLS 1.3 client must check
   //that the last 8 bytes are not equal to the bytes 44 4F 57 4E 47 52 44 00
   if(context->version <= TLS_VERSION_1_2 &&
      context->versionMax >= TLS_VERSION_1_3)
   {
      //If a match is found, the client must abort the handshake with an
      //illegal_parameter alert
      if(!osMemcmp(message->random + 24, tls12DowngradeRandom, 8))
         return ERROR_ILLEGAL_PARAMETER;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Resume TLS session via session ID
 * @param[in] context Pointer to the TLS context
 * @param[in] sessionId Pointer to the session ID provided by the server
 * @param[in] sessionIdLen Length of the session ID, in bytes
 * @param[in] cipherSuite Cipher suite selected by the server
 * @return Error code
 **/

error_t tlsResumeSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, uint16_t cipherSuite)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether the session ID matches the value that was supplied by the
   //client
   if(sessionIdLen != 0 && sessionIdLen == context->sessionIdLen &&
      !osMemcmp(sessionId, context->sessionId, sessionIdLen))
   {
      //For resumed sessions, the selected cipher suite shall be the same as
      //the session being resumed
      if(cipherSuite != 0 && cipherSuite == context->cipherSuite.identifier)
      {
         //Perform abbreviated handshake
         context->resume = TRUE;
      }
      else
      {
         //The session ID is no more valid
         context->sessionIdLen = 0;

         //When renegotiating, if the server tries to use another version or
         //compression method than previously, abort
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   {
      //Perform a full handshake
      context->resume = FALSE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether a session ticket is valid
 * @param[in] context Pointer to the TLS context
 * @return TRUE is the session ticket is valid, else FALSE
 **/

bool_t tlsIsTicketValid(TlsContext *context)
{
   bool_t valid = FALSE;

   //TLS 1.3 tickets cannot be used to resume a TLS 1.2 session
   if(context->version <= TLS_VERSION_1_2)
   {
      //Valid ticket?
      if(context->ticket != NULL && context->ticketLen > 0)
      {
         valid = TRUE;
      }
   }

   //Return TRUE is the ticket is valid, else FALSE
   return valid;
}

#endif
