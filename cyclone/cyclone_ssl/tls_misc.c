/**
 * @file tls_misc.c
 * @brief TLS helper functions
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
#include "tls_common.h"
#include "tls_ffdhe.h"
#include "tls_misc.h"
#include "tls13_key_material.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Translate an error code to an alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] errorCode Internal error code
 **/

void tlsProcessError(TlsContext *context, error_t errorCode)
{
   //Check current state
   if(context->state != TLS_STATE_INIT &&
      context->state != TLS_STATE_CLOSED)
   {
      //Check status code
      switch(errorCode)
      {
      //The timeout interval has elapsed
      case ERROR_TIMEOUT:
         break;

      //The read/write operation would have blocked
      case ERROR_WOULD_BLOCK:
         break;

      //Failed to allocate memory
      case ERROR_OUT_OF_MEMORY:
         break;

      //The read/write operation has failed
      case ERROR_WRITE_FAILED:
      case ERROR_READ_FAILED:
         context->state = TLS_STATE_CLOSED;
         break;

      //An inappropriate message was received
      case ERROR_UNEXPECTED_MESSAGE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
         break;

      //A record is received with an incorrect MAC
      case ERROR_BAD_RECORD_MAC:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC);
         break;

      //Invalid record length
      case ERROR_RECORD_OVERFLOW:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_RECORD_OVERFLOW);
         break;

      //Unable to negotiate an acceptable set of security parameters
      case ERROR_HANDSHAKE_FAILED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
         break;

      //A certificate was corrupt
      case ERROR_BAD_CERTIFICATE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_CERTIFICATE);
         break;

      //A certificate was of an unsupported type
      case ERROR_UNSUPPORTED_CERTIFICATE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_CERTIFICATE);
         break;

      //A certificate has expired or is not currently valid
      case ERROR_CERTIFICATE_EXPIRED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_CERTIFICATE_EXPIRED);
         break;
      //Some other issue arose in processing the certificate, rendering it unacceptable
      case ERROR_UNKNOWN_CERTIFICATE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_CERTIFICATE_UNKNOWN);
         break;

      //A field in the handshake was out of range or inconsistent with other fields
      case ERROR_ILLEGAL_PARAMETER:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
         break;

      //The certificate could not be matched with a known, trusted CA
      case ERROR_UNKNOWN_CA:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNKNOWN_CA);
         break;

      //A message could not be decoded because some field was incorrect
      case ERROR_DECODING_FAILED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
         break;

      //A handshake cryptographic operation failed
      case ERROR_DECRYPTION_FAILED:
      case ERROR_INVALID_SIGNATURE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECRYPT_ERROR);
         break;

      //The protocol version the client has attempted to negotiate is not supported
      case ERROR_VERSION_NOT_SUPPORTED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
         break;

      //Inappropriate fallback detected by the server
      case ERROR_INAPPROPRIATE_FALLBACK:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_INAPPROPRIATE_FALLBACK);
         break;

      //Handshake message not containing an extension that is mandatory
      case ERROR_MISSING_EXTENSION:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_MISSING_EXTENSION);
         break;

      //The ServerHello contains an extension not present in the ClientHello
      case ERROR_UNSUPPORTED_EXTENSION:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
         break;

      //A client certificate is desired but none was provided by the client
      case ERROR_CERTIFICATE_REQUIRED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_CERTIFICATE_REQUIRED);
         break;

      //No application protocol supported by the server
      case ERROR_NO_APPLICATION_PROTOCOL:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_NO_APPLICATION_PROTOCOL);
         break;

      //Internal error
      default:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_INTERNAL_ERROR);
         break;
      }
   }
}


/**
 * @brief Generate client or server random value
 * @param[in] context Pointer to the TLS context
 * @param[out] random Pointer to the random value
 * @return Error code
 **/

error_t tlsGenerateRandomValue(TlsContext *context, uint8_t *random)
{
   error_t error;

   //Verify that the pseudorandom number generator is properly configured
   if(context->prngAlgo != NULL && context->prngContext != NULL)
   {
      //Generate a 32-byte random value using a cryptographically-safe
      //pseudorandom number generator
      error = context->prngAlgo->read(context->prngContext, random, 32);
   }
   else
   {
      //Report an error
      error = ERROR_NOT_CONFIGURED;
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Check status code
   if(!error)
   {
      //TLS 1.3 has a downgrade protection mechanism embedded in the server's
      //random value
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         //Check negotiated version
         if(context->version <= TLS_VERSION_1_1 &&
            context->versionMax >= TLS_VERSION_1_2)
         {
            //If negotiating TLS 1.1 or below, TLS 1.3 servers must, and TLS 1.2
            //servers should, set the last eight bytes of their random value to
            //the bytes 44 4F 57 4E 47 52 44 00
            osMemcpy(random + 24, tls11DowngradeRandom, 8);
         }
         else if(context->version == TLS_VERSION_1_2 &&
            context->versionMax >= TLS_VERSION_1_3)
         {
            //If negotiating TLS 1.2, TLS 1.3 servers must set the last eight
            //bytes of their random value to the bytes 44 4F 57 4E 47 52 44 01
            osMemcpy(random + 24, tls12DowngradeRandom, 8);
         }
         else
         {
            //No downgrade protection mechanism
         }
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Generate a random session identifier
 * @param[in] context Pointer to the TLS context
 * @param[out] length Desired length of the session ID
 * @return Error code
 **/

error_t tlsGenerateSessionId(TlsContext *context, size_t length)
{
   error_t error;

   //Verify that the pseudorandom number generator is properly configured
   if(context->prngAlgo != NULL && context->prngContext != NULL)
   {
      //Generate a random value using a cryptographically-safe pseudorandom
      //number generator
      error = context->prngAlgo->read(context->prngContext, context->sessionId,
         length);

      //Check status code
      if(!error)
      {
         //Save the length of the session identifier
         context->sessionIdLen = length;
      }
   }
   else
   {
      //Report an error
      error = ERROR_NOT_CONFIGURED;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the TLS version to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] version TLS version
 * @return Error code
 **/

error_t tlsSelectVersion(TlsContext *context, uint16_t version)
{
   error_t error;

   //Initialize status code
   error = ERROR_VERSION_NOT_SUPPORTED;

   //Check TLS version
   if(version >= context->versionMin && version <= context->versionMax)
   {
      //Save the TLS protocol version to be used
      context->version = version;
      //The specified TLS version is acceptable
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Set cipher suite
 * @param[in] context Pointer to the TLS context
 * @param[in] identifier Cipher suite identifier
 * @return Error code
 **/

error_t tlsSelectCipherSuite(TlsContext *context, uint16_t identifier)
{
   error_t error;
   uint_t i;
   uint_t n;
   const TlsCipherSuiteInfo *cipherSuite;

   //Initialize status code
   error = ERROR_HANDSHAKE_FAILED;

   //Determine the number of supported cipher suites
   n = tlsGetNumSupportedCipherSuites();

   //Loop through the list of supported cipher suites
   for(cipherSuite = NULL, i = 0; i < n; i++)
   {
      //Compare cipher suite identifiers
      if(tlsSupportedCipherSuites[i].identifier == identifier)
      {
         //The cipher suite is supported
         cipherSuite = &tlsSupportedCipherSuites[i];
         break;
      }
   }

   //Restrict the use of certain cipher suites
   if(context->numCipherSuites > 0)
   {
      //Loop through the list of allowed cipher suites
      for(i = 0; i < context->numCipherSuites; i++)
      {
         //Compare cipher suite identifiers
         if(context->cipherSuites[i] == identifier)
            break;
      }

      //Check whether the use of the cipher suite is restricted
      if(i >= context->numCipherSuites)
         cipherSuite = NULL;
   }

   //Acceptable cipher suite?
   if(cipherSuite != NULL)
   {
      //Check whether the cipher suite can be negotiated with the negotiated
      //protocol version
      if(!tlsIsCipherSuiteAcceptable(cipherSuite, context->version,
         context->version, context->transportProtocol))
      {
         cipherSuite = NULL;
      }
   }

   //Ensure that the selected cipher suite matches all the criteria
   if(cipherSuite != NULL)
   {
      //Save the negotiated cipher suite
      context->cipherSuite = *cipherSuite;
      //Set the key exchange method to be used
      context->keyExchMethod = cipherSuite->keyExchMethod;

      //PRF with the SHA-256 is used for all cipher suites published prior
      //than TLS 1.2 when TLS 1.2 is negotiated
      if(context->cipherSuite.prfHashAlgo == NULL)
      {
         context->cipherSuite.prfHashAlgo = SHA256_HASH_ALGO;
      }

      //The length of the verify data depends on the TLS version currently used
      if(context->version <= TLS_VERSION_1_1)
      {
         //Verify data is always 12-byte long for TLS 1.0 and 1.1
         context->cipherSuite.verifyDataLen = 12;
      }
      else
      {
         //The length of the verify data depends on the cipher suite for TLS 1.2
      }

      //The specified cipher suite is acceptable
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Save session ID
 * @param[in] context Pointer to the TLS context
 * @param[out] session Pointer to the session state
 * @return Error code
 **/

error_t tlsSaveSessionId(const TlsContext *context,
   TlsSessionState *session)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check TLS version
   if(context->version < TLS_VERSION_1_0 || context->version > TLS_VERSION_1_2)
      return ERROR_INVALID_VERSION;

   //Invalid session identifier?
   if(context->sessionIdLen == 0)
      return ERROR_INVALID_TICKET;

   //Invalid session parameters?
   if(context->cipherSuite.identifier == 0)
      return ERROR_INVALID_SESSION;

   //Save current time
   session->timestamp = osGetSystemTime();

   //Save session parameters
   session->version = context->version;
   session->cipherSuite = context->cipherSuite.identifier;

   //Copy session identifier
   osMemcpy(session->sessionId, context->sessionId, context->sessionIdLen);
   session->sessionIdLen = context->sessionIdLen;

   //Save master secret
   osMemcpy(session->secret, context->masterSecret, TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   session->extendedMasterSecret = context->emsExtReceived;
#endif

#if (TLS_SNI_SUPPORT == ENABLED)
   //Any ServerName extension received by the server?
   if(context->entity == TLS_CONNECTION_END_SERVER &&
      context->serverName != NULL)
   {
      size_t n;

      //Retrieve the length of the server name
      n = osStrlen(context->serverName);

      //Allocate a memory block to hold the server name
      session->serverName = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(session->serverName == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Copy the server name
      osStrcpy(session->serverName, context->serverName);
   }
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Save session ticket
 * @param[in] context Pointer to the TLS context
 * @param[out] session Pointer to the session state
 * @return Error code
 **/

error_t tlsSaveSessionTicket(const TlsContext *context,
   TlsSessionState *session)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check TLS version
   if(context->version < TLS_VERSION_1_0 || context->version > TLS_VERSION_1_2)
      return ERROR_INVALID_VERSION;

   //Invalid session ticket?
   if(context->ticket == NULL || context->ticketLen == 0)
      return ERROR_INVALID_TICKET;

   //Invalid session parameters?
   if(context->cipherSuite.identifier == 0)
      return ERROR_INVALID_SESSION;

   //Save session parameters
   session->version = context->version;
   session->cipherSuite = context->cipherSuite.identifier;

   //Allocate a memory block to hold the ticket
   session->ticket = tlsAllocMem(context->ticketLen);
   //Failed to allocate memory?
   if(session->ticket == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy session ticket
   osMemcpy(session->ticket, context->ticket, context->ticketLen);
   session->ticketLen = context->ticketLen;

   //Save master secret
   osMemcpy(session->secret, context->masterSecret, TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   session->extendedMasterSecret = context->emsExtReceived;
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Restore a TLS session using session ID
 * @param[in] context Pointer to the TLS context
 * @param[in] session Pointer to the session state
 * @return Error code
 **/

error_t tlsRestoreSessionId(TlsContext *context,
   const TlsSessionState *session)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check TLS version
   if(session->version < TLS_VERSION_1_0 || session->version > TLS_VERSION_1_2)
      return ERROR_INVALID_VERSION;

   //Invalid session identifier?
   if(session->sessionIdLen == 0)
      return ERROR_INVALID_SESSION;

   //Invalid session parameters?
   if(session->cipherSuite == 0)
      return ERROR_INVALID_SESSION;

   //Restore session parameters
   context->version = session->version;
   context->cipherSuite.identifier = session->cipherSuite;
   context->sessionIdLen = 0;

   //Copy session identifier
   osMemcpy(context->sessionId, session->sessionId, session->sessionIdLen);
   context->sessionIdLen = session->sessionIdLen;

   //Restore master secret
   osMemcpy(context->masterSecret, session->secret, TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   context->emsExtReceived = session->extendedMasterSecret;
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Restore a TLS session using session ticket
 * @param[in] context Pointer to the TLS context
 * @param[in] session Pointer to the session state
 * @return Error code
 **/

error_t tlsRestoreSessionTicket(TlsContext *context,
   const TlsSessionState *session)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check TLS version
   if(session->version < TLS_VERSION_1_0 || session->version > TLS_VERSION_1_2)
      return ERROR_INVALID_VERSION;

   //Invalid session ticket?
   if(session->ticket == NULL || session->ticketLen == 0)
      return ERROR_INVALID_TICKET;

   //Invalid session parameters?
   if(session->cipherSuite == 0)
      return ERROR_INVALID_SESSION;

   //Restore session parameters
   context->version = session->version;
   context->cipherSuite.identifier = session->cipherSuite;
   context->sessionIdLen = 0;

   //Release existing session ticket, if any
   if(context->ticket != NULL)
   {
      osMemset(context->ticket, 0, context->ticketLen);
      tlsFreeMem(context->ticket);
      context->ticket = NULL;
      context->ticketLen = 0;
   }

   //Allocate a memory block to hold the ticket
   context->ticket = tlsAllocMem(session->ticketLen);
   //Failed to allocate memory?
   if(context->ticket == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy session ticket
   osMemcpy(context->ticket, session->ticket, session->ticketLen);
   context->ticketLen = session->ticketLen;

   //Restore master secret
   osMemcpy(context->masterSecret, session->secret, TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   context->emsExtReceived = session->extendedMasterSecret;
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Initialize encryption engine
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine to
 *   be initialized
 * @param[in] entity Specifies whether client or server write keys shall be used
 * @param[in] secret Pointer to the secret value
 * @return Error code
 **/

__weak_func error_t tlsInitEncryptionEngine(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, TlsConnectionEnd entity,
   const uint8_t *secret)
{
   error_t error;
   const CipherAlgo *cipherAlgo;
   TlsCipherSuiteInfo *cipherSuite;

   //Point to the negotiated cipher suite
   cipherSuite = &context->cipherSuite;
   //Point to the cipher algorithm
   cipherAlgo = cipherSuite->cipherAlgo;

   //Save the negotiated TLS version
   encryptionEngine->version = context->version;

   //The sequence number is set to zero at the beginning of a connection
   //and whenever the key is changed
   osMemset(&encryptionEngine->seqNum, 0, sizeof(TlsSequenceNumber));

#if (DTLS_SUPPORT == ENABLED)
   //The epoch number is initially zero and is incremented each time a
   //ChangeCipherSpec message is sent
   encryptionEngine->epoch++;

   //Sequence numbers are maintained separately for each epoch, with each
   //sequence number initially being 0 for each epoch
   osMemset(&encryptionEngine->dtlsSeqNum, 0, sizeof(DtlsSequenceNumber));
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //The value of RecordSizeLimit is used to limit the size of records
   //that are created when encoding application data and the protected
   //handshake message into records (refer to RFC 8449, section 4)
   if(entity == context->entity)
   {
      encryptionEngine->recordSizeLimit = context->recordSizeLimit;
   }
   else
   {
      encryptionEngine->recordSizeLimit = MIN(context->rxBufferMaxLen,
         TLS_MAX_RECORD_LENGTH);
   }
#endif

   //Set appropriate length for MAC key, encryption key, authentication
   //tag and IV
   encryptionEngine->macKeyLen = cipherSuite->macKeyLen;
   encryptionEngine->encKeyLen = cipherSuite->encKeyLen;
   encryptionEngine->fixedIvLen = cipherSuite->fixedIvLen;
   encryptionEngine->recordIvLen = cipherSuite->recordIvLen;
   encryptionEngine->authTagLen = cipherSuite->authTagLen;

   //Set cipher and hash algorithms
   encryptionEngine->cipherAlgo = cipherSuite->cipherAlgo;
   encryptionEngine->cipherMode = cipherSuite->cipherMode;
   encryptionEngine->hashAlgo = cipherSuite->hashAlgo;

   //Initialize cipher context
   encryptionEngine->cipherContext = NULL;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize HMAC context
   encryptionEngine->hmacContext = &context->hmacContext;
#endif

#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //Initialize GCM context
   encryptionEngine->gcmContext = NULL;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      const uint8_t *p;

      //Check whether client or server write keys shall be used
      if(entity == TLS_CONNECTION_END_CLIENT)
      {
         //Point to the key material
         p = context->keyBlock;
         //Save MAC key
         osMemcpy(encryptionEngine->macKey, p, cipherSuite->macKeyLen);

         //Advance current position in the key block
         p += 2 * cipherSuite->macKeyLen;
         //Save encryption key
         osMemcpy(encryptionEngine->encKey, p, cipherSuite->encKeyLen);

         //Advance current position in the key block
         p += 2 * cipherSuite->encKeyLen;
         //Save initialization vector
         osMemcpy(encryptionEngine->iv, p, cipherSuite->fixedIvLen);
      }
      else
      {
         //Point to the key material
         p = context->keyBlock + cipherSuite->macKeyLen;
         //Save MAC key
         osMemcpy(encryptionEngine->macKey, p, cipherSuite->macKeyLen);

         //Advance current position in the key block
         p += cipherSuite->macKeyLen + cipherSuite->encKeyLen;
         //Save encryption key
         osMemcpy(encryptionEngine->encKey, p, cipherSuite->encKeyLen);

         //Advance current position in the key block
         p += cipherSuite->encKeyLen + cipherSuite->fixedIvLen;
         //Save initialization vector
         osMemcpy(encryptionEngine->iv, p, cipherSuite->fixedIvLen);
      }

      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      const HashAlgo *hashAlgo;

      //The hash function used by HKDF is the cipher suite hash algorithm
      hashAlgo = cipherSuite->prfHashAlgo;

      //Make sure the hash algorithm is valid
      if(hashAlgo != NULL)
      {
         //Calculate the write key
         error = tls13HkdfExpandLabel(context->transportProtocol, hashAlgo,
            secret, hashAlgo->digestSize, "key", NULL, 0,
            encryptionEngine->encKey, cipherSuite->encKeyLen);

         //Debug message
         TRACE_DEBUG("Write Key:\r\n");
         TRACE_DEBUG_ARRAY("  ", encryptionEngine->encKey, cipherSuite->encKeyLen);

         //Check status code
         if(!error)
         {
            //Calculate the write IV
            error = tls13HkdfExpandLabel(context->transportProtocol, hashAlgo,
               secret, hashAlgo->digestSize, "iv", NULL, 0,
               encryptionEngine->iv, cipherSuite->fixedIvLen);
         }

         //Debug message
         TRACE_DEBUG("Write IV:\r\n");
         TRACE_DEBUG_ARRAY("  ", encryptionEngine->iv, cipherSuite->fixedIvLen);
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

   //Check status code
   if(!error)
   {
      //Check cipher mode of operation
      if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM ||
         encryptionEngine->cipherMode == CIPHER_MODE_CBC ||
         encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
         encryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         //Allocate encryption context
         encryptionEngine->cipherContext = tlsAllocMem(cipherAlgo->contextSize);

         //Successful memory allocation?
         if(encryptionEngine->cipherContext != NULL)
         {
            //Configure the encryption engine with the write key
            error = cipherAlgo->init(encryptionEngine->cipherContext,
               encryptionEngine->encKey, cipherSuite->encKeyLen);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else if(encryptionEngine->cipherMode == CIPHER_MODE_NULL ||
         encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         //No need to allocate an encryption context
         error = NO_ERROR;
      }
      else
      {
         //Unsupported mode of operation
         error = ERROR_FAILURE;
      }
   }

#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //GCM cipher mode?
      if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         //Allocate a memory buffer to hold the GCM context
         encryptionEngine->gcmContext = tlsAllocMem(sizeof(GcmContext));

         //Successful memory allocation?
         if(encryptionEngine->gcmContext != NULL)
         {
            //Initialize GCM context
            error = gcmInit(encryptionEngine->gcmContext, cipherAlgo,
               encryptionEngine->cipherContext);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Release encryption engine
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 **/

void tlsFreeEncryptionEngine(TlsEncryptionEngine *encryptionEngine)
{
   //Valid cipher context?
   if(encryptionEngine->cipherContext != NULL)
   {
      //Erase cipher context
      encryptionEngine->cipherAlgo->deinit(encryptionEngine->cipherContext);

      //Release memory
      tlsFreeMem(encryptionEngine->cipherContext);
      encryptionEngine->cipherContext = NULL;
   }

#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //Valid GCM context?
   if(encryptionEngine->gcmContext != NULL)
   {
      //Erase GCM context
      osMemset(encryptionEngine->gcmContext, 0, sizeof(GcmContext));

      //Release memory
      tlsFreeMem(encryptionEngine->gcmContext);
      encryptionEngine->gcmContext = NULL;
   }
#endif

   //Reset encryption parameters
   encryptionEngine->cipherAlgo = NULL;
   encryptionEngine->cipherMode = CIPHER_MODE_NULL;
   encryptionEngine->hashAlgo = NULL;
}


/**
 * @brief Encode a multiple precision integer to an opaque vector
 * @param[in] a Pointer to a multiple precision integer
 * @param[out] data Buffer where to store the opaque vector
 * @param[out] length Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsWriteMpi(const Mpi *a, uint8_t *data, size_t *length)
{
   error_t error;
   size_t n;

   //Retrieve the actual size of the integer
   n = mpiGetByteLength(a);

   //The data is preceded by a 2-byte length field
   STORE16BE(n, data);

   //Convert the integer to an octet string
   error = mpiExport(a, data + 2, n, MPI_FORMAT_BIG_ENDIAN);
   //Conversion failed?
   if(error)
      return error;

   //Return the total number of bytes that have been written
   *length = n + 2;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read a multiple precision integer from an opaque vector
 * @param[out] a Resulting multiple precision integer
 * @param[in] data Buffer where to read the opaque vector
 * @param[in] size Total number of bytes available in the buffer
 * @param[out] length Total number of bytes that have been read
 * @return Error code
 **/

error_t tlsReadMpi(Mpi *a, const uint8_t *data, size_t size, size_t *length)
{
   error_t error;
   size_t n;

   //Buffer underrun?
   if(size < 2)
      return ERROR_DECODING_FAILED;

   //Decode the length field
   n = LOAD16BE(data);

   //Buffer underrun?
   if(size < (n + 2))
      return ERROR_DECODING_FAILED;

   //Convert the octet string to a multiple precision integer
   error = mpiImport(a, data + 2, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Return the total number of bytes that have been read
   *length = n + 2;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encode an EC point to an opaque vector
 * @param[in] params EC domain parameters
 * @param[in] a Pointer to an EC point
 * @param[out] data Buffer where to store the opaque vector
 * @param[out] length Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsWriteEcPoint(const EcDomainParameters *params,
   const EcPoint *a, uint8_t *data, size_t *length)
{
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   error_t error;

   //Convert the EC point to an octet string
   error = ecExport(params, a, data + 1, length);
   //Any error to report?
   if(error)
      return error;

   //Set the length of the opaque vector
   data[0] = (uint8_t) (*length);

   //Return the total number of bytes that have been written
   *length += 1;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Read an EC point from an opaque vector
 * @param[in] params EC domain parameters
 * @param[out] a Resulting EC point
 * @param[in] data Buffer where to read the opaque vector
 * @param[in] size Total number of bytes available in the buffer
 * @param[out] length Total number of bytes that have been read
 * @return Error code
 **/

error_t tlsReadEcPoint(const EcDomainParameters *params,
   EcPoint *a, const uint8_t *data, size_t size, size_t *length)
{
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Buffer underrun?
   if(size < 1)
      return ERROR_DECODING_FAILED;

   //The EC point representation is preceded by a length field
   n = data[0];

   //Invalid EC point representation?
   if(n == 0)
      return ERROR_DECODING_FAILED;

   //Buffer underrun?
   if(size < (n + 1))
      return ERROR_DECODING_FAILED;

   //Convert the octet string to an EC point
   error = ecImport(params, a, data + 1, n);
   //Any error to report?
   if(error)
      return error;

   //Return the total number of bytes that have been read
   *length = n + 1;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Convert TLS version to string representation
 * @param[in] version Version number
 * @return String representation
 **/

const char_t *tlsGetVersionName(uint16_t version)
{
   const char_t *s;

   //TLS versions
   static const char_t *const label[] =
   {
      "SSL 3.0",
      "TLS 1.0",
      "TLS 1.1",
      "TLS 1.2",
      "TLS 1.3",
      "DTLS 1.0",
      "DTLS 1.2",
      "DTLS 1.3",
      "Unknown"
   };

   //Check current version
   switch(version)
   {
   case SSL_VERSION_3_0:
      s = label[0];
      break;
   case TLS_VERSION_1_0:
      s = label[1];
      break;
   case TLS_VERSION_1_1:
      s = label[2];
      break;
   case TLS_VERSION_1_2:
      s = label[3];
      break;
   case TLS_VERSION_1_3:
      s = label[4];
      break;
   case DTLS_VERSION_1_0:
      s = label[5];
      break;
   case DTLS_VERSION_1_2:
      s = label[6];
      break;
   case DTLS_VERSION_1_3:
      s = label[7];
      break;
   default:
      s = label[8];
      break;
   }

   //Return the string representation
   return s;
}


/**
 * @brief Get the hash algorithm that matches the specified identifier
 * @param[in] hashAlgoId Hash algorithm identifier
 * @return Pointer to the hash algorithm
 **/

const HashAlgo *tlsGetHashAlgo(uint8_t hashAlgoId)
{
   const HashAlgo *hashAlgo;

   //Check hash algorithm identifier
   switch(hashAlgoId)
   {
#if (TLS_MD5_SUPPORT == ENABLED)
   //MD5 hash identifier?
   case TLS_HASH_ALGO_MD5:
      hashAlgo = MD5_HASH_ALGO;
      break;
#endif
#if (TLS_SHA1_SUPPORT == ENABLED)
   //SHA-1 hash identifier?
   case TLS_HASH_ALGO_SHA1:
      hashAlgo = SHA1_HASH_ALGO;
      break;
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
   //SHA-224 hash identifier?
   case TLS_HASH_ALGO_SHA224:
      hashAlgo = SHA224_HASH_ALGO;
      break;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
   //SHA-256 hash identifier?
   case TLS_HASH_ALGO_SHA256:
      hashAlgo = SHA256_HASH_ALGO;
      break;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
   //SHA-384 hash identifier?
   case TLS_HASH_ALGO_SHA384:
      hashAlgo = SHA384_HASH_ALGO;
      break;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
   //SHA-512 hash identifier?
   case TLS_HASH_ALGO_SHA512:
      hashAlgo = SHA512_HASH_ALGO;
      break;
#endif
   //Unknown hash identifier?
   default:
      hashAlgo = NULL;
      break;
   }

   //Return a pointer to the corresponding hash algorithm
   return hashAlgo;
}


/**
 * @brief Get the EC domain parameters that match the specified named curve
 * @param[in] context Pointer to the TLS context
 * @param[in] namedCurve Elliptic curve identifier
 * @return Elliptic curve domain parameters
 **/

const EcCurveInfo *tlsGetCurveInfo(TlsContext *context, uint16_t namedCurve)
{
   uint_t i;
   const EcCurveInfo *curveInfo;

   //Default elliptic curve domain parameters
   curveInfo = NULL;

#if (TLS_ECDH_SUPPORT == ENABLED)
   //Check named curve
   switch(namedCurve)
   {
#if (TLS_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   case TLS_GROUP_SECP160K1:
      curveInfo = ecGetCurveInfo(SECP160K1_OID, sizeof(SECP160K1_OID));
      break;
#endif
#if (TLS_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   case TLS_GROUP_SECP160R1:
      curveInfo = ecGetCurveInfo(SECP160R1_OID, sizeof(SECP160R1_OID));
      break;
#endif
#if (TLS_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   case TLS_GROUP_SECP160R2:
      curveInfo = ecGetCurveInfo(SECP160R2_OID, sizeof(SECP160R2_OID));
      break;
#endif
#if (TLS_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   case TLS_GROUP_SECP192K1:
      curveInfo = ecGetCurveInfo(SECP192K1_OID, sizeof(SECP192K1_OID));
      break;
#endif
#if (TLS_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   case TLS_GROUP_SECP192R1:
      curveInfo = ecGetCurveInfo(SECP192R1_OID, sizeof(SECP192R1_OID));
      break;
#endif
#if (TLS_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   case TLS_GROUP_SECP224K1:
      curveInfo = ecGetCurveInfo(SECP224K1_OID, sizeof(SECP224K1_OID));
      break;
#endif
#if (TLS_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   case TLS_GROUP_SECP224R1:
      curveInfo = ecGetCurveInfo(SECP224R1_OID, sizeof(SECP224R1_OID));
      break;
#endif
#if (TLS_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   case TLS_GROUP_SECP256K1:
      curveInfo = ecGetCurveInfo(SECP256K1_OID, sizeof(SECP256K1_OID));
      break;
#endif
#if (TLS_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   case TLS_GROUP_SECP256R1:
      curveInfo = ecGetCurveInfo(SECP256R1_OID, sizeof(SECP256R1_OID));
      break;
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   case TLS_GROUP_SECP384R1:
      curveInfo = ecGetCurveInfo(SECP384R1_OID, sizeof(SECP384R1_OID));
      break;
#endif
#if (TLS_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   case TLS_GROUP_SECP521R1:
      curveInfo = ecGetCurveInfo(SECP521R1_OID, sizeof(SECP521R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   case TLS_GROUP_BRAINPOOLP256R1:
   case TLS_GROUP_BRAINPOOLP256R1_TLS13:
      curveInfo = ecGetCurveInfo(BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   case TLS_GROUP_BRAINPOOLP384R1:
   case TLS_GROUP_BRAINPOOLP384R1_TLS13:
      curveInfo = ecGetCurveInfo(BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   case TLS_GROUP_BRAINPOOLP512R1:
   case TLS_GROUP_BRAINPOOLP512R1_TLS13:
      curveInfo = ecGetCurveInfo(BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID));
      break;
#endif
#if (TLS_X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   case TLS_GROUP_ECDH_X25519:
      curveInfo = ecGetCurveInfo(X25519_OID, sizeof(X25519_OID));
      break;
#endif
#if (TLS_X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   case TLS_GROUP_ECDH_X448:
      curveInfo = ecGetCurveInfo(X448_OID, sizeof(X448_OID));
      break;
#endif
   //Unknown elliptic curve identifier?
   default:
      curveInfo = NULL;
      break;
   }
#endif

   //Restrict the use of certain elliptic curves
   if(context->numSupportedGroups > 0)
   {
      //Loop through the list of allowed named groups
      for(i = 0; i < context->numSupportedGroups; i++)
      {
         //Compare named groups
         if(context->supportedGroups[i] == namedCurve)
            break;
      }

      //Check whether the use of the elliptic curve is restricted
      if(i >= context->numSupportedGroups)
      {
         curveInfo = NULL;
      }
   }

   //Return elliptic curve domain parameters, if any
   return curveInfo;
}


/**
 * @brief Get the named curve that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Named curve
 **/

TlsNamedGroup tlsGetNamedCurve(const uint8_t *oid, size_t length)
{
   TlsNamedGroup namedCurve;

   //Default named curve
   namedCurve = TLS_GROUP_NONE;

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      namedCurve = TLS_GROUP_NONE;
   }
#if (TLS_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   else if(!oidComp(oid, length, SECP160K1_OID, sizeof(SECP160K1_OID)))
   {
      namedCurve = TLS_GROUP_SECP160K1;
   }
#endif
#if (TLS_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   else if(!oidComp(oid, length, SECP160R1_OID, sizeof(SECP160R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP160R1;
   }
#endif
#if (TLS_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   else if(!oidComp(oid, length, SECP160R2_OID, sizeof(SECP160R2_OID)))
   {
      namedCurve = TLS_GROUP_SECP160R2;
   }
#endif
#if (TLS_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   else if(!oidComp(oid, length, SECP192K1_OID, sizeof(SECP192K1_OID)))
   {
      namedCurve = TLS_GROUP_SECP192K1;
   }
#endif
#if (TLS_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   else if(!oidComp(oid, length, SECP192R1_OID, sizeof(SECP192R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP192R1;
   }
#endif
#if (TLS_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   else if(!oidComp(oid, length, SECP224K1_OID, sizeof(SECP224K1_OID)))
   {
      namedCurve = TLS_GROUP_SECP224K1;
   }
#endif
#if (TLS_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   else if(!oidComp(oid, length, SECP224R1_OID, sizeof(SECP224R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP224R1;
   }
#endif
#if (TLS_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   else if(!oidComp(oid, length, SECP256K1_OID, sizeof(SECP256K1_OID)))
   {
      namedCurve = TLS_GROUP_SECP256K1;
   }
#endif
#if (TLS_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   else if(!oidComp(oid, length, SECP256R1_OID, sizeof(SECP256R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP256R1;
   }
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   else if(!oidComp(oid, length, SECP384R1_OID, sizeof(SECP384R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP384R1;
   }
#endif
#if (TLS_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   else if(!oidComp(oid, length, SECP521R1_OID, sizeof(SECP521R1_OID)))
   {
      namedCurve = TLS_GROUP_SECP521R1;
   }
#endif
#if (TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID)))
   {
      namedCurve = TLS_GROUP_BRAINPOOLP256R1;
   }
#endif
#if (TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID)))
   {
      namedCurve = TLS_GROUP_BRAINPOOLP384R1;
   }
#endif
#if (TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID)))
   {
      namedCurve = TLS_GROUP_BRAINPOOLP512R1;
   }
#endif
   //Unknown identifier?
   else
   {
      namedCurve = TLS_GROUP_NONE;
   }
#endif

   //Return the corresponding named curve
   return namedCurve;
}


/**
 * @brief Compute overhead caused by encryption
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] payloadLen Length of the payload, in bytes
 * @return Overhead, in bytes, caused by encryption
 **/

size_t tlsComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine,
   size_t payloadLen)
{
   size_t n;

   //Initialize variable
   n = 0;

   //Message authentication?
   if(encryptionEngine->hashAlgo != NULL)
      n += encryptionEngine->hashAlgo->digestSize;

   //Check cipher mode
   if(encryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //TLS 1.1 and 1.2 use an explicit IV
      if(encryptionEngine->version >= TLS_VERSION_1_1)
      {
         n += encryptionEngine->recordIvLen;
      }

      //Padding is added to force the length of the plaintext to be an integral
      //multiple of the cipher's block length
      n += encryptionEngine->cipherAlgo->blockSize -
         ((payloadLen + n) % encryptionEngine->cipherAlgo->blockSize);
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Consider the explicit nonce and the authentication tag
      n += encryptionEngine->recordIvLen + encryptionEngine->authTagLen;
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Consider the authentication tag only
      n += encryptionEngine->authTagLen;
   }
   else
   {
      //Stream ciphers do not cause any overhead
   }

   //Return the total overhead caused by encryption
   return n;
}


/**
 * @brief DNS hostname verification
 * @param[in] name Pointer to the hostname
 * @param[in] length Length of the hostname
 * @return The function returns TRUE is the name is a valid DNS hostname
 **/

bool_t tlsCheckDnsHostname(const char_t *name, size_t length)
{
   size_t i;
   bool_t valid;

   //Initialize flag
   valid = TRUE;

   //Loop through the hostname
   for(i = 0; i < length && valid; i++)
   {
      //DNS hostnames must start with a letter, end with a letter or
      //digit, and have as interior characters only letters, digits,
      //and hyphen (refer to RFC 1034, section 3.5)
      if(name[i] == '-' || name[i] == '.')
      {
         //Valid character
      }
      else if(name[i] >= '0' && name[i] <= '9')
      {
         //Valid character
      }
      else if(name[i] >= 'A' && name[i] <= 'Z')
      {
         //Valid character
      }
      else if(name[i] >= 'a' && name[i] <= 'z')
      {
         //Valid character
      }
      else
      {
         //Invalid character
         valid = FALSE;
      }
   }

   //Return TRUE is the name is a valid DNS hostname
   return valid;
}

#endif
