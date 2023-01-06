/**
 * @file tls13_server_misc.c
 * @brief Helper functions for TLS 1.3 server
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
#include "tls_server_misc.h"
#include "tls_transcript_hash.h"
#include "tls_ffdhe.h"
#include "tls_misc.h"
#include "tls13_server_extensions.h"
#include "tls13_server_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Cipher suite and key exchange method negotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tls13NegotiateCipherSuite(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, const TlsCipherSuites *cipherSuites,
   TlsHelloExtensions *extensions)
{
   error_t error;

   //In TLS 1.3, the cipher suite concept has been changed. The key exchange
   //mechanism is negotiated separately from the cipher suite
   context->keyExchMethod = TLS_KEY_EXCH_NONE;

   //The PreSharedKey extension is used to negotiate the identity of the
   //pre-shared key to be used with a given handshake in association with
   //PSK key establishment
   error = tls13ParseClientPreSharedKeyExtension(context, clientHello,
      clientHelloLen, extensions->identityList, extensions->binderList);
   //Any error to report?
   if(error)
      return error;

   //Externally established PSKs should influence cipher suite selection
   if(context->selectedIdentity >= 0)
   {
      //Select a cipher suite indicating a hash associated with the PSK
      error = tlsNegotiateCipherSuite(context, context->cipherSuite.prfHashAlgo,
         cipherSuites, extensions);

      //The server must ensure that it selects a compatible PSK and cipher suite
      if(!error)
      {
         //Perform PSK handshake
         context->keyExchMethod = TLS13_KEY_EXCH_PSK;
      }
      else
      {
         //Perform a non-PSK handshake if possible
         context->keyExchMethod = TLS_KEY_EXCH_NONE;
         context->selectedIdentity = -1;
      }
   }

   //Check key exchange method
   if(context->keyExchMethod == TLS_KEY_EXCH_NONE)
   {
      //Perform cipher suite negotiation
      error = tlsNegotiateCipherSuite(context, NULL, cipherSuites, extensions);
      //If no acceptable choices are presented, terminate the handshake
      if(error)
         return ERROR_HANDSHAKE_FAILED;
   }

   //If the handshake includes a HelloRetryRequest, the initial ClientHello
   //and HelloRetryRequest are included in the transcript along with the new
   //ClientHello
   if(context->state != TLS_STATE_CLIENT_HELLO_2)
   {
      //Initialize handshake message hashing
      error = tlsInitTranscriptHash(context);
      //Any error to report?
      if(error)
         return error;
   }

   //If the client opts to send 0-RTT data, it must supply an EarlyData
   //extension in its ClientHello
   error = tls13ParseClientEarlyDataExtension(context,
      extensions->earlyDataIndication);
   //Any error to report?
   if(error)
      return error;

   //The KeyShare extension contains the client's cryptographic parameters
   error = tls13ParseClientKeyShareExtension(context, extensions->keyShareList);
   //Any error to report?
   if(error)
      return error;

   //Incorrect (EC)DHE share?
   if(extensions->keyShareList != NULL && context->namedGroup == TLS_GROUP_NONE)
   {
      //Select an appropriate ECDHE or FFDHE group
      error = tls13SelectGroup(context, extensions->supportedGroupList);
      //Any error to report?
      if(error)
         return error;

      //The server corrects the mismatch with a HelloRetryRequest
      context->state = TLS_STATE_HELLO_RETRY_REQUEST;
   }
   else
   {
      //Check key exchange method
      if(context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_ECDHE)
      {
         //Check whether the client supports session resumption with a PSK
         error = tls13ParsePskKeModesExtension(context,
            extensions->pskKeModeList);
         //Any error to report?
         if(error)
            return error;
      }
      else if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
      {
         //Servers must not select a key exchange mode that is not listed by
         //the client in the PskKeyExchangeModes extension
         error = tls13ParsePskKeModesExtension(context,
            extensions->pskKeModeList);
         //Any error to report?
         if(error)
            return error;

         //Prior to accepting PSK key establishment, the server must validate
         //the corresponding binder value
         error = tls13VerifyPskBinder(context, clientHello, clientHelloLen,
            extensions->identityList, extensions->binderList,
            context->selectedIdentity);
         //If this value does not validate, the server must abort the handshake
         if(error)
            return error;
      }
      else
      {
         //If no common cryptographic parameters can be negotiated, the server
         //must abort the handshake with an appropriate alert
         return ERROR_HANDSHAKE_FAILED;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Select the group to be used when performing (EC)DHE key exchange
 * @param[in] context Pointer to the TLS context
 * @param[in] groupList List of named groups supported by the client
 * @return Error code
 **/

error_t tls13SelectGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList)
{
   error_t error;

   //Initialize status code
   error = ERROR_HANDSHAKE_FAILED;

   //Reset the named group to its default value
   context->namedGroup = TLS_GROUP_NONE;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Valid SupportedGroups extension?
   if(groupList != NULL)
   {
      uint_t i;
      uint_t j;
      uint_t n;
      uint16_t namedGroup;

      //Get the number of named groups present in the list
      n = ntohs(groupList->length) / sizeof(uint16_t);

      //Any preferred ECDHE or FFDHE groups?
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

               //The named group to be used when performing (EC)DHE key exchange
               //must be one of those present in the SupportedGroups extension
               if(context->supportedGroups[i] == namedGroup)
               {
                  //Check whether the ECDHE or FFDHE group is supported
                  if(tls13IsGroupSupported(context, namedGroup))
                  {
                     //Save the named group
                     context->namedGroup = namedGroup;
                     error = NO_ERROR;
                  }
               }
            }
         }
      }
      else
      {
         //The named group to be used when performing (EC)DHE key exchange must
         //be one of those present in the SupportedGroups extension
         for(j = 0; j < n && error; j++)
         {
            //Convert the named group to host byte order
            namedGroup = ntohs(groupList->value[j]);

            //Check whether the ECDHE or FFDHE group is supported
            if(tls13IsGroupSupported(context, namedGroup))
            {
               //Save the named group
               context->namedGroup = namedGroup;
               error = NO_ERROR;
            }
         }
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Verify PSK binder value
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] identityList List of the identities that the client is willing
 *   to negotiate with the server
 * @param[in] binderList List of HMAC values, one for each PSK offered in the
 *   PreSharedKey extension
 * @param[in] selectedIdentity Selected PSK identity
 * @return Error code
 **/

error_t tls13VerifyPskBinder(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, const Tls13PskIdentityList *identityList,
   const Tls13PskBinderList *binderList, int_t selectedIdentity)
{
#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   error_t error;
   int_t i;
   size_t n;
   const uint8_t *p;
   const Tls13PskIdentity *identity;
   const Tls13PskBinder *binder;
   uint8_t calculatedBinder[TLS_MAX_HKDF_DIGEST_SIZE];

   //Initialize variables
   identity = NULL;
   binder = NULL;

   //Make sure the PreSharedKey extension is valid
   if(identityList == NULL || binderList == NULL)
      return ERROR_FAILURE;

   //Make sure the selected identity is valid
   if(selectedIdentity < 0)
      return ERROR_FAILURE;

   //Point to the list of the identities that the client is willing to
   //negotiate with the server
   p = identityList->value;
   n = ntohs(identityList->length);

   //Loop through the list of PSK identities
   for(i = 0; i <= selectedIdentity && n > 0; i++)
   {
      //Point to the current PskIdentity entry
      identity = (Tls13PskIdentity *) p;

      //Malformed PreSharedKey extension?
      if(n < sizeof(TlsPskIdentity))
         return ERROR_DECODING_FAILED;
      if(n < (sizeof(TlsPskIdentity) + ntohs(identity->length)))
         return ERROR_DECODING_FAILED;

      //Point to the obfuscated_ticket_age field
      p += sizeof(TlsPskIdentity) + ntohs(identity->length);
      n -= sizeof(TlsPskIdentity) + ntohs(identity->length);

      //The obfuscated_ticket_age field is a 32-bit unsigned integer
      if(n < sizeof(uint32_t))
         return ERROR_DECODING_FAILED;

      //Point to the next PskIdentity entry
      p += sizeof(uint32_t);
      n -= sizeof(uint32_t);
   }

   //Make sure the selected identity is within the range supplied by the client
   if(selectedIdentity >= i)
      return ERROR_FAILURE;

   //Point to the list of HMAC values, one for each PSK offered in the
   //PreSharedKey extension
   p = binderList->value;
   n = ntohs(binderList->length);

   //Loop through the list of PSK binders
   for(i = 0; i <= selectedIdentity && n > 0; i++)
   {
      //Point to the PskBinderEntry
      binder = (Tls13PskBinder *) p;

      //Malformed PreSharedKey extension?
      if(n < sizeof(Tls13PskBinder))
         return ERROR_DECODING_FAILED;
      if(n < (sizeof(Tls13PskBinder) + binder->length))
         return ERROR_DECODING_FAILED;

      //Point to the next PskBinderEntry
      p += sizeof(Tls13PskBinder) + binder->length;
      n -= sizeof(Tls13PskBinder) + binder->length;
   }

   //Make sure the selected identity is within the range supplied by the client
   if(selectedIdentity >= i)
      return ERROR_FAILURE;

   //Check the length of the PSK binder
   if(binder->length > TLS_MAX_HKDF_DIGEST_SIZE)
      return ERROR_DECRYPTION_FAILED;

   //The PSK binder is computed as an HMAC over a transcript hash containing
   //a partial ClientHello up to the binders list itself
   n = (uint8_t *) binderList - (uint8_t *) clientHello;

   //Compute PSK binder value
   error = tls13ComputePskBinder(context, clientHello, clientHelloLen,
      n, identity, calculatedBinder, binder->length);
   //Any error to report?
   if(error)
      return ERROR_DECRYPTION_FAILED;

   //Debug message
   TRACE_DEBUG("PSK binder:\r\n");
   TRACE_DEBUG_ARRAY("  ", binder->value, binder->length);
   TRACE_DEBUG("Calculated PSK binder:\r\n");
   TRACE_DEBUG_ARRAY("  ", calculatedBinder, binder->length);

   //Prior to accepting PSK key establishment, the server must validate the
   //corresponding binder value
   if(osMemcmp(calculatedBinder, binder->value, binder->length))
   {
      //If this value does not validate, the server must abort the handshake
      return ERROR_DECRYPTION_FAILED;
   }

   //Successful verification
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Process early data
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the early data
 * @param[in] length Length of the early data, in bytes
 * @return Error code
 **/

error_t tls13ProcessEarlyData(TlsContext *context, const uint8_t *data,
   size_t length)
{
   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_CLIENT_HELLO_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //If the client opts to send 0-RTT data, it must supply an EarlyData
   //extension in its ClientHello (refer to RFC 8446, section 4.2.10)
   if(!context->earlyDataExtReceived)
      return ERROR_UNEXPECTED_MESSAGE;

   //Amount of 0-RTT data received by the server
   context->earlyDataLen += length;

   //Discard records which fail deprotection (up to the configured
   //max_early_data_size)
   if(context->earlyDataLen > context->maxEarlyDataSize)
      return ERROR_BAD_RECORD_MAC;

   //Debug message
   TRACE_INFO("Discarding early data (%" PRIuSIZE " bytes)...\r\n", length);

   //The server may opt to reject early data
   return NO_ERROR;
}

#endif
