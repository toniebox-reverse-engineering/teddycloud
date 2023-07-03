/**
 * @file tls13_server_extensions.c
 * @brief Formatting and parsing of extensions (TLS 1.3 server)
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
#include "tls_misc.h"
#include "tls13_server_extensions.h"
#include "tls13_server_misc.h"
#include "tls13_ticket.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Format SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SupportedVersions extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatServerSupportedVersionsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   uint16_t version;
   TlsExtension *extension;

   //Add the SupportedVersions extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_SUPPORTED_VERSIONS);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Retrieve the selected DTLS version
      version = dtlsTranslateVersion(context->version);
   }
   else
#endif
   {
      //Retrieve the selected TLS version
      version = context->version;
   }

   //The extension contains the selected version value
   STORE16BE(version, extension->value);

   //The extension data field contains a 16-bit unsigned integer
   n = sizeof(uint16_t);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the SupportedVersions extension
   n += sizeof(TlsExtension);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format KeyShare extension (HelloRetryRequest message)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the KeyShare extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatSelectedGroupExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Check whether the selected ECDHE or FFDHE group is valid
   if(context->namedGroup != TLS_GROUP_NONE)
   {
      TlsExtension *extension;

      //Add the KeyShare extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_KEY_SHARE);

      //The extension contains the mutually supported group the server intends
      //to negotiate
      STORE16BE(context->namedGroup, extension->value);

      //The extension data field contains a 16-bit unsigned integer
      n = sizeof(uint16_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the KeyShare extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format KeyShare extension (ServerHello message)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the KeyShare extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatServerKeyShareExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //If using (EC)DHE key establishment, servers offer exactly one
   //KeyShareEntry in the ServerHello
   if(context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_ECDHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
   {
      error_t error;
      TlsExtension *extension;
      Tls13KeyShareEntry *keyShareEntry;

      //Add the KeyShare extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_KEY_SHARE);

      //If using (EC)DHE key establishment, servers offer exactly one
      //KeyShareEntry in the ServerHello
      keyShareEntry = (Tls13KeyShareEntry *) extension->value;

      //The key share value must be in the same group as the KeyShareEntry
      //value offered by the client that the server has selected for the
      //negotiated key exchange
      keyShareEntry->group = htons(context->namedGroup);

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
      //ECDHE key exchange method?
      if(context->keyExchMethod == TLS13_KEY_EXCH_ECDHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
      {
         //ECDHE parameters are encoded in the opaque key_exchange field of
         //the KeyShareEntry
         error = ecExport(&context->ecdhContext.params,
            &context->ecdhContext.qa.q, keyShareEntry->keyExchange, &n);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
      //DHE key exchange method?
      if(context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE)
      {
         //Retrieve the length of the modulus
         n = mpiGetByteLength(&context->dhContext.params.p);

         //Diffie-Hellman parameters are encoded in the opaque key_exchange field
         //of the KeyShareEntry. The opaque value contains the Diffie-Hellman
         //public value for the specified group encoded as a big-endian integer
         //and padded to the left with zeros to the size of p in bytes
         error = mpiExport(&context->dhContext.ya,
            keyShareEntry->keyExchange, n, MPI_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
      //Unknown key exchange method?
      {
         //Report an error
         return ERROR_FAILURE;
      }

      //Set the length of the key_exchange field
      keyShareEntry->length = htons(n);

      //Compute the length, in bytes, of the KeyShareEntry
      n += sizeof(Tls13KeyShareEntry);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the KeyShare extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PreSharedKey extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PreSharedKey extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatServerPreSharedKeyExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
   {
      TlsExtension *extension;

      //Add the PreSharedKey extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_PRE_SHARED_KEY);

      //The extension contains the selected identity
      STORE16BE(context->selectedIdentity, extension->value);

      //The extension data field contains a 16-bit unsigned integer
      n = sizeof(uint16_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the PreSharedKey extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format EarlyData extension
 * @param[in] context Pointer to the TLS context
 * @param[in] msgType Handshake message type
 * @param[in] p Output stream where to write the EarlyData extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatServerEarlyDataExtension(TlsContext *context,
   TlsMessageType msgType, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //The extension may appear in EncryptedExtensions and NewSessionTicket
   //messages
   if(msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
   {
      //If the server intends to process the early data, then it returns its
      //own EarlyData extension in EncryptedExtensions
      if(context->earlyDataExtReceived && !context->earlyDataRejected)
      {
         TlsExtension *extension;

         //Add the EarlyData extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_EARLY_DATA);

         //The extension data field of this extension is empty
         extension->length = HTONS(0);

         //Compute the length, in bytes, of the EarlyData extension
         n = sizeof(TlsExtension);
      }
   }
   else if(msgType == TLS_TYPE_NEW_SESSION_TICKET)
   {
      TlsExtension *extension;

      //Add the EarlyData extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_EARLY_DATA);

      //The extension contains the maximum amount of 0-RTT data that the
      //client is allowed to send when using this ticket, in bytes
      STORE32BE(context->maxEarlyDataSize, extension->value);

      //The extension data field contains a 32-bit unsigned integer
      n = sizeof(uint32_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the EarlyData extension
      n += sizeof(TlsExtension);
   }
   else
   {
      //Just for sanity
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyShare extension
 * @param[in] context Pointer to the TLS context
 * @param[in] keyShareList Pointer to the KeyShare extension
 * @return Error code
 **/

error_t tls13ParseClientKeyShareExtension(TlsContext *context,
   const Tls13KeyShareList *keyShareList)
{
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //KeyShare extension found?
   if(keyShareList != NULL)
   {
      error_t error;
      bool_t acceptable;
      size_t n;
      size_t length;
      const uint8_t *p;
      const Tls13KeyShareEntry *keyShareEntry;

      //Initialize variables
      acceptable = FALSE;
      keyShareEntry = NULL;

      //Point to the first KeyShareEntry of the list
      p = keyShareList->value;
      //Retrieve the length of the list
      length = ntohs(keyShareList->length);

      //The extension contains a list of KeyShareEntry values offered by the
      //client. The values are indicated in descending order of preference
      while(length > 0 && !acceptable)
      {
         //Malformed extension?
         if(length < sizeof(Tls13KeyShareEntry))
            return ERROR_DECODING_FAILED;

         //Point to the current key share entry
         keyShareEntry = (Tls13KeyShareEntry *) p;
         //Retrieve the length of the key_exchange field
         n = ntohs(keyShareEntry->length);

         //Malformed extension?
         if(length < (sizeof(Tls13KeyShareEntry) + n))
            return ERROR_DECODING_FAILED;

         //Initial or updated ClientHello?
         if(context->state == TLS_STATE_CLIENT_HELLO)
         {
            //Check whether the ECDHE or FFDHE group is supported
            acceptable = tls13IsGroupSupported(context,
               ntohs(keyShareEntry->group));
         }
         else
         {
            //If the server has sent a HelloRetryRequest, the client needs
            //to restart the handshake with an appropriate group
            if(ntohs(keyShareEntry->group) == context->namedGroup)
            {
               //Check whether the ECDHE or FFDHE group is supported
               acceptable = tls13IsGroupSupported(context,
                  ntohs(keyShareEntry->group));
            }
         }

         //Point to the next entry
         p += sizeof(Tls13KeyShareEntry) + n;
         //Remaining bytes to process
         length -= sizeof(Tls13KeyShareEntry) + n;
      }

      //Acceptable ECDHE or FFDHE group found?
      if(acceptable)
      {
         //Generate an ephemeral key pair
         error = tls13GenerateKeyShare(context, ntohs(keyShareEntry->group));
         //Any error to report?
         if(error)
            return error;

         //Compute (EC)DHE shared secret
         error = tls13GenerateSharedSecret(context, keyShareEntry->keyExchange,
            ntohs(keyShareEntry->length));
         //Any error to report?
         if(error)
            return error;

         //Elliptic curve group?
         if(tls13IsEcdheGroupSupported(context, context->namedGroup))
         {
            //ECDHE key exchange mechanism provides forward secrecy
            if(context->keyExchMethod == TLS13_KEY_EXCH_PSK)
            {
               context->keyExchMethod = TLS13_KEY_EXCH_PSK_ECDHE;
            }
            else
            {
               context->keyExchMethod = TLS13_KEY_EXCH_ECDHE;
            }
         }
         //Finite field group?
         else if(tls13IsFfdheGroupSupported(context, context->namedGroup))
         {
            //DHE key exchange mechanism provides forward secrecy
            if(context->keyExchMethod == TLS13_KEY_EXCH_PSK)
            {
               context->keyExchMethod = TLS13_KEY_EXCH_PSK_DHE;
            }
            else
            {
               context->keyExchMethod = TLS13_KEY_EXCH_DHE;
            }
         }
         //Unknown group?
         else
         {
            //Just for sanity
            return ERROR_FAILURE;
         }
      }
      else
      {
         //If no common cryptographic parameters can be negotiated, the server
         //must abort the handshake with an appropriate alert
         if(context->state == TLS_STATE_CLIENT_HELLO_2)
            return ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PskKeyExchangeModes extension
 * @param[in] context Pointer to the TLS context
 * @param[in] pskKeModeList Pointer to the PskKeyExchangeModes extension
 * @return Error code
 **/

error_t tls13ParsePskKeModesExtension(TlsContext *context,
   const Tls13PskKeModeList *pskKeModeList)
{
   error_t error;
   uint_t i;

   //PskKeyExchangeModes extension found?
   if(pskKeModeList != NULL)
   {
      //Check whether the client supports session resumption with a PSK
      for(i = 0; i < pskKeModeList->length; i++)
      {
         //PSK key establishment supported?
         if(pskKeModeList->value[i] == TLS_PSK_KEY_EXCH_MODE_PSK_KE ||
            pskKeModeList->value[i] == TLS_PSK_KEY_EXCH_MODE_PSK_DHE_KE)
         {
            context->pskKeModeSupported = TRUE;
         }
      }
   }

   //PSK key exchange method?
   if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
   {
      //PskKeyExchangeModes extension found?
      if(pskKeModeList != NULL)
      {
         //Initialize status code
         error = ERROR_HANDSHAKE_FAILED;

         //The extension contains a list of supported PSK key exchange modes
         for(i = 0; i < pskKeModeList->length && error; i++)
         {
#if (TLS13_PSK_KE_SUPPORT == ENABLED)
            //PSK-only key establishment?
            if(pskKeModeList->value[i] == TLS_PSK_KEY_EXCH_MODE_PSK_KE)
            {
               //Servers must not select a key exchange mode that is not listed
               //by the client
               if(context->keyExchMethod == TLS13_KEY_EXCH_PSK)
               {
                  error = NO_ERROR;
               }
            }
            else
#endif
#if (TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
            //PSK with (EC)DHE key establishment?
            if(pskKeModeList->value[i] == TLS_PSK_KEY_EXCH_MODE_PSK_DHE_KE)
            {
               //Servers must not select a key exchange mode that is not listed
               //by the client
               if(context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
                  context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
               {
                  error = NO_ERROR;
               }
            }
            else
#endif
            //Unknown key exchange method?
            {
               //Just for sanity
            }
         }
      }
      else
      {
         //A client must provide a PskKeyExchangeModes extension if it offers a
         //PreSharedKey extension
         error = ERROR_MISSING_EXTENSION;
      }
   }
   else
   {
      //If no acceptable PSKs are found, the server should perform a non-PSK
      //handshake if possible
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse PreSharedKey extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] identityList List of the identities that the client is willing
 *   to negotiate with the server
 * @param[in] binderList List of HMAC values, one for each PSK offered in the
 *   PreSharedKey extension
 * @return Error code
 **/

error_t tls13ParseClientPreSharedKeyExtension(TlsContext *context,
   const TlsClientHello *clientHello, size_t clientHelloLen,
   const Tls13PskIdentityList *identityList, const Tls13PskBinderList *binderList)
{
 #if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //PreSharedKey extension found?
   if(identityList != NULL && binderList != NULL)
   {
      error_t error;
      int_t i;
      size_t n;
      size_t m;
      uint32_t obfuscatedTicketAge;
      const uint8_t *p;
      const uint8_t *q;
      const Tls13PskIdentity *identity;
      const Tls13PskBinder *binder;
      const HashAlgo *hashAlgo;

      //Initialize variables
      identity = NULL;
      binder = NULL;

      //Reset the server's chosen identity to its default value
      context->selectedIdentity = -1;

      //Debug message
      TRACE_DEBUG("PSK identity list:\r\n");
      TRACE_DEBUG_ARRAY("  ", identityList, ntohs(identityList->length) + 2);
      TRACE_DEBUG("PSK binder list:\r\n");
      TRACE_DEBUG_ARRAY("  ", binderList, ntohs(binderList->length) + 2);

      //Point to the list of the identities that the client is willing to
      //negotiate with the server
      p = identityList->value;
      n = ntohs(identityList->length);

      //Point to the list of HMAC values, one for each PSK offered in the
      //PreSharedKey extension
      q = binderList->value;
      m = ntohs(binderList->length);

      //Loop through the list of PSK identities
      for(i = 0; n > 0; i++)
      {
         //Point to the current PskIdentity entry
         identity = (Tls13PskIdentity *) p;

         //Malformed PreSharedKey extension?
         if(n < sizeof(TlsPskIdentity))
            return ERROR_DECODING_FAILED;
         if(n < (sizeof(TlsPskIdentity) + ntohs(identity->length)))
            return ERROR_DECODING_FAILED;

         //Debug message
         TRACE_DEBUG("PSK identity #%u:\r\n", i);
         TRACE_DEBUG_ARRAY("  ", identity->value, ntohs(identity->length));

         //Point to the obfuscated_ticket_age field
         p += sizeof(TlsPskIdentity) + ntohs(identity->length);
         n -= sizeof(TlsPskIdentity) + ntohs(identity->length);

         //Malformed PreSharedKey extension?
         if(n < sizeof(uint32_t))
            return ERROR_DECODING_FAILED;

         //The obfuscated_ticket_age field is a 32-bit unsigned integer
         obfuscatedTicketAge = LOAD32BE(p);

         //Point to the next PskIdentity entry
         p += sizeof(uint32_t);
         n -= sizeof(uint32_t);

         //Point to the PskBinderEntry
         binder = (Tls13PskBinder *) q;

         //If the binder is not present, the server must abort the handshake
         if(context->selectedIdentity >= 0 && m == 0)
            return ERROR_ILLEGAL_PARAMETER;

         //Malformed PreSharedKey extension?
         if(m < sizeof(Tls13PskBinder))
            return ERROR_DECODING_FAILED;
         if(m < (sizeof(Tls13PskBinder) + binder->length))
            return ERROR_DECODING_FAILED;

         //Debug message
         TRACE_DEBUG("PSK binder #%u:\r\n", i);
         TRACE_DEBUG_ARRAY("  ", binder->value, binder->length);

         //Point to the next PskBinderEntry
         q += sizeof(Tls13PskBinder) + binder->length;
         m -= sizeof(Tls13PskBinder) + binder->length;

         //The server should select a single PSK
         if(context->selectedIdentity < 0)
         {
            //Any registered callback?
            if(context->pskCallback != NULL)
            {
               //Check whether the PSK identity provided by the client matches
               //any externally established PSK
               error = context->pskCallback(context, identity->value,
                  ntohs(identity->length));

               //Valid PSK?
               if(!error && tls13IsPskValid(context))
               {
                  //For externally established PSKs, the hash algorithm must be
                  //set when the PSK is established
                  hashAlgo = tlsGetHashAlgo(context->pskHashAlgo);

                  //Make sure the hash algorithm is valid
                  if(hashAlgo != NULL)
                  {
                     //Save the hash algorithm associated with the PSK
                     context->cipherSuite.prfHashAlgo = hashAlgo;

                     //The server's chosen identity is expressed as a 0-based
                     //index into the identities in the client's list
                     context->selectedIdentity = i;
                  }
               }
            }
         }

         //The server should select a single PSK
         if(context->selectedIdentity < 0)
         {
            //Decrypt the received ticket and verify the ticket's validity
            error = tls13VerifyTicket(context, identity->value,
               htons(identity->length), obfuscatedTicketAge);

            //Valid ticket?
            if(!error)
            {
               //The server's chosen identity is expressed as a 0-based index
               //into the identities in the client's list
               context->selectedIdentity = i;
            }
         }
      }

      //Extra binders found?
      if(m != 0)
      {
         return ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   {
      //Initial or updated ClientHello?
      if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         //When responding to a HelloRetryRequest, the client must send the
         //same ClientHello without modification
         if(context->selectedIdentity >= 0)
         {
            return ERROR_ILLEGAL_PARAMETER;
         }
      }

      //The ClientHello message does not contain any PreSharedKey extension
      context->selectedIdentity = -1;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EarlyData extension
 * @param[in] context Pointer to the TLS context
 * @param[in] earlyDataIndication Pointer to the EarlyData extension
 * @return Error code
 **/

error_t tls13ParseClientEarlyDataExtension(TlsContext *context,
   const TlsExtension *earlyDataIndication)
{
   //EarlyData extension found?
   if(earlyDataIndication != NULL)
   {
      //Early data is not permitted after a HelloRetryRequest (refer to
      //RFC 8446, section 4.1.2)
      if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         context->earlyDataRejected = TRUE;
      }

      //In order to accept early data, the server must have accepted a PSK
      //cipher suite and selected the first key offered in the client's
      //PreSharedKey extension (refer to RFC 8446, section 4.2.10)
      if(context->selectedIdentity != 0)
      {
         context->earlyDataRejected = TRUE;
      }

      //A valid EarlyData extension has been received
      context->earlyDataExtReceived = TRUE;
   }
   else
   {
      //The ClientHello message does not contain any EarlyData extension
      context->earlyDataExtReceived = FALSE;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
