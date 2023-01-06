/**
 * @file tls13_client_extensions.c
 * @brief Formatting and parsing of extensions (TLS 1.3 client)
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
#include "tls13_client_extensions.h"
#include "tls13_ticket.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Format Cookie extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the Cookie extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatCookieExtension(TlsContext *context, uint8_t *p,
   size_t *written)
{
   size_t n;
   TlsExtension *extension;
   Tls13Cookie *cookie;

   //Initialize length field
   n = 0;

   //When sending a HelloRetryRequest, the server may provide a Cookie
   //extension to the client
   if(context->cookieLen > 0)
   {
      //Add the Cookie extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_COOKIE);

      //Point to the extension data field
      cookie = (Tls13Cookie *) extension->value;

      //When sending the new ClientHello, the client must copy the contents
      //of the Cookie extension received in the HelloRetryRequest
      osMemcpy(cookie->value, context->cookie, context->cookieLen);

      //Set the length of the cookie
      cookie->length = ntohs(context->cookieLen);

      //Consider the 2-byte length field that precedes the cookie
      n = sizeof(Tls13Cookie) + context->cookieLen;
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the Cookie extension
      n += sizeof(TlsExtension);
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format KeyShare extension (ClientHello message)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the KeyShare extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatClientKeyShareExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   error_t error;
   TlsExtension *extension;
   Tls13KeyShareList *keyShareList;
   Tls13KeyShareEntry *keyShareEntry;

   //Add the KeyShare extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_KEY_SHARE);

   //The extension contains a list of offered KeyShareEntry values in
   //descending order of client preference
   keyShareList = (Tls13KeyShareList *) extension->value;

   //Point to the KeyShareEntry
   keyShareEntry = (Tls13KeyShareEntry *) keyShareList->value;

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(tls13IsEcdheGroupSupported(context, context->namedGroup))
   {
      //Specify the named group for the key being exchanged
      keyShareEntry->group = htons(context->namedGroup);

      //ECDHE parameters are encoded in the opaque key_exchange field of
      //the KeyShareEntry
      error = ecExport(&context->ecdhContext.params,
         &context->ecdhContext.qa.q, keyShareEntry->keyExchange, &n);
      //Any error to report?
      if(error)
         return error;

      //Set the length of the key_exchange field
      keyShareEntry->length = htons(n);

      //Compute the length of the KeyShareEntry
      n += sizeof(Tls13KeyShareEntry);
   }
   else
#endif
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
   //Finite field group?
   if(tls13IsFfdheGroupSupported(context, context->namedGroup))
   {
#if (TLS_FFDHE_SUPPORT == ENABLED)
      //Specify the named group for the key being exchanged
      keyShareEntry->group = htons(context->namedGroup);

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

      //Set the length of the key_exchange field
      keyShareEntry->length = htons(n);

      //Compute the length of the KeyShareEntry
      n += sizeof(Tls13KeyShareEntry);
#endif
   }
   else
#endif
   //Unknown group?
   {
      //Clients may send an empty client_shares vector in order to request group
      //selection from the server, at the cost of an additional round trip
   }

   //Fix the length of the list of offered key shares
   keyShareList->length = htons(n);

   //Consider the 2-byte length field that precedes the list
   n += sizeof(Tls13KeyShareList);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the KeyShare extension
   n += sizeof(TlsExtension);
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PskKeyExchangeModes extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PskKeyExchangeModes extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatPskKeModesExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   TlsExtension *extension;
   Tls13PskKeModeList *pskKeModeList;

   //Add the PskKeyExchangeModes extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_PSK_KEY_EXCHANGE_MODES);

   //Point to the extension data field
   pskKeModeList = (Tls13PskKeModeList *) extension->value;
   //The extension contains a list of supported PSK key exchange modes
   n = 0;

#if (TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //PSK with (EC)DHE key establishment
   pskKeModeList->value[n++] = TLS_PSK_KEY_EXCH_MODE_PSK_DHE_KE;
#endif
#if (TLS13_PSK_KE_SUPPORT == ENABLED)
   //PSK-only key establishment
   pskKeModeList->value[n++] = TLS_PSK_KEY_EXCH_MODE_PSK_KE;
#endif

   //Fix the length of the list
   pskKeModeList->length = (uint8_t) n;

   //Consider the length field that precedes the list
   n += sizeof(Tls13PskKeModeList);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the PskKeyExchangeModes extension
   n += sizeof(TlsExtension);
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
 * @param[out] identityList Pointer to the list of the identities that the
 *   client is willing to negotiate with the server
 * @param[out] binderList Pointer to the list of HMAC values, one for each PSK
 *   offered in the PreSharedKey extension
 * @return Error code
 **/

error_t tls13FormatClientPreSharedKeyExtension(TlsContext *context,
   uint8_t *p, size_t *written, Tls13PskIdentityList **identityList,
   Tls13PskBinderList **binderList)
{
   size_t n = 0;

#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Check whether the client is attempting a PSK key establishment
   if(tls13IsPskValid(context) || tls13IsTicketValid(context))
   {
      error_t error;
      size_t m;
      uint16_t cipherSuite;
      uint32_t ticketAge;
      TlsExtension *extension;
      TlsPskIdentity *pskIdentity;
      Tls13PskBinder *pskBinder;
      const HashAlgo *hashAlgo;

      //Add the PreSharedKey extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_PRE_SHARED_KEY);

      //Point to the extension data field
      *identityList = (Tls13PskIdentityList *) extension->value;
      //Point to the first PskIdentity entry of the list
      pskIdentity = (TlsPskIdentity *) (*identityList)->value;

      //Although PSKs can be established out of band, PSKs can also be
      //established in a previous connection
      if(tls13IsPskValid(context))
      {
         //Retrieve the length of the PSK identity
         n = osStrlen(context->pskIdentity);
         //Copy PSK identity
         osMemcpy(pskIdentity->value, context->pskIdentity, n);

         //For externally established PSKs, the hash algorithm must be set when
         //the PSK is established or default to SHA-256 if no such algorithm is
         //defined
         hashAlgo = tlsGetHashAlgo(context->pskHashAlgo);

         //Retrieve the cipher suite associated with the PSK, if any
         cipherSuite = context->pskCipherSuite;

         //For PSK identities established externally, an obfuscated_ticket_age
         //of 0 should be used (refer to RFC 8446, section 4.2.11)
         ticketAge = 0;
      }
      else if(tls13IsTicketValid(context))
      {
         //Retrieve the length of the session ticket
         n = context->ticketLen;
         //Copy session ticket
         osMemcpy(pskIdentity->value, context->ticket, n);

         //Each PSK is associated with a single hash algorithm. For PSKs
         //established via the ticket mechanism, this is the KDF hash algorithm
         //on the connection where the ticket was established
         hashAlgo = tlsGetHashAlgo(context->ticketHashAlgo);

         //Retrieve the cipher suite associated with the ticket
         cipherSuite = context->ticketCipherSuite;

         //The client's view of the age of a ticket is the time since the
         //receipt of the NewSessionTicket message
         ticketAge = context->clientHelloTimestamp - context->ticketTimestamp;

         //The obfuscated_ticket_age field contains an obfuscated version of
         //the ticket age formed by taking the age in milliseconds and adding
         //the ticket_age_add value that was included with the ticket
         ticketAge += context->ticketAgeAdd;
      }
      else
      {
         //Just for sanity
         return ERROR_FAILURE;
      }

      //Valid cipher suite provisioned?
      if(cipherSuite != 0)
      {
         //Restore the cipher suite associated with the PSK
         error = tlsSelectCipherSuite(context, cipherSuite);
         //Any error to report?
         if(error)
            return error;
      }
      else
      {
         //Make sure the hash algorithm is valid
         if(hashAlgo == NULL)
            return ERROR_FAILURE;

         //Restore the hash algorithm associated with the PSK
         context->cipherSuite.prfHashAlgo = hashAlgo;
      }

      //Fix the length of the PSK identity
      pskIdentity->length = htons(n);
      //Consider the length field that precedes the PSK identity
      n += sizeof(TlsPskIdentity);

      //The obfuscated_ticket_age field is a 32-bit unsigned integer
      STORE32BE(ticketAge, (uint8_t *) pskIdentity + n);
      //Compute the length of the PskIdentity entry
      n += sizeof(uint32_t);

      //Fix the length of the list of PSK identities
      (*identityList)->length = htons(n);
      //Consider the 2-byte length field that precedes the list
      n += sizeof(Tls13PskIdentityList);

      //Point to the list of PSK binders
      *binderList = (Tls13PskBinderList *) ((uint8_t *) *identityList + n);
      //Point to the first PskBinderEntry of the list
      pskBinder = (Tls13PskBinder *) (*binderList)->value;

      //The PSK binder consists of Hash.length bytes
      m = hashAlgo->digestSize;
      //The value of the PSK binder will be calculated in a second step
      osMemset(pskBinder->value, 0, m);

      //Fix the length of the PSK binder
      pskBinder->length = (uint8_t) m;
      //Consider the length field that precedes the PSK binder
      m += sizeof(Tls13PskBinder);

      //Fix the length of the list of PSK binders
      (*binderList)->length = htons(m);
      //Consider the 2-byte length field that precedes the list
      n += sizeof(Tls13PskBinderList) + m;

      //Fix the length of the extension
      extension->length = htons(n);
      //Compute the length, in bytes, of the PreSharedKey extension
      n += sizeof(TlsExtension);
   }
   else
#endif
   {
      //PSK key establishment is not used
      *identityList = NULL;
      *binderList = NULL;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format EarlyData extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the EarlyData extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatClientEarlyDataExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //If the client opts to send application data in its first flight of
   //messages, it must supply both the PreSharedKey and EarlyData extensions
   if(context->earlyDataEnabled && !context->earlyDataRejected)
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
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] selectedVersion Pointer to the SupportedVersions extension
 * @return Error code
 **/

error_t tls13ParseServerSupportedVersionsExtension(TlsContext *context,
   const TlsExtension *selectedVersion)
{
   error_t error;
   uint16_t version;

   //The extension contains the selected version value
   version = LOAD16BE(selectedVersion->value);

   //If the SupportedVersions extension contains a version prior to TLS 1.3,
   //the client must abort the handshake with an illegal_parameter alert
   if(version < TLS_VERSION_1_3)
      return ERROR_ILLEGAL_PARAMETER;

   //Debug message
   TRACE_INFO("  selectedVersion = 0x%04" PRIX16 " (%s)\r\n",
      version, tlsGetVersionName(version));

   //Set the TLS version to be used
   error = tlsSelectVersion(context, version);
   //Specified TLS/DTLS version not supported?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Cookie extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cookie Pointer to the Cookie extension
 * @return Error code
 **/

error_t tls13ParseCookieExtension(TlsContext *context,
   const Tls13Cookie *cookie)
{
   //Cookie extension found?
   if(cookie != NULL)
   {
      size_t n;

      //Retrieve the length of the cookie
      n = ntohs(cookie->length);

      //Clients must abort the handshake with an illegal_parameter alert if the
      //HelloRetryRequest would not result in any change in the ClientHello
      if(n == 0)
         return ERROR_ILLEGAL_PARAMETER;

      //Check the length of the cookie
      if(n > TLS13_MAX_COOKIE_SIZE)
         return ERROR_ILLEGAL_PARAMETER;

      //Sanity check
      if(context->cookie != NULL)
      {
         //Release memory
         tlsFreeMem(context->cookie);
         context->cookie = NULL;
         context->cookieLen = 0;
      }

      //Allocate a memory block to store the cookie
      context->cookie = tlsAllocMem(n);
      //Failed to allocate memory?
      if(context->cookie == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save cookie
      osMemcpy(context->cookie, cookie->value, n);
      context->cookieLen = n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyShare extension (HelloRetryRequest message)
 * @param[in] context Pointer to the TLS context
 * @param[in] selectedGroup Pointer to the KeyShare extension
 * @return Error code
 **/

error_t tls13ParseSelectedGroupExtension(TlsContext *context,
   const TlsExtension *selectedGroup)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //KeyShare extension found?
   if(selectedGroup != NULL)
   {
      uint16_t namedGroup;

      //The KeyShare extension contains the mutually supported group the server
      //intends to negotiate
      namedGroup = LOAD16BE(selectedGroup->value);

      //Check whether the server has selected a different ECDHE or FFDHE group
      if(namedGroup != context->namedGroup)
      {
         //Generate an ephemeral key pair
         error = tls13GenerateKeyShare(context, namedGroup);
      }
   }
#else
   //KeyShare extension found?
   if(selectedGroup != NULL)
   {
      //If a client receives an extension type that it did not request in the
      //ClientHello, it must abort the handshake with an unsupported_extension
      //fatal alert
      error = ERROR_UNSUPPORTED_EXTENSION;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse KeyShare extension (ServerHello message)
 * @param[in] context Pointer to the TLS context
 * @param[in] serverShare Pointer to the KeyShare extension
 * @return Error code
 **/

error_t tls13ParseServerKeyShareExtension(TlsContext *context,
   const Tls13KeyShareEntry *serverShare)
{
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry
   //in the ServerHello
   if(serverShare != NULL)
   {
      error_t error;
      uint16_t namedGroup;

      //Convert the selected NamedGroup to host byte order
      namedGroup = ntohs(serverShare->group);

      //Elliptic curve group?
      if(tls13IsEcdheGroupSupported(context, namedGroup))
      {
         //ECDHE key exchange mechanism provides forward secrecy
         context->keyExchMethod = TLS13_KEY_EXCH_ECDHE;
      }
      //Finite field group?
      else if(tls13IsFfdheGroupSupported(context, namedGroup))
      {
         //DHE key exchange mechanism provides forward secrecy
         context->keyExchMethod = TLS13_KEY_EXCH_DHE;
      }
      //Unknown group?
      else
      {
         //Servers must not send a KeyShareEntry for any group not indicated
         //in the client's SupportedGroups extension
         return ERROR_ILLEGAL_PARAMETER;
      }

      //The client must verify that the selected NamedGroup in the ServerHello
      //is the same as that in the HelloRetryRequest
      if(namedGroup != context->namedGroup)
         return ERROR_ILLEGAL_PARAMETER;

      //Compute (EC)DHE shared secret
      error = tls13GenerateSharedSecret(context, serverShare->keyExchange,
         ntohs(serverShare->length));
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //PSKs can be used alone, at the cost of losing forward secrecy for
      //the application data
      context->keyExchMethod = TLS_KEY_EXCH_NONE;
   }
#else
   //KeyShareEntry extension found?
   if(serverShare != NULL)
   {
      //If a client receives an extension type that it did not request in the
      //ClientHello, it must abort the handshake with an unsupported_extension
      //fatal alert
      return ERROR_UNSUPPORTED_EXTENSION;
   }
   else
   {
      //Perform a PSK handshake if possible
      context->keyExchMethod = TLS_KEY_EXCH_NONE;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PreSharedKey extension
 * @param[in] context Pointer to the TLS context
 * @param[in] selectedIdentity Pointer to the PreSharedKey extension
 * @return Error code
 **/

error_t tls13ParseServerPreSharedKeyExtension(TlsContext *context,
   const TlsExtension *selectedIdentity)
{
   //Reset the server's selected_identity to its default value
   context->selectedIdentity = -1;

#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //PreSharedKey extension found?
   if(selectedIdentity != NULL)
   {
      const HashAlgo *hashAlgo;

      //If a client receives an extension type that it did not request in the
      //ClientHello, it must abort the handshake with an unsupported_extension
      //fatal alert
      if(!tls13IsPskValid(context) && !tls13IsTicketValid(context))
         return ERROR_UNSUPPORTED_EXTENSION;

      //In order to accept PSK key establishment, the server sends a
      //PreSharedKey extension indicating the selected identity
      context->selectedIdentity = LOAD16BE(selectedIdentity->value);

      //Clients must verify that the server's selected_identity is within the
      //range supplied by the client (refer to RFC 8446, section 4.2.11)
      if(context->selectedIdentity != 0)
         return ERROR_ILLEGAL_PARAMETER;

      //Point to the cipher suite hash algorithm
      hashAlgo = context->cipherSuite.prfHashAlgo;
      //Make sure the hash algorithm is valid
      if(hashAlgo == NULL)
         return ERROR_FAILURE;

      //Clients must also verify that the server has selected a cipher suite
      //indicating a hash algorithm associated with the PSK
      if(tls13IsPskValid(context))
      {
         //PSK incompatible with the selected cipher suite?
         if(tlsGetHashAlgo(context->pskHashAlgo) != hashAlgo)
            return ERROR_ILLEGAL_PARAMETER;
      }
      else if(tls13IsTicketValid(context))
      {
         //PSK incompatible with the selected cipher suite?
         if(tlsGetHashAlgo(context->ticketHashAlgo) != hashAlgo)
            return ERROR_ILLEGAL_PARAMETER;
      }
      else
      {
         //Just for sanity
      }

      //PSKs can be used with (EC)DHE key exchange in order to provide forward
      //secrecy in combination with shared keys, or can be used alone, at the
      //cost of losing forward secrecy for the application data
#if (TLS13_PSK_KE_SUPPORT == ENABLED)
      if(context->keyExchMethod == TLS_KEY_EXCH_NONE)
      {
         context->keyExchMethod = TLS13_KEY_EXCH_PSK;
      }
#endif
#if (TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
      if(context->keyExchMethod == TLS13_KEY_EXCH_DHE)
      {
         context->keyExchMethod = TLS13_KEY_EXCH_PSK_DHE;
      }
#endif
#if (TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
      if(context->keyExchMethod == TLS13_KEY_EXCH_ECDHE)
      {
         context->keyExchMethod = TLS13_KEY_EXCH_PSK_ECDHE;
      }
#endif
   }
#else
   //PreSharedKey extension found?
   if(selectedIdentity != NULL)
   {
      //If a client receives an extension type that it did not request in the
      //ClientHello, it must abort the handshake with an unsupported_extension
      //fatal alert
      return ERROR_UNSUPPORTED_EXTENSION;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EarlyData extension
 * @param[in] msgType Handshake message type
 * @param[in] context Pointer to the TLS context
 * @param[in] earlyDataIndication Pointer to the EarlyData extension
 * @return Error code
 **/

error_t tls13ParseServerEarlyDataExtension(TlsContext *context,
   TlsMessageType msgType, const TlsExtension *earlyDataIndication)
{
#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //The extension may appear in EncryptedExtensions and NewSessionTicket
   //messages
   if(msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
   {
      //EarlyData extension found?
      if(earlyDataIndication != NULL)
      {
         //If a client receives an extension type that it did not request in the
         //ClientHello, it must abort the handshake with an unsupported_extension
         //fatal alert
         if(!context->earlyDataEnabled || context->earlyDataRejected)
            return ERROR_UNSUPPORTED_EXTENSION;

         //If the server has supplied an EarlyData extension, the client must
         //verify that the server's selected_identity is 0. If any other value
         //is returned, it must abort the handshake with an illegal_parameter
         //fatal alert
         if(context->selectedIdentity != 0)
            return ERROR_ILLEGAL_PARAMETER;

         //A valid EarlyData extension has been received
         context->earlyDataExtReceived = TRUE;
      }
      else
      {
         //The EncryptedExtensions message does not contain any EarlyData
         //extension
         context->earlyDataExtReceived = FALSE;
      }
   }
   else if(msgType == TLS_TYPE_NEW_SESSION_TICKET)
   {
      //The extension contains the maximum amount of 0-RTT data that the client
      //is allowed to send
      if(earlyDataIndication != NULL)
         context->maxEarlyDataSize = LOAD32BE(earlyDataIndication->value);
      else
         context->maxEarlyDataSize = 0;
   }
   else
   {
      //Just for sanity
   }
#else
   //Check message type
   if(msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
   {
      //EarlyData extension found?
      if(earlyDataIndication != NULL)
      {
         //If a client receives an extension type that it did not request in the
         //ClientHello, it must abort the handshake with an unsupported_extension
         //fatal alert
         return ERROR_UNSUPPORTED_EXTENSION;
      }
   }
   else if(msgType == TLS_TYPE_NEW_SESSION_TICKET)
   {
      //Early data is not implemented
      context->maxEarlyDataSize = 0;
   }
   else
   {
      //Just for sanity
   }
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
