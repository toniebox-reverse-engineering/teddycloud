/**
 * @file tls_client.c
 * @brief Handshake message processing (TLS client)
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
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
#include "tls_handshake.h"
#include "tls_client.h"
#include "tls_client_extensions.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_extensions.h"
#include "tls_certificate.h"
#include "tls_signature.h"
#include "tls_key_material.h"
#include "tls_transcript_hash.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_client.h"
#include "tls13_client_extensions.h"
#include "tls13_client_misc.h"
#include "dtls_record.h"
#include "dtls_misc.h"
#include "pkix/pem_import.h"
#include "date_time.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send ClientHello message
 *
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message. The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendClientHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsClientHello *message;

   //Point to the buffer where to format the message
   message = (TlsClientHello *) (context->txBuffer + context->txBufferLen);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //When sending the first ClientHello, the client does not have a cookie yet
      if(context->cookieLen == 0)
      {
         //Generate the client random value using a cryptographically-safe
         //pseudorandom number generator
         error = tlsGenerateRandomValue(context, context->clientRandom);
      }
      else
      {
         //When responding to a HelloVerifyRequest, the client must use the
         //same random value as it did in the original ClientHello
         error = NO_ERROR;
      }
   }
   else
#endif
   //TLS protocol?
   {
      //Initial or updated ClientHello?
      if(context->state == TLS_STATE_CLIENT_HELLO)
      {
         //Generate the client random value using a cryptographically-safe
         //pseudorandom number generator
         error = tlsGenerateRandomValue(context, context->clientRandom);
      }
      else
      {
         //When responding to a HelloRetryRequest, the client must use the
         //same random value as it did in the initial ClientHello
         error = NO_ERROR;
      }
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check status code
   if(!error)
   {
      //In versions of TLS prior to TLS 1.3, the SessionTicket extension is used
      //to resume a TLS session without requiring session-specific state at the
      //TLS server
      if(context->versionMin <= TLS_VERSION_1_2)
      {
         //Initial ClientHello?
         if(context->state == TLS_STATE_CLIENT_HELLO)
         {
#if (TLS_TICKET_SUPPORT == ENABLED)
            //When presenting a ticket, the client may generate and include a
            //session ID in the TLS ClientHello
            if(tlsIsTicketValid(context) && context->sessionIdLen == 0)
            {
               //If the server accepts the ticket and the session ID is not
               //empty, then it must respond with the same session ID present in
               //the ClientHello. This allows the client to easily differentiate
               //when the server is resuming a session from when it is falling
               //back to a full handshake
               error = tlsGenerateSessionId(context, 32);
            }
#endif
         }
      }
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Check status code
   if(!error)
   {
      //TLS 1.3 supported by the client?
      if(context->versionMax >= TLS_VERSION_1_3 &&
         context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Initial or updated ClientHello?
         if(context->state == TLS_STATE_CLIENT_HELLO)
         {
#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
            //In compatibility mode the session ID field must be non-empty
            if(context->sessionIdLen == 0)
            {
               //A client not offering a pre-TLS 1.3 session must generate a
               //new 32-byte value. This value need not be random but should
               //be unpredictable to avoid implementations fixating on a
               //specific value (refer to RFC 8446, section 4.1.2)
               error = tlsGenerateSessionId(context, 32);
            }
#endif
            //Check status code
            if(!error)
            {
               //Any preferred ECDHE or FFDHE group?
               if(tls13IsGroupSupported(context, context->preferredGroup))
               {
                  //Pregenerate key share using preferred named group
                  error = tls13GenerateKeyShare(context, context->preferredGroup);
               }
               else
               {
                  //Request group selection from the server, at the cost of an
                  //additional round trip
                  context->preferredGroup = TLS_GROUP_NONE;
               }
            }
         }
         else
         {
            //The updated ClientHello message is not encrypted
            tlsFreeEncryptionEngine(&context->encryptionEngine);
         }
      }

      //Save current time
      context->clientHelloTimestamp = osGetSystemTime();
   }
#endif

   //Check status code
   if(!error)
   {
      //Format ClientHello message
      error = tlsFormatClientHello(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ClientHello message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_CLIENT_HELLO);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Initial ClientHello?
      if(context->state == TLS_STATE_CLIENT_HELLO)
      {
         //Wait for a ServerHello or HelloRetryRequest message
         context->state = TLS_STATE_SERVER_HELLO;
      }
      else
      {
         //Wait for a ServerHello message
         context->state = TLS_STATE_SERVER_HELLO_2;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ClientKeyExchange message
 *
 * This message is always sent by the client. It must immediately
 * follow the client Certificate message, if it is sent. Otherwise,
 * it must be the first message sent by the client after it receives
 * the ServerHelloDone message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendClientKeyExchange(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsClientKeyExchange *message;

   //Point to the buffer where to format the message
   message = (TlsClientKeyExchange *) (context->txBuffer + context->txBufferLen);

   //Format ClientKeyExchange message
   error = tlsFormatClientKeyExchange(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ClientKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_CLIENT_KEY_EXCHANGE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Derive session keys from the premaster secret
      error = tlsGenerateSessionKeys(context);

      //Key material successfully generated?
      if(!error)
      {
         //Send a CertificateVerify message to the server
         context->state = TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format ClientHello message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ClientHello message
 * @param[out] length Length of the resulting ClientHello message
 * @return Error code
 **/

error_t tlsFormatClientHello(TlsContext *context,
   TlsClientHello *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   uint_t cipherSuiteTypes;
   TlsExtensionList *extensionList;

   //In TLS 1.3, the client indicates its version preferences in the
   //SupportedVersions extension and the legacy_version field must be
   //set to 0x0303, which is the version number for TLS 1.2
   context->clientVersion = MIN(context->versionMax, TLS_VERSION_1_2);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Translate TLS version into DTLS version
      context->clientVersion = dtlsTranslateVersion(context->clientVersion);
   }
#endif

   //In previous versions of TLS, the version field is used for version
   //negotiation and represents the highest version number supported by
   //the client
   message->clientVersion = htons(context->clientVersion);

   //Client random value
   osMemcpy(message->random, context->clientRandom, 32);

   //Point to the session ID
   p = message->sessionId;
   //Length of the handshake message
   *length = sizeof(TlsClientHello);

   //The session ID value identifies a session the client wishes to reuse for
   //this connection
   error = tlsFormatSessionId(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the session ID
   message->sessionIdLen = (uint8_t) n;

   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Format Cookie field
      error = dtlsFormatCookie(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Adjust the length of the message
      *length += n;
   }
#endif

   //Format the list of cipher suites supported by the client
   error = tlsFormatCipherSuites(context, &cipherSuiteTypes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //Format the list of compression methods supported by the client
   error = tlsFormatCompressMethods(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //Clients may request extended functionality from servers by sending
   //data in the extensions field
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);

   //In TLS 1.2, the client can indicate its version preferences in the
   //SupportedVersions extension
   error = tlsFormatClientSupportedVersionsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName
   //extension
   error = tlsFormatClientSniExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //In order to negotiate smaller maximum fragment lengths, clients may
   //include a MaxFragmentLength extension
   error = tlsFormatClientMaxFragLenExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //The value of RecordSizeLimit is the maximum size of record in octets
   //that the endpoint is willing to receive
   error = tlsFormatClientRecordSizeLimitExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

   //A client that proposes ECC/FFDHE cipher suites in its ClientHello message
   //should send the SupportedGroups extension
   error = tlsFormatSupportedGroupsExtension(context, cipherSuiteTypes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

   //A client that proposes ECC cipher suites in its ClientHello message
   //should send the EcPointFormats extension
   error = tlsFormatClientEcPointFormatsExtension(context, cipherSuiteTypes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

   //Include the SignatureAlgorithms extension only if TLS 1.2 is supported
   error = tlsFormatSignatureAlgorithmsExtension(context, cipherSuiteTypes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

#if (TLS_SIGN_ALGOS_CERT_SUPPORT == ENABLED)
   //The SignatureAlgorithmsCert extension allows a client to indicate which
   //signature algorithms it can validate in X.509 certificates
   error = tlsFormatSignatureAlgorithmsCertExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the list of protocols advertised by the
   //client, in descending order of preference
   error = tlsFormatClientAlpnExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //In order to indicate the support of raw public keys, clients include the
   //ClientCertType extension in an extended ClientHello message
   error = tlsFormatClientCertTypeListExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

   //In order to indicate the support of raw public keys, clients include the
   //ServerCertType extension in an extended ClientHello message
   error = tlsFormatServerCertTypeListExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //In all handshakes, a client implementing RFC 7627 must send the
   //ExtendedMasterSecret extension in its ClientHello
   error = tlsFormatClientEmsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_TICKET_SUPPORT == ENABLED)
   //The SessionTicket extension is used to resume a TLS session without
   //requiring session-specific state at the TLS server
   error = tlsFormatClientSessionTicketExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //If the connection's secure_renegotiation flag is set to TRUE, the client
   //must include a RenegotiationInfo extension in its ClientHello message
   error = tlsFormatClientRenegoInfoExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 supported by the client?
   if(context->versionMax >= TLS_VERSION_1_3 &&
      context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      Tls13PskIdentityList *identityList;
      Tls13PskBinderList *binderList;

      //Clients must not use cookies in their initial ClientHello
      if(context->state != TLS_STATE_CLIENT_HELLO)
      {
         //When sending the new ClientHello, the client must copy the contents
         //of the Cookie extension received in the HelloRetryRequest into a
         //Cookie extension in the new ClientHello
         error = tls13FormatCookieExtension(context, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Fix the length of the extension list
         extensionList->length += (uint16_t) n;
         //Point to the next field
         p += n;
      }

      //The KeyShare extension contains the client's cryptographic parameters
      error = tls13FormatClientKeyShareExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
      //If the client opts to send application data in its first flight of
      //messages, it must supply both the PreSharedKey and EarlyData extensions
      error = tls13FormatClientEarlyDataExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

      //In order to use PSKs, clients must send a PskKeyExchangeModes extension
      error = tls13FormatPskKeModesExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

#if (TLS_CLIENT_HELLO_PADDING_SUPPORT == ENABLED)
      //The first pass calculates the length of the PreSharedKey extension
      error = tls13FormatClientPreSharedKeyExtension(context, p, &n,
         &identityList, &binderList);
      //Any error to report?
      if(error)
         return error;

      //Determine the length of the resulting message
      n += *length + sizeof(TlsExtensionList) + extensionList->length;

      //Add a padding extension to ensure the ClientHello is never between
      //256 and 511 bytes in length
      error = tlsFormatClientHelloPaddingExtension(context, n, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

      //The extensions may appear in any order, with the exception of
      //PreSharedKey which must be the last extension in the ClientHello
      error = tls13FormatClientPreSharedKeyExtension(context, p, &n,
         &identityList, &binderList);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Total length of the message
      *length += sizeof(TlsExtensionList) + htons(extensionList->length);

      //Fix PSK binder values in the PreSharedKey extension
      error = tls13ComputePskBinders(context, message, *length, identityList,
         binderList);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
   {
#if (TLS_CLIENT_HELLO_PADDING_SUPPORT == ENABLED)
      //Retrieve the actual length of the message
      n = *length;

      //Any extensions included in the ClientHello message?
      if(extensionList->length > 0)
         n += sizeof(TlsExtensionList) + extensionList->length;

      //Add a padding extension to ensure the ClientHello is never between
      //256 and 511 bytes in length
      error = tlsFormatClientHelloPaddingExtension(context, n, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

      //Any extensions included in the ClientHello message?
      if(extensionList->length > 0)
      {
         //Convert the length of the extension list to network byte order
         extensionList->length = htons(extensionList->length);
         //Total length of the message
         *length += sizeof(TlsExtensionList) + htons(extensionList->length);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ClientKeyExchange message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ClientKeyExchange message
 * @param[out] length Length of the resulting ClientKeyExchange message
 * @return Error code
 **/

error_t tlsFormatClientKeyExchange(TlsContext *context,
   TlsClientKeyExchange *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Point to the beginning of the handshake message
   p = message;
   //Length of the handshake message
   *length = 0;

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //The client indicates which key to use by including a PSK identity
      //in the ClientKeyExchange message
      error = tlsFormatPskIdentity(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }
#endif

   //RSA, Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod != TLS_KEY_EXCH_PSK)
   {
      //Format client's key exchange parameters
      error = tlsFormatClientKeyParams(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Invalid pre-shared key?
      if(context->pskLen == 0)
         return ERROR_INVALID_KEY_LENGTH;

      //Generate premaster secret
      error = tlsGeneratePskPremasterSecret(context);
      //Any error to report?
      if(error)
         return error;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HelloRequest message
 *
 * HelloRequest is a simple notification that the client should begin the
 * negotiation process anew. In response, the client should send a ClientHello
 * message when convenient
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming HelloRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseHelloRequest(TlsContext *context,
   const TlsHelloRequest *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("HelloRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //The HelloRequest message does not contain any data
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state == TLS_STATE_APPLICATION_DATA)
   {
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //Check whether the secure_renegociation flag is set
      if(context->secureRenegoEnabled && context->secureRenegoFlag)
      {
         //Release existing session ticket, if any
         if(context->ticket != NULL)
         {
            osMemset(context->ticket, 0, context->ticketLen);
            tlsFreeMem(context->ticket);
            context->ticket = NULL;
            context->ticketLen = 0;
         }

#if (DTLS_SUPPORT == ENABLED)
         //Release DTLS cookie
         if(context->cookie != NULL)
         {
            tlsFreeMem(context->cookie);
            context->cookie = NULL;
            context->cookieLen = 0;
         }
#endif
         //HelloRequest is a simple notification that the client should begin
         //the negotiation process anew
         context->state = TLS_STATE_CLIENT_HELLO;

         //Continue processing
         error = NO_ERROR;
      }
      else
#endif
      {
         //If the connection's secure_renegotiation flag is set to FALSE, it
         //is recommended that clients refuse this renegotiation request (refer
         //to RFC 5746, section 4.2)
         error = tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL,
            TLS_ALERT_NO_RENEGOTIATION);
      }
   }
   else
   {
      //The HelloRequest message can be sent at any time but it should be
      //ignored by the client if it arrives in the middle of a handshake
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ServerHello message
 *
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerHello message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerHello(TlsContext *context,
   const TlsServerHello *message, size_t length)
{
   error_t error;
   uint16_t cipherSuite;
   uint8_t compressMethod;
   const uint8_t *p;
   TlsHelloExtensions extensions;

   //Debug message
   TRACE_INFO("ServerHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check current state
   if(context->state != TLS_STATE_SERVER_HELLO &&
      context->state != TLS_STATE_SERVER_HELLO_2 &&
      context->state != TLS_STATE_SERVER_HELLO_3)
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Check the length of the ServerHello message
   if(length < sizeof(TlsServerHello))
      return ERROR_DECODING_FAILED;

   //Point to the session ID
   p = message->sessionId;
   //Remaining bytes to process
   length -= sizeof(TlsServerHello);

   //Check the length of the session ID
   if(message->sessionIdLen > length)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLen > 32)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += message->sessionIdLen;
   //Remaining bytes to process
   length -= message->sessionIdLen;

   //Malformed ServerHello message?
   if(length < sizeof(uint16_t))
      return ERROR_DECODING_FAILED;

   //Get the negotiated cipher suite
   cipherSuite = LOAD16BE(p);
   //Point to the next field
   p += sizeof(uint16_t);
   //Remaining bytes to process
   length -= sizeof(uint16_t);

   //Malformed ServerHello message?
   if(length < sizeof(uint8_t))
      return ERROR_DECODING_FAILED;

   //Get the negotiated compression method
   compressMethod = *p;
   //Point to the next field
   p += sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Server version
   TRACE_INFO("  serverVersion = 0x%04" PRIX16 " (%s)\r\n",
      ntohs(message->serverVersion),
      tlsGetVersionName(ntohs(message->serverVersion)));

   //Server random value
   TRACE_DEBUG("  random\r\n");
   TRACE_DEBUG_ARRAY("    ", message->random, 32);

   //Session identifier
   TRACE_DEBUG("  sessionId\r\n");
   TRACE_DEBUG_ARRAY("    ", message->sessionId, message->sessionIdLen);

   //Cipher suite identifier
   TRACE_INFO("  cipherSuite = 0x%04" PRIX16 " (%s)\r\n",
      cipherSuite, tlsGetCipherSuiteName(cipherSuite));

   //Compression method
   TRACE_DEBUG("  compressMethod = 0x%02" PRIX8 "\r\n", compressMethod);

   //The CRIME exploit takes advantage of TLS compression, so conservative
   //implementations do not accept compression at the TLS level
   if(compressMethod != TLS_COMPRESSION_METHOD_NULL)
      return ERROR_ILLEGAL_PARAMETER;

   //Parse the list of extensions offered by the server
   error = tlsParseHelloExtensions(TLS_TYPE_SERVER_HELLO, p, length,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //TLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      //Check whether the ServerHello message is received in response to
      //the initial ClientHello
      if(context->state != TLS_STATE_SERVER_HELLO_2)
      {
         //Release transcript hash context
         tlsFreeTranscriptHash(context);

         //Format initial ClientHello message
         error = tlsFormatInitialClientHello(context);
         //Any error to report?
         if(error)
            return error;
      }
   }

   //Select TLS version
   error = tlsSelectClientVersion(context, message, &extensions);
   //TLS version not supported?
   if(error)
      return error;

   //Check the list of extensions offered by the server
   error = tlsCheckHelloExtensions(TLS_TYPE_SERVER_HELLO, context->version,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Save server random value
   osMemcpy(context->serverRandom, message->random, 32);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Reset the named group to its default value
      context->namedGroup = TLS_GROUP_NONE;

      //Check whether the server has decided to resume a previous session
      error = tlsResumeSession(context, message->sessionId,
         message->sessionIdLen, cipherSuite);
      //Any error to report?
      if(error)
         return error;

      //Set cipher suite
      error = tlsSelectCipherSuite(context, cipherSuite);
      //Specified cipher suite not supported?
      if(error)
         return error;

      //Initialize handshake message hashing
      error = tlsInitTranscriptHash(context);
      //Any error to report?
      if(error)
         return error;

      //Save session identifier
      osMemcpy(context->sessionId, message->sessionId, message->sessionIdLen);
      context->sessionIdLen = message->sessionIdLen;

#if (TLS_TICKET_SUPPORT == ENABLED)
      //Parse SessionTicket extension
      error = tlsParseServerSessionTicketExtension(context,
         extensions.sessionTicket);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //Parse RenegotiationInfo extension
      error = tlsParseServerRenegoInfoExtension(context, &extensions);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_SNI_SUPPORT == ENABLED)
      //When the server includes a ServerName extension, the data field of
      //this extension may be empty
      error = tlsParseServerSniExtension(context, extensions.serverNameList);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
      //Servers that receive an ClientHello containing a MaxFragmentLength
      //extension may accept the requested maximum fragment length by including
      //an extension of type MaxFragmentLength in the ServerHello
      error = tlsParseServerMaxFragLenExtension(context, extensions.maxFragLen);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
      //The value of RecordSizeLimit is the maximum size of record in octets
      //that the peer is willing to receive
      error = tlsParseServerRecordSizeLimitExtension(context,
         extensions.recordSizeLimit);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //A server that selects an ECC cipher suite in response to a ClientHello
      //message including an EcPointFormats extension appends this extension
      //to its ServerHello message
      error = tlsParseServerEcPointFormatsExtension(context,
         extensions.ecPointFormatList);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
      //Parse ALPN extension
      error = tlsParseServerAlpnExtension(context, extensions.protocolNameList);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //Parse ClientCertType extension
      error = tlsParseClientCertTypeExtension(context, extensions.clientCertType);
      //Any error to report?
      if(error)
         return error;

      //Parse ServerCertType extension
      error = tlsParseServerCertTypeExtension(context, extensions.serverCertType);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //Parse ExtendedMasterSecret extension
      error = tlsParseServerEmsExtension(context, extensions.extendedMasterSecret);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
      //Use abbreviated handshake?
      if(context->resume)
      {
         //Derive session keys from the master secret
         error = tlsGenerateSessionKeys(context);
         //Unable to generate key material?
         if(error)
            return error;

#if (TLS_TICKET_SUPPORT == ENABLED)
         //The server uses the SessionTicket extension to indicate to the client
         //that it will send a new session ticket using the NewSessionTicket
         //handshake message
         if(context->sessionTicketExtReceived)
         {
            //Wait for a NewSessionTicket message from the server
            context->state = TLS_STATE_NEW_SESSION_TICKET;
         }
         else
#endif
         {
            //At this point, both client and server must send ChangeCipherSpec
            //messages and proceed directly to Finished messages
            context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
         }
      }
      else
#endif
      {
         //Perform a full handshake
         if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
            context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
            context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
            context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
            context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
         {
            //The Certificate message is omitted from the server's response
            context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
         }
         else
         {
            //The server is required to send a Certificate message
            context->state = TLS_STATE_SERVER_CERTIFICATE;
         }
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //A client which receives a legacy_session_id_echo field that does not
      //match what it sent in the ClientHello must abort the handshake with an
      //illegal_parameter alert (RFC 8446, section 4.1.3)
      if(message->sessionIdLen != context->sessionIdLen ||
         osMemcmp(message->sessionId, context->sessionId, message->sessionIdLen))
      {
         //The legacy_session_id_echo field is not valid
         return ERROR_ILLEGAL_PARAMETER;
      }

      //Check whether the ServerHello message is received in response to the
      //initial or the updated ClientHello
      if(context->state != TLS_STATE_SERVER_HELLO_2)
      {
         //Set cipher suite
         error = tlsSelectCipherSuite(context, cipherSuite);
         //Specified cipher suite not supported?
         if(error)
            return error;

         //Initialize handshake message hashing
         error = tlsInitTranscriptHash(context);
         //Any error to report?
         if(error)
            return error;
      }
      else
      {
         //Clients must check that the cipher suite supplied in the ServerHello
         //is the same as that in the HelloRetryRequest and otherwise abort the
         //handshake with an illegal_parameter alert
         if(cipherSuite != context->cipherSuite.identifier)
            return ERROR_ILLEGAL_PARAMETER;
      }

      //If using (EC)DHE key establishment, servers offer exactly one
      //KeyShareEntry in the ServerHello
      error = tls13ParseServerKeyShareExtension(context,
         extensions.serverShare);
      //Any error to report?
      if(error)
         return error;

      //The PreSharedKey extension contains the selected PSK identity
      error = tls13ParseServerPreSharedKeyExtension(context,
         extensions.selectedIdentity);
      //Any error to report?
      if(error)
         return error;

      //In TLS 1.3, the cipher suite concept has been changed. The key exchange
      //mechanism is negotiated separately from the cipher suite
      if(context->keyExchMethod == TLS_KEY_EXCH_NONE)
         return ERROR_HANDSHAKE_FAILED;

#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
      //The middlebox compatibility mode improves the chance of successfully
      //connecting through middleboxes
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM &&
         context->state == TLS_STATE_SERVER_HELLO)
      {
         //In middlebox compatibility mode, the client sends a dummy
         //ChangeCipherSpec record immediately before its second flight
         context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC_2;
      }
      else
#endif
      {
         //All handshake messages after the ServerHello are now encrypted
         context->state = TLS_STATE_HANDSHAKE_TRAFFIC_KEYS;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Just for sanity
      return ERROR_INVALID_VERSION;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerKeyExchange message
 *
 * The ServerKeyExchange message is sent by the server only when the
 * server Certificate message does not contain enough data to allow
 * the client to exchange a premaster secret
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerKeyExchange message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerKeyExchange(TlsContext *context,
   const TlsServerKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   const uint8_t *p;
   const uint8_t *params;

   //Initialize variables
   params = NULL;
   paramsLen = 0;

   //Debug message
   TRACE_INFO("ServerKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE)
      return ERROR_UNEXPECTED_MESSAGE;

   //Point to the beginning of the handshake message
   p = message;

#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //To help the client in selecting which identity to use, the server
      //can provide a PSK identity hint in the ServerKeyExchange message
      error = tlsParsePskIdentityHint(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }
#endif

   //Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Point to the server's key exchange parameters
      params = p;

      //Parse server's key exchange parameters
      error = tlsParseServerKeyParams(context, p, length, &paramsLen);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += paramsLen;
      //Remaining bytes to process
      length -= paramsLen;
   }

   //For non-anonymous Diffie-Hellman and ECDH key exchanges, the signature
   //over the server's key exchange parameters shall be verified
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
      //TLS 1.0 or TLS 1.1 currently selected?
      if(context->version <= TLS_VERSION_1_1)
      {
         //Signature verification
         error = tlsVerifyServerKeySignature(context,
            (TlsDigitalSignature *) p, length, params, paramsLen, &n);
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.2 currently selected?
      if(context->version == TLS_VERSION_1_2)
      {
         //Signature verification
         error = tls12VerifyServerKeySignature(context,
            (Tls12DigitalSignature *) p, length, params, paramsLen, &n);
      }
      else
#endif
      {
         //Report an error
         error = ERROR_INVALID_VERSION;
      }

      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //If the amount of data in the message does not precisely match the format
   //of the ServerKeyExchange message, then send a fatal alert
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Anomynous server?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //An anonymous server cannot request client authentication
      context->state = TLS_STATE_SERVER_HELLO_DONE;
   }
   else
   {
      //A non-anonymous server can optionally request a certificate from
      //the client, if appropriate for the selected cipher suite
      context->state = TLS_STATE_CERTIFICATE_REQUEST;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertificateRequest message
 *
 * A server can optionally request a certificate from the client, if
 * appropriate for the selected cipher suite. This message will
 * immediately follow the ServerKeyExchange message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming CertificateRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificateRequest(TlsContext *context,
   const TlsCertificateRequest *message, size_t length)
{
   error_t error;
   uint_t i;
   uint_t j;
   size_t n;
   uint_t certTypesLen;
   bool_t acceptable;
   const uint8_t *p;
   const uint8_t *certTypes;
   const TlsCertAuthorities *certAuthorities;
   const TlsSignHashAlgos *supportedSignAlgos;
   const TlsSignHashAlgos *supportedCertSignAlgos;

   //Debug message
   TRACE_INFO("CertificateRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check key exchange method
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //It is a fatal handshake failure alert for an anonymous server to
      //request client authentication
      return ERROR_HANDSHAKE_FAILED;
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      //If no PSK identity hint is provided by the server, then the
      //ServerKeyExchange message is omitted
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_CERTIFICATE_REQUEST)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
   {
      //Servers which are authenticating with a PSK must not send the
      //CertificateRequest message in the main handshake
      return ERROR_HANDSHAKE_FAILED;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CERTIFICATE_REQUEST)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //The server requests a certificate from the client, so that connection
   //can be mutually authenticated
   context->clientCertRequested = TRUE;

   //Point to the beginning of the handshake message
   p = (uint8_t *) message;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check the length of the ServerKeyExchange message
      if(length < sizeof(TlsCertificateRequest))
         return ERROR_DECODING_FAILED;

      //Remaining bytes to process
      length -= sizeof(TlsCertificateRequest);

      //Retrieve the length of the list
      n = message->certificateTypesLen;
      //Malformed CertificateRequest message?
      if(n > length)
         return ERROR_DECODING_FAILED;

      //Point to the list of supported certificate types
      certTypes = message->certificateTypes;
      certTypesLen = message->certificateTypesLen;

      //Point to the next field
      p += sizeof(TlsCertificateRequest) + n;
      //Remaining bytes to process
      length -= n;

      //TLS 1.2 currently selected?
      if(context->version == TLS_VERSION_1_2)
      {
         //Malformed CertificateRequest message?
         if(length < sizeof(TlsSignHashAlgos))
            return ERROR_DECODING_FAILED;

         //Point to the list of the hash/signature algorithm pairs
         supportedSignAlgos = (TlsSignHashAlgos *) p;
         //Remaining bytes to process
         length -= sizeof(TlsSignHashAlgos);

         //Retrieve the length of the list
         n = ntohs(supportedSignAlgos->length);
         //Malformed CertificateRequest message?
         if(n > length)
            return ERROR_DECODING_FAILED;

         //The supported_signature_algorithms field cannot be empty (refer to
         //RFC 5246, section 7.4.4)
         if(n == 0)
            return ERROR_DECODING_FAILED;
         if((n % 2) != 0)
            return ERROR_DECODING_FAILED;

         //Point to the next field
         p += sizeof(TlsSignHashAlgos) + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //Implementations prior to TLS 1.2 do not include a list of supported
         //hash/signature algorithm pairs
         supportedSignAlgos = NULL;
      }

      //List of signature algorithms that may appear in X.509 certificates
      supportedCertSignAlgos = supportedSignAlgos;

      //Malformed CertificateRequest message?
      if(length < sizeof(TlsCertAuthorities))
         return ERROR_DECODING_FAILED;

      //Point to the list of acceptable certificate authorities
      certAuthorities = (TlsCertAuthorities *) p;
      //Remaining bytes to process
      length -= sizeof(TlsCertAuthorities);

      //Retrieve the length of the list
      n = ntohs(certAuthorities->length);
      //Malformed CertificateRequest message?
      if(n != length)
         return ERROR_DECODING_FAILED;
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      TlsHelloExtensions extensions;
      const Tls13CertRequestContext *certRequestContext;

      //Unused parameters
      certTypes = NULL;
      certTypesLen = 0;
      certAuthorities = NULL;

      //Malformed CertificateRequest message?
      if(length < sizeof(Tls13CertRequestContext))
         return ERROR_DECODING_FAILED;

      //Point to the certificate_request_context field
      certRequestContext = (Tls13CertRequestContext *) p;
      //Remaining bytes to process
      length -= sizeof(Tls13CertRequestContext);

      //Retrieve the length of the field
      n = certRequestContext->length;
      //Malformed CertificateRequest message?
      if(n > length)
         return ERROR_DECODING_FAILED;

      //The certificate_request_context field shall be zero length unless
      //used for the post-handshake authentication exchange
      if(certRequestContext->length != 0)
         return ERROR_ILLEGAL_PARAMETER;

      //Point to the next field
      p += sizeof(Tls13CertRequestContext) + n;
      //Remaining bytes to process
      length -= n;

      //The extensions describe the parameters of the certificate being
      //requested
      error = tlsParseHelloExtensions(TLS_TYPE_CERTIFICATE_REQUEST, p,
         length, &extensions);
      //Any error to report?
      if(error)
         return error;

      //Check the list of extensions offered by the server
      error = tlsCheckHelloExtensions(TLS_TYPE_CERTIFICATE_REQUEST,
         context->version, &extensions);
      //Any error to report?
      if(error)
         return error;

      //The SignatureAlgorithms extension must be specified (refer to RFC 8446,
      //section 4.3.2)
      if(extensions.signAlgoList == NULL)
         return ERROR_MISSING_EXTENSION;

      //Point to the list of the hash/signature algorithm pairs that
      //the server is able to verify
      supportedSignAlgos = extensions.signAlgoList;

      //If no SignatureAlgorithmsCert extension is present, then the
      //SignatureAlgorithms extension also applies to signatures appearing
      //in certificates (RFC 8446, section 4.2.3)
      if(extensions.certSignAlgoList != NULL)
      {
         supportedCertSignAlgos = extensions.certSignAlgoList;
      }
      else
      {
         supportedCertSignAlgos = extensions.signAlgoList;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      return ERROR_INVALID_VERSION;
   }

   //No suitable certificate has been found for the moment
   context->cert = NULL;
   acceptable = FALSE;

   //Select the most appropriate certificate (2-pass process)
   for(i = 0; i < 2 && !acceptable; i++)
   {
      //Loop through the list of available certificates
      for(j = 0; j < context->numCerts && !acceptable; j++)
      {
         //Check whether the current certificate is suitable
         acceptable = tlsIsCertificateAcceptable(context, &context->certs[j],
            certTypes, certTypesLen, supportedSignAlgos, supportedCertSignAlgos,
            NULL, certAuthorities);

         //TLS 1.2 and TLS 1.3 require additional examinations
         if(acceptable && context->version >= TLS_VERSION_1_2)
         {
            //The hash and signature algorithms used in the signature of the
            //CertificateVerify message must be one of those present in the
            //SupportedSignatureAlgorithms field
            error = tlsSelectSignatureScheme(context, &context->certs[j],
               supportedSignAlgos);

            //Check status code
            if(error)
            {
               acceptable = FALSE;
            }
         }

         //If all the requirements were met, the certificate can be used
         if(acceptable)
         {
            context->cert = &context->certs[j];
         }
      }

      //The second pass relaxes the constraints
      supportedCertSignAlgos = NULL;
      certAuthorities = NULL;
   }

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Wait for a ServerHelloDone message
      context->state = TLS_STATE_SERVER_HELLO_DONE;
   }
   else
   {
      //Wait for a Certificate message
      context->state = TLS_STATE_SERVER_CERTIFICATE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerHelloDone message
 *
 * The ServerHelloDone message is sent by the server to indicate the
 * end of the ServerHello and associated messages. After sending this
 * message, the server will wait for a client response
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerHelloDone message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerHelloDone(TlsContext *context,
   const TlsServerHelloDone *message, size_t length)
{
   //Debug message
   TRACE_INFO("ServerHelloDone message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check key exchange method
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //The server may omit the CertificateRequest message and go
      //directly to the ServerHelloDone message
      if(context->state != TLS_STATE_CERTIFICATE_REQUEST &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_PSK)
   {
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      //The server may omit the ServerKeyExchange message and/or
      //the CertificateRequest message
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_CERTIFICATE_REQUEST &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_HELLO_DONE)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //The ServerHelloDone message does not contain any data
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Another handshake message cannot be packed in the same record as the
   //ServerHelloDone
   if(context->rxBufferLen != 0)
      return ERROR_UNEXPECTED_MESSAGE;

   //The client must send a Certificate message if the server requests it
   context->state = TLS_STATE_CLIENT_CERTIFICATE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NewSessionTicket message
 *
 * This NewSessionTicket message is sent by the server during the TLS handshake
 * before the ChangeCipherSpec message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming NewSessionTicket message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseNewSessionTicket(TlsContext *context,
   const TlsNewSessionTicket *message, size_t length)
{
   size_t n;

   //Debug message
   TRACE_INFO("NewSessionTicket message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_NEW_SESSION_TICKET)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check the length of the NewSessionTicket message
   if(length < sizeof(TlsNewSessionTicket))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the ticket
   n = ntohs(message->ticketLen);

   //Malformed NewSessionTicket message?
   if(length != (sizeof(TlsNewSessionTicket) + n))
      return ERROR_DECODING_FAILED;

#if (TLS_TICKET_SUPPORT == ENABLED)
   //This message must not be sent if the server did not include a SessionTicket
   //extension in the ServerHello (refer to RFC 5077, section 3.3)
   if(!context->sessionTicketExtReceived)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check the length of the session ticket
   if(n > 0 && n <= TLS_MAX_TICKET_SIZE)
   {
      //Release existing session ticket, if any
      if(context->ticket != NULL)
      {
         osMemset(context->ticket, 0, context->ticketLen);
         tlsFreeMem(context->ticket);
         context->ticket = NULL;
         context->ticketLen = 0;
      }

      //Allocate a memory block to hold the ticket
      context->ticket = tlsAllocMem(n);
      //Failed to allocate memory?
      if(context->ticket == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Copy session ticket
      osMemcpy(context->ticket, message->ticket, n);
      context->ticketLen = n;

      //The lifetime is relative to when the ticket is received (refer to
      //RFC 5077, appendix A)
      context->ticketTimestamp = osGetSystemTime();

      //The ticket_lifetime_hint field contains a hint from the server about
      //how long the ticket should be stored. A ticket lifetime value of zero
      //indicates that the lifetime of the ticket is unspecified
      context->ticketLifetime = ntohl(message->ticketLifetimeHint);

      //If the client receives a session ticket from the server, then it
      //discards any session ID that was sent in the ServerHello (refer to
      //RFC 5077, section 3.4)
      context->sessionIdLen = 0;
   }
#endif

   //The NewSessionTicket message is sent by the server during the TLS handshake
   //before the ChangeCipherSpec message
   context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;

   //Successful processing
   return NO_ERROR;
}

#endif
