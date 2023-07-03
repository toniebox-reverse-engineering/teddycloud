/**
 * @file tls_server.c
 * @brief Handshake message processing (TLS server)
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
#include "tls_server.h"
#include "tls_server_extensions.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_extensions.h"
#include "tls_signature.h"
#include "tls_key_material.h"
#include "tls_transcript_hash.h"
#include "tls_cache.h"
#include "tls_ffdhe.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_server.h"
#include "tls13_server_extensions.h"
#include "tls13_server_misc.h"
#include "dtls_record.h"
#include "dtls_misc.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "date_time.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Send ServerHello message
 *
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHello *message;

   //Point to the buffer where to format the message
   message = (TlsServerHello *) (context->txBuffer + context->txBufferLen);

   //Generate the server random value using a cryptographically-safe
   //pseudorandom number generator
   error = tlsGenerateRandomValue(context, context->serverRandom);

   //Check status code
   if(!error)
   {
      //Format ServerHello message
      error = tlsFormatServerHello(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHello message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_SERVER_HELLO);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
         //Use abbreviated handshake?
         if(context->resume)
         {
            //Derive session keys from the master secret
            error = tlsGenerateSessionKeys(context);

            //Key material successfully generated?
            if(!error)
            {
#if (TLS_TICKET_SUPPORT == ENABLED)
               //The server uses a zero-length SessionTicket extension to
               //indicate to the client that it will send a new session ticket
               //using the NewSessionTicket handshake message
               if(context->sessionTicketExtSent)
               {
                  //Send a NewSessionTicket message to the client
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
         }
         else
#endif
         {
            //Perform a full handshake
            context->state = TLS_STATE_SERVER_CERTIFICATE;
         }
      }
      else
      {
#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
         //First handshake message sent by the server?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM &&
            context->state == TLS_STATE_SERVER_HELLO)
         {
            //In middlebox compatibility mode, the server must send a dummy
            //ChangeCipherSpec record immediately after its first handshake
            //message
            context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
         }
         else
#endif
         {
            //All handshake messages after the ServerHello are now encrypted
            context->state = TLS_STATE_HANDSHAKE_TRAFFIC_KEYS;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerKeyExchange message
 *
 * The ServerKeyExchange message is sent by the server only when the
 * server Certificate message does not contain enough data to allow
 * the client to exchange a premaster secret
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerKeyExchange(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerKeyExchange *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (TlsServerKeyExchange *) (context->txBuffer + context->txBufferLen);
   //Initialize length
   length = 0;

   //The ServerKeyExchange message is sent by the server only when the server
   //Certificate message (if sent) does not contain enough data to allow the
   //client to exchange a premaster secret
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Format ServerKeyExchange message
      error = tlsFormatServerKeyExchange(context, message, &length);
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
#if (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted...
      if(context->pskIdentityHint != NULL)
      {
         //Format ServerKeyExchange message
         error = tlsFormatServerKeyExchange(context, message, &length);
      }
#endif
   }

   //Check status code
   if(!error)
   {
      //Any message to send?
      if(length > 0)
      {
         //Debug message
         TRACE_INFO("Sending ServerKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", message, length);

         //Send handshake message
         error = tlsSendHandshakeMessage(context, message, length,
            TLS_TYPE_SERVER_KEY_EXCHANGE);
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //A server can optionally request a certificate from the client
      context->state = TLS_STATE_CERTIFICATE_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Send CertificateRequest message
 *
 * A server can optionally request a certificate from the client, if
 * appropriate for the selected cipher suite. This message will
 * immediately follow the ServerKeyExchange message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificateRequest(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificateRequest *message;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //A server can optionally request a certificate from the client
   if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
   {
      //Non-anonymous key exchange?
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
         context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_ECDHE)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateRequest *) (context->txBuffer + context->txBufferLen);

         //Format CertificateRequest message
         error = tlsFormatCertificateRequest(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateRequest message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE_REQUEST);
         }
      }
   }
#endif

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Send a ServerHelloDone message to the client
         context->state = TLS_STATE_SERVER_HELLO_DONE;
      }
      else
      {
         //Send a Certificate message to the client
         context->state = TLS_STATE_SERVER_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerHelloDone message
 *
 * The ServerHelloDone message is sent by the server to indicate the
 * end of the ServerHello and associated messages. After sending this
 * message, the server will wait for a client response
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHelloDone(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHelloDone *message;

   //Point to the buffer where to format the message
   message = (TlsServerHelloDone *) (context->txBuffer + context->txBufferLen);

   //Format ServerHelloDone message
   error = tlsFormatServerHelloDone(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHelloDone message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_SERVER_HELLO_DONE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
      {
         context->state = TLS_STATE_CLIENT_CERTIFICATE;
      }
      else
      {
         context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send NewSessionTicket message
 *
 * This NewSessionTicket message is sent by the server during the TLS handshake
 * before the ChangeCipherSpec message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendNewSessionTicket(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsNewSessionTicket *message;

   //Point to the buffer where to format the message
   message = (TlsNewSessionTicket *) (context->txBuffer + context->txBufferLen);

   //Format NewSessionTicket message
   error = tlsFormatNewSessionTicket(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending NewSessionTicket message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_NEW_SESSION_TICKET);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The NewSessionTicket message is sent by the server during the TLS
      //handshake before the ChangeCipherSpec message
      context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ServerHello message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHello message
 * @param[out] length Length of the resulting ServerHello message
 * @return Error code
 **/

error_t tlsFormatServerHello(TlsContext *context,
   TlsServerHello *message, size_t *length)
{
   error_t error;
   uint16_t version;
   size_t n;
   uint8_t *p;
   TlsExtensionList *extensionList;

   //In TLS 1.3, the client indicates its version preferences in the
   //SupportedVersions extension and the legacy_version field must be
   //set to 0x0303, which is the version number for TLS 1.2
   version = MIN(context->version, TLS_VERSION_1_2);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Get the corresponding DTLS version
      version = dtlsTranslateVersion(version);
   }
#endif

   //In previous versions of TLS, the version field contains the lower of
   //the version suggested by the client in the ClientHello and the highest
   //supported by the server
   message->serverVersion = htons(version);

   //Server random value
   osMemcpy(message->random, context->serverRandom, 32);

   //Point to the session ID
   p = message->sessionId;
   //Length of the handshake message
   *length = sizeof(TlsServerHello);

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
      //The session ID uniquely identifies the current session
      osMemcpy(message->sessionId, context->sessionId, context->sessionIdLen);
      message->sessionIdLen = (uint8_t) context->sessionIdLen;
#else
      //The server may return an empty session ID to indicate that the session
      //will not be cached and therefore cannot be resumed
      message->sessionIdLen = 0;
#endif
   }
   else
   {
      //The legacy_session_id_echo echoes the contents of the client's
      //legacy_session_id field
      osMemcpy(message->sessionId, context->sessionId, context->sessionIdLen);
      message->sessionIdLen = (uint8_t) context->sessionIdLen;
   }

   //Debug message
   TRACE_DEBUG("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLen);
   TRACE_DEBUG_ARRAY("  ", message->sessionId, message->sessionIdLen);

   //Advance data pointer
   p += message->sessionIdLen;
   //Adjust the length of the message
   *length += message->sessionIdLen;

   //The cipher_suite field contains the cipher suite selected by the server
   STORE16BE(context->cipherSuite.identifier, p);

   //Advance data pointer
   p += sizeof(uint16_t);
   //Adjust the length of the message
   *length += sizeof(uint16_t);

   //The CRIME exploit takes advantage of TLS compression, so conservative
   //implementations do not enable compression at the TLS level
   *p = TLS_COMPRESSION_METHOD_NULL;

   //Advance data pointer
   p += sizeof(uint8_t);
   //Adjust the length of the message
   *length += sizeof(uint8_t);

   //Only extensions offered by the client can appear in the server's list
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 selected by the server?
   if(context->version <= TLS_VERSION_1_2)
   {
#if (TLS_SNI_SUPPORT == ENABLED)
      //The server may include a SNI extension in the ServerHello
      error = tlsFormatServerSniExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
      //Servers that receive an ClientHello containing a MaxFragmentLength
      //extension may accept the requested maximum fragment length by including
      //an extension of type MaxFragmentLength in the ServerHello
      error = tlsFormatServerMaxFragLenExtension(context, p, &n);
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
      error = tlsFormatServerRecordSizeLimitExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //A server that selects an ECC cipher suite in response to a ClientHello
      //message including an EcPointFormats extension appends this extension
      //to its ServerHello message
      error = tlsFormatServerEcPointFormatsExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
      //The ALPN extension contains the name of the selected protocol
      error = tlsFormatServerAlpnExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //The ClientCertType extension in the ServerHello indicates the type
      //of certificates the client is requested to provide in a subsequent
      //certificate payload
      error = tlsFormatClientCertTypeExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

      //With the ServerCertType extension in the ServerHello, the TLS server
      //indicates the certificate type carried in the certificate payload
      error = tlsFormatServerCertTypeExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //If a server implementing RFC 7627 receives the ExtendedMasterSecret
      //extension, it must include the extension in its ServerHello message
      error = tlsFormatServerEmsExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_TICKET_SUPPORT == ENABLED)
      //The server uses the SessionTicket extension to indicate to the client
      //that it will send a new session ticket using the NewSessionTicket
      //handshake message
      error = tlsFormatServerSessionTicketExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //During secure renegotiation, the server must include a renegotiation_info
      //extension containing the saved client_verify_data and server_verify_data
      error = tlsFormatServerRenegoInfoExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
#endif
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 selected by the server?
   if(context->version == TLS_VERSION_1_3)
   {
      //A server which negotiates TLS 1.3 must respond by sending a
      //SupportedVersions extension containing the selected version value
      error = tls13FormatServerSupportedVersionsExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

      //If using (EC)DHE key establishment, servers offer exactly one
      //KeyShareEntry in the ServerHello
      error = tls13FormatServerKeyShareExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;

      //In order to accept PSK key establishment, the server sends a
      //PreSharedKey extension indicating the selected identity
      error = tls13FormatServerPreSharedKeyExtension(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Fix the length of the extension list
      extensionList->length += (uint16_t) n;
      //Point to the next field
      p += n;
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      return ERROR_INVALID_VERSION;
   }

   //Any extensions included in the ServerHello message?
   if(extensionList->length > 0)
   {
      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Total length of the message
      *length += sizeof(TlsExtensionList) + htons(extensionList->length);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ServerKeyExchange message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerKeyExchange message
 * @param[out] length Length of the resulting ServerKeyExchange message
 * @return Error code
 **/

error_t tlsFormatServerKeyExchange(TlsContext *context,
   TlsServerKeyExchange *message, size_t *length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   uint8_t *p;
   uint8_t *params;

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
      //To help the client in selecting which identity to use, the server
      //can provide a PSK identity hint in the ServerKeyExchange message
      error = tlsFormatPskIdentityHint(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
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

      //Format server's key exchange parameters
      error = tlsFormatServerKeyParams(context, p, &paramsLen);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += paramsLen;
      //Adjust the length of the message
      *length += paramsLen;
   }
   else
   {
      //Just for sanity
      params = NULL;
      paramsLen = 0;
   }

   //For non-anonymous Diffie-Hellman and ECDH key exchanges, a signature
   //over the server's key exchange parameters shall be generated
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
      //TLS 1.0 or TLS 1.1 currently selected?
      if(context->version <= TLS_VERSION_1_1)
      {
         //Sign server's key exchange parameters
         error = tlsGenerateServerKeySignature(context,
            (TlsDigitalSignature *) p, params, paramsLen, &n);
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.2 currently selected?
      if(context->version == TLS_VERSION_1_2)
      {
         //Sign server's key exchange parameters
         error = tls12GenerateServerKeySignature(context,
            (Tls12DigitalSignature *) p, params, paramsLen, &n);
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

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CertificateRequest message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the CertificateRequest message
 * @param[out] length Length of the resulting CertificateRequest message
 * @return Error code
 **/

error_t tlsFormatCertificateRequest(TlsContext *context,
   TlsCertificateRequest *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Initialize status code
   error = NO_ERROR;

   //Point to the beginning of the message
   p = (uint8_t *) message;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      size_t pemCertLen;
      const char_t *trustedCaList;
      size_t trustedCaListLen;
      uint8_t *derCert;
      size_t derCertLen;
      X509CertificateInfo *certInfo;
      TlsCertAuthorities *certAuthorities;

      //Enumerate the types of certificate types that the client may offer
      n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //Accept certificates that contain an RSA public key
      message->certificateTypes[n++] = TLS_CERT_RSA_SIGN;
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //Accept certificates that contain a DSA public key
      message->certificateTypes[n++] = TLS_CERT_DSS_SIGN;
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //Accept certificates that contain an ECDSA public key
      message->certificateTypes[n++] = TLS_CERT_ECDSA_SIGN;
#endif

      //Fix the length of the list
      message->certificateTypesLen = (uint8_t) n;
      //Length of the handshake message
      *length = sizeof(TlsCertificateRequest) + n;

      //TLS 1.2 currently selected?
      if(context->version == TLS_VERSION_1_2)
      {
         TlsSignHashAlgos *supportedSignAlgos;

         //Point to the list of the hash/signature algorithm pairs that the server
         //is able to verify. Servers can minimize the computation cost by offering
         //a restricted set of digest algorithms
         supportedSignAlgos = PTR_OFFSET(message, *length);

         //Enumerate the hash/signature algorithm pairs in descending
         //order of preference
         n = 0;

#if (TLS_SHA256_SUPPORT == ENABLED)
         //The hash algorithm used for PRF operations can also be used for signing
         if(context->cipherSuite.prfHashAlgo == SHA256_HASH_ALGO)
         {
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature algorithm with SHA-256
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //Check whether the X.509 parser supports RSA-PSS signatures
            if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
            {
               //RSASSA-PSS PSS signature algorithm with SHA-256
               supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256;
               supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
            }
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS RSAE signature algorithm with SHA-256
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-256
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature algorithm with SHA-256
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
         }
#endif

#if (TLS_SHA384_SUPPORT == ENABLED)
         //The hash algorithm used for PRF operations can also be used for signing
         if(context->cipherSuite.prfHashAlgo == SHA384_HASH_ALGO)
         {
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature algorithm with SHA-384
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //Check whether the X.509 parser supports RSA-PSS signatures
            if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
            {
               //RSASSA-PSS PSS signature algorithm with SHA-384
               supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384;
               supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
            }
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS RSAE signature algorithm with SHA-384
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-384
            supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
            supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
         }
#endif

#if (TLS_SHA1_SUPPORT == ENABLED)
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-1
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
         //RSASSA-PKCS1-v1_5 signature algorithm with SHA-1
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
         //DSA signature algorithm with SHA-1
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#endif
         //Fix the length of the list
         supportedSignAlgos->length = htons(n * sizeof(TlsSignHashAlgo));
         //Adjust the length of the message
         *length += sizeof(TlsSignHashAlgos) + n * sizeof(TlsSignHashAlgo);
      }

      //Point to the list of the distinguished names of acceptable certificate
      //authorities
      certAuthorities = PTR_OFFSET(message, *length);
      //Adjust the length of the message
      *length += sizeof(TlsCertAuthorities);

      //Point to the first certificate authority
      p = certAuthorities->value;
      //Length of the list in bytes
      n = 0;

      //Point to the first trusted CA certificate
      trustedCaList = context->trustedCaList;
      //Get the total length, in bytes, of the trusted CA list
      trustedCaListLen = context->trustedCaListLen;

      //Allocate a memory buffer to store X.509 certificate info
      certInfo = tlsAllocMem(sizeof(X509CertificateInfo));

      //Successful memory allocation?
      if(certInfo != NULL)
      {
         //Loop through the list of trusted CA certificates
         while(trustedCaListLen > 0 && error == NO_ERROR)
         {
            //The first pass calculates the length of the DER-encoded certificate
            error = pemImportCertificate(trustedCaList, trustedCaListLen, NULL,
               &derCertLen, &pemCertLen);

            //Check status code
            if(!error)
            {
               //Allocate a memory buffer to hold the DER-encoded certificate
               derCert = tlsAllocMem(derCertLen);

               //Successful memory allocation?
               if(derCert != NULL)
               {
                  //The second pass decodes the PEM certificate
                  error = pemImportCertificate(trustedCaList, trustedCaListLen,
                     derCert, &derCertLen, NULL);

                  //Check status code
                  if(!error)
                  {
                     //Parse X.509 certificate
                     error = x509ParseCertificate(derCert, derCertLen, certInfo);
                  }

                  //Valid CA certificate?
                  if(!error)
                  {
                     //Adjust the length of the message
                     *length += certInfo->tbsCert.subject.rawDataLen + 2;

                     //Sanity check
                     if(*length <= context->txBufferMaxLen)
                     {
                        //Each distinguished name is preceded by a 2-byte length field
                        STORE16BE(certInfo->tbsCert.subject.rawDataLen, p);

                        //The distinguished name shall be DER-encoded
                        osMemcpy(p + 2, certInfo->tbsCert.subject.rawData,
                           certInfo->tbsCert.subject.rawDataLen);

                        //Advance write pointer
                        p += certInfo->tbsCert.subject.rawDataLen + 2;
                        n += certInfo->tbsCert.subject.rawDataLen + 2;
                     }
                     else
                     {
                        //Report an error
                        error = ERROR_MESSAGE_TOO_LONG;
                     }
                  }
                  else
                  {
                     //Discard current CA certificate
                     error = NO_ERROR;
                  }

                  //Free previously allocated memory
                  tlsFreeMem(derCert);
               }
               else
               {
                  //Failed to allocate memory
                  error = ERROR_OUT_OF_MEMORY;
               }

               //Advance read pointer
               trustedCaList += pemCertLen;
               trustedCaListLen -= pemCertLen;
            }
            else
            {
               //End of file detected
               trustedCaListLen = 0;
               error = NO_ERROR;
            }
         }

         //Fix the length of the list
         certAuthorities->length = htons(n);

         //Free previously allocated memory
         tlsFreeMem(certInfo);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      Tls13CertRequestContext *certRequestContext;
      TlsExtensionList *extensionList;

      //Point to the certificate_request_context field
      certRequestContext = (Tls13CertRequestContext *) p;

      //The certificate_request_context field shall be zero length unless
      //used for the post-handshake authentication exchange
      certRequestContext->length = 0;

      //Point to the next field
      p += sizeof(Tls13CertRequestContext);
      //Length of the handshake message
      *length = sizeof(Tls13CertRequestContext);

      //The extensions describe the parameters of the certificate being
      //requested
      extensionList = (TlsExtensionList *) p;
      //Total length of the extension list
      extensionList->length = 0;

      //Point to the first extension of the list
      p += sizeof(TlsExtensionList);
      //Adjust the length of the message
      *length += sizeof(TlsExtensionList);

      //The SignatureAlgorithms extension must be specified
      error = tlsFormatSignatureAlgorithmsExtension(context,
         TLS_CIPHER_SUITE_TYPE_ECC, p, &n);

#if (TLS_SIGN_ALGOS_CERT_SUPPORT == ENABLED)
      //Check status code
      if(!error)
      {
         //Fix the length of the extension list
         extensionList->length += (uint16_t) n;
         //Point to the next field
         p += n;

         //The SignatureAlgorithmsCert extension may optionally be included
         error = tlsFormatSignatureAlgorithmsCertExtension(context, p, &n);
      }
#endif

      //Check status code
      if(!error)
      {
         //Fix the length of the extension list
         extensionList->length += (uint16_t) n;
         //Point to the next field
         p += n;
      }

      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Total length of the message
      *length += htons(extensionList->length);
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
 * @brief Format ServerHelloDone message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHelloDone message
 * @param[out] length Length of the resulting ServerHelloDone message
 * @return Error code
 **/

error_t tlsFormatServerHelloDone(TlsContext *context,
   TlsServerHelloDone *message, size_t *length)
{
   //The ServerHelloDone message does not contain any data
   *length = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format NewSessionTicket message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the NewSessionTicket message
 * @param[out] length Length of the resulting NewSessionTicket message
 * @return Error code
 **/

error_t tlsFormatNewSessionTicket(TlsContext *context,
   TlsNewSessionTicket *message, size_t *length)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2 && \
   TLS_TICKET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   TlsPlaintextSessionState *state;

   //The ticket_lifetime_hint field contains a hint from the server about how
   //long the ticket should be stored
   message->ticketLifetimeHint = HTONL(TLS_TICKET_LIFETIME / 1000);

   //The ticket itself is opaque to the client
   state = (TlsPlaintextSessionState *) message->ticket;

   //Save session state
   state->version = context->version;
   state->cipherSuite = context->cipherSuite.identifier;
   osMemcpy(state->secret, context->masterSecret, TLS_MASTER_SECRET_SIZE);
   state->ticketTimestamp = osGetSystemTime();
   state->ticketLifetime = TLS_TICKET_LIFETIME;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   state->extendedMasterSecret = context->emsExtReceived;
#endif

   //Make sure a valid callback has been registered
   if(context->ticketEncryptCallback != NULL)
   {
      //Encrypt the state information
      error = context->ticketEncryptCallback(context, (uint8_t *) state,
         sizeof(TlsPlaintextSessionState), message->ticket, &n,
         context->ticketParam);
   }
   else
   {
      //Report en error
      error = ERROR_FAILURE;
   }

   //Check status code
   if(!error)
   {
      //Fix the length of the ticket
      message->ticketLen = htons(n);

      //Total length of the message
      *length = sizeof(TlsNewSessionTicket) + n;
   }

   //Return status code
   return error;
#else
   //Session ticket mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse ClientHello message
 *
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message. The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientHello message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientHello(TlsContext *context,
   const TlsClientHello *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const TlsCipherSuites *cipherSuites;
   const TlsCompressMethods *compressMethods;
   TlsHelloExtensions extensions;
#if (DTLS_SUPPORT == ENABLED)
   const DtlsCookie *cookie;
#endif

   //Debug message
   TRACE_INFO("ClientHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check current state
   if(context->state == TLS_STATE_CLIENT_HELLO)
   {
      //When a client first connects to a server, it is required to send
      //the ClientHello as its first message
   }
   else if(context->state == TLS_STATE_CLIENT_HELLO_2)
   {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //The client will also send a updated ClientHello when the server has
      //responded to its initial ClientHello with a HelloRetryRequest
      context->updatedClientHelloReceived = TRUE;
#endif
   }
   else if(context->state == TLS_STATE_APPLICATION_DATA)
   {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
         //Check whether secure renegotiation is enabled
         if(context->secureRenegoEnabled)
         {
            //Make sure the secure_renegociation flag is set
            if(!context->secureRenegoFlag)
            {
               //If the connection's secure_renegotiation flag is set to
               //FALSE, it is recommended that servers do not permit legacy
               //renegotiation (refer to RFC 5746, section 4.4)
               return ERROR_HANDSHAKE_FAILED;
            }
         }
         else
#endif
         {
            //Secure renegotiation is disabled
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      else
#endif
      {
         //Because TLS 1.3 forbids renegotiation, if a server has negotiated
         //TLS 1.3 and receives a ClientHello at any other time, it must
         //terminate the connection with an unexpected_message alert
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Check the length of the ClientHello message
   if(length < sizeof(TlsClientHello))
      return ERROR_DECODING_FAILED;

   //Get the version the client wishes to use during this session
   context->clientVersion = ntohs(message->clientVersion);

   //Point to the session ID
   p = message->sessionId;
   //Remaining bytes to process
   n = length - sizeof(TlsClientHello);

   //Check the length of the session ID
   if(message->sessionIdLen > n)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLen > 32)
      return ERROR_DECODING_FAILED;

   //Debug message
   TRACE_DEBUG("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLen);
   TRACE_DEBUG_ARRAY("  ", message->sessionId, message->sessionIdLen);

   //Point to the next field
   p += message->sessionIdLen;
   //Remaining bytes to process
   n -= message->sessionIdLen;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Point to the Cookie field
      cookie = (DtlsCookie *) p;

      //Malformed ClientHello message?
      if(n < sizeof(DtlsCookie))
         return ERROR_DECODING_FAILED;
      if(n < (sizeof(DtlsCookie) + cookie->length))
         return ERROR_DECODING_FAILED;

      //Check the length of the cookie
      if(cookie->length > DTLS_MAX_COOKIE_SIZE)
         return ERROR_ILLEGAL_PARAMETER;

      //Point to the next field
      p += sizeof(DtlsCookie) + cookie->length;
      //Remaining bytes to process
      n -= sizeof(DtlsCookie) + cookie->length;
   }
   else
   {
      //Just for sanity
      cookie = NULL;
   }
#endif

   //List of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;

   //Malformed ClientHello message?
   if(n < sizeof(TlsCipherSuites))
      return ERROR_DECODING_FAILED;
   if(n < (sizeof(TlsCipherSuites) + ntohs(cipherSuites->length)))
      return ERROR_DECODING_FAILED;

   //Check the length of the list
   if(ntohs(cipherSuites->length) == 0)
      return ERROR_DECODING_FAILED;
   if((ntohs(cipherSuites->length) % 2) != 0)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(TlsCipherSuites) + ntohs(cipherSuites->length);
   //Remaining bytes to process
   n -= sizeof(TlsCipherSuites) + ntohs(cipherSuites->length);

   //List of compression algorithms supported by the client
   compressMethods = (TlsCompressMethods *) p;

   //Malformed ClientHello message?
   if(n < sizeof(TlsCompressMethods))
      return ERROR_DECODING_FAILED;
   if(n < (sizeof(TlsCompressMethods) + compressMethods->length))
      return ERROR_DECODING_FAILED;

   //Check the length of the list
   if(compressMethods->length == 0)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(TlsCompressMethods) + compressMethods->length;
   //Remaining bytes to process
   n -= sizeof(TlsCompressMethods) + compressMethods->length;

   //Parse the list of extensions offered by the client
   error = tlsParseHelloExtensions(TLS_TYPE_CLIENT_HELLO, p, n, &extensions);
   //Any error to report?
   if(error)
      return error;

   //Check whether the ClientHello includes any SCSV cipher suites
   error = tlsCheckSignalingCipherSuiteValues(context, cipherSuites);
   //Any error to report?
   if(error)
      return error;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Parse RenegotiationInfo extension
   error = tlsParseClientRenegoInfoExtension(context, &extensions);
   //Any error to report?
   if(error)
      return error;
#endif

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsClientParameters clientParams;

      //The server should use client parameters (version, random, session_id,
      //cipher_suites, compression_method) to generate its cookie
      clientParams.version = ntohs(message->clientVersion);
      clientParams.random = message->random;
      clientParams.randomLen = 32;
      clientParams.sessionId = message->sessionId;
      clientParams.sessionIdLen = message->sessionIdLen;
      clientParams.cipherSuites = (const uint8_t *) cipherSuites->value;
      clientParams.cipherSuitesLen = ntohs(cipherSuites->length);
      clientParams.compressMethods = compressMethods->value;
      clientParams.compressMethodsLen = compressMethods->length;

      //Verify that the cookie is valid
      error = dtlsVerifyCookie(context, cookie, &clientParams);
      //Any error to report?
      if(error)
         return error;

      //The server may respond with a HelloVerifyRequest message containing
      //a stateless cookie
      if(context->state == TLS_STATE_HELLO_VERIFY_REQUEST)
      {
         //Exit immediately
         return NO_ERROR;
      }
   }
#endif

   //Perform version negotiation
   error = tlsNegotiateVersion(context, ntohs(message->clientVersion),
      extensions.supportedVersionList);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions offered by the client
   error = tlsCheckHelloExtensions(TLS_TYPE_CLIENT_HELLO, context->version,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //The SignatureAlgorithms extension is not meaningful for TLS versions
   //prior to 1.2 (refer to RFC 5246, section 7.4.1.4.1)
   if(context->version <= TLS_VERSION_1_1)
   {
      //Even if clients do offer it, the rules specified in RFC 6066 require
      //servers to ignore extensions they do not understand
      extensions.signAlgoList = NULL;
      extensions.certSignAlgoList = NULL;
   }

   //Save client random value
   osMemcpy(context->clientRandom, message->random, 32);

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName
   //extension
   error = tlsParseClientSniExtension(context, extensions.serverNameList);
   //Any error to report?
   if(error)
      return error;
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Parse ALPN extension
   error = tlsParseClientAlpnExtension(context, extensions.protocolNameList);
   //Any error to report?
   if(error)
      return error;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
#if (TLS_TICKET_SUPPORT == ENABLED)
      //Parse SessionTicket extension
      error = tlsParseClientSessionTicketExtension(context,
         extensions.sessionTicket);
      //Any error to report?
      if(error)
         return error;

      //The server attempts to resume TLS session via session ticket
      error = tlsResumeStatelessSession(context, message->sessionId,
         message->sessionIdLen, cipherSuites, &extensions);
#else
      //No session ticket presented by the client
      error = ERROR_NO_TICKET;
#endif

      //If a ticket is presented by the client, the server must not attempt
      //to use the session ID in the ClientHello for stateful session
      //resumption (refer to RFC 5077, section 3.4)
      if(error == ERROR_NO_TICKET)
      {
         //The server attempts to resume TLS session via session ID
         error = tlsResumeStatefulSession(context, message->sessionId,
            message->sessionIdLen, cipherSuites, &extensions);
         //Any error to report?
         if(error)
            return error;
      }

      //Full handshake?
      if(!context->resume)
      {
         //Perform cipher suite negotiation
         error = tlsNegotiateCipherSuite(context, NULL, cipherSuites,
            &extensions);
         //If no acceptable choices are presented, terminate the handshake
         if(error)
            return ERROR_HANDSHAKE_FAILED;

         //Parse the list of compression methods supported by the client
         error = tlsParseCompressMethods(context, compressMethods);
         //Any error to report?
         if(error)
            return error;
      }

      //Initialize handshake message hashing
      error = tlsInitTranscriptHash(context);
      //Any error to report?
      if(error)
         return error;

#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //A client that proposes ECC cipher suites in its ClientHello message
      //may send the EcPointFormats extension
      error = tlsParseClientEcPointFormatsExtension(context,
         extensions.ecPointFormatList);
      //Any error to report?
      if(error)
         return error;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //Parse ExtendedMasterSecret extension
      error = tlsParseClientEmsExtension(context,
         extensions.extendedMasterSecret);
      //Any error to report?
      if(error)
         return error;
#endif
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //Save the client's legacy_session_id field
      osMemcpy(context->sessionId, message->sessionId, message->sessionIdLen);
      context->sessionIdLen = message->sessionIdLen;

      //Perform cipher suite and key exchange method negotiation
      error = tls13NegotiateCipherSuite(context, message, length, cipherSuites,
         &extensions);
      //If no acceptable choices are presented, terminate the handshake
      if(error)
         return error;

      //Parse the list of compression methods supported by the client
      error = tlsParseCompressMethods(context, compressMethods);
      //Any error to report?
      if(error)
         return error;

      //When a PSK is used and early data is allowed for that PSK, the client
      //can send application data in its first flight of messages
      if(extensions.earlyDataIndication != NULL)
      {
         //If the client opts to do so, it must supply both the PreSharedKey
         //and EarlyData extensions (refer to RFC 8446, section 4.2.10)
         if(extensions.identityList == NULL || extensions.binderList == NULL)
         {
            context->earlyDataRejected = TRUE;
         }
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Just for sanity
      return ERROR_INVALID_VERSION;
   }

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED && TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //A server that supports the RecordSizeLimit extension must ignore a
   //MaxFragmentLength that appears in a ClientHello if both extensions
   //appear (refer to RFC 8449, section 5)
   if(extensions.maxFragLen != NULL && extensions.recordSizeLimit != NULL)
   {
      extensions.maxFragLen = NULL;
   }
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //In order to negotiate smaller maximum fragment lengths, clients may
   //include a MaxFragmentLength extension
   error = tlsParseClientMaxFragLenExtension(context, extensions.maxFragLen);
   //Any error to report?
   if(error)
      return error;
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //The value of RecordSizeLimit is the maximum size of record in octets
   //that the peer is willing to receive
   error = tlsParseClientRecordSizeLimitExtension(context,
      extensions.recordSizeLimit);
   //Any error to report?
   if(error)
      return error;
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Parse ClientCertType extension
   error = tlsParseClientCertTypeListExtension(context,
      extensions.clientCertTypeList);
   //Any error to report?
   if(error)
      return error;

   //Parse ServerCertType extension
   error = tlsParseServerCertTypeListExtension(context,
      extensions.serverCertTypeList);
   //Any error to report?
   if(error)
      return error;
#endif

   //Another handshake message cannot be packed in the same record as the
   //ClientHello
   if(context->rxBufferLen != 0)
      return ERROR_UNEXPECTED_MESSAGE;

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Send a ServerHello message to the client
      context->state = TLS_STATE_SERVER_HELLO;
   }
   else
   {
      //Send a ServerHello or a HelloRetryRequest message to the client
      if(context->state == TLS_STATE_CLIENT_HELLO)
      {
         context->state = TLS_STATE_SERVER_HELLO;
      }
      else if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         context->state = TLS_STATE_SERVER_HELLO_2;
      }
      else
      {
         context->state = TLS_STATE_HELLO_RETRY_REQUEST;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientKeyExchange message
 *
 * This message is always sent by the client. It must immediately
 * follow the client Certificate message, if it is sent. Otherwise,
 * it must be the first message sent by the client after it receives
 * the ServerHelloDone message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientKeyExchange message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientKeyExchange(TlsContext *context,
   const TlsClientKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Debug message
   TRACE_INFO("ClientKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state == TLS_STATE_CLIENT_CERTIFICATE)
   {
      //A an non-anonymous server can optionally request a certificate from the client
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //If client authentication is required by the server for the handshake
         //to continue, it may respond with a fatal handshake failure alert
         if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
            return ERROR_HANDSHAKE_FAILED;
      }
   }
   else if(context->state != TLS_STATE_CLIENT_KEY_EXCHANGE)
   {
      //Send a fatal alert to the client
      return ERROR_UNEXPECTED_MESSAGE;
   }

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
      //The PSK identity is sent in cleartext
      error = tlsParsePskIdentity(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }
#endif

   //RSA, Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod != TLS_KEY_EXCH_PSK)
   {
      //Parse client's key exchange parameters
      error = tlsParseClientKeyParams(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //If the amount of data in the message does not precisely match the format
   //of the ClientKeyExchange message, then send a fatal alert
   if(length != 0)
      return ERROR_DECODING_FAILED;

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

   //Derive session keys from the premaster secret
   error = tlsGenerateSessionKeys(context);
   //Unable to generate key material?
   if(error)
      return error;

   //The client must send a CertificateVerify message when the Certificate
   //message is non-empty
   if(context->peerCertType != TLS_CERT_NONE)
   {
      context->state = TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
   }
   else
   {
      context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
