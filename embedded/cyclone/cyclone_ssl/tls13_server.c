/**
 * @file tls13_server.c
 * @brief Handshake message processing (TLS 1.3 server)
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
#include "tls_handshake.h"
#include "tls_server_extensions.h"
#include "tls_server_misc.h"
#include "tls_extensions.h"
#include "tls_transcript_hash.h"
#include "tls_ffdhe.h"
#include "tls_misc.h"
#include "tls13_server.h"
#include "tls13_server_extensions.h"
#include "tls13_server_misc.h"
#include "tls13_ticket.h"
#include "tls13_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Send HelloRetryRequest message
 *
 * The server will send this message in response to a ClientHello message if it
 * is able to find an acceptable set of parameters but the ClientHello does not
 * contain sufficient information to proceed with the handshake
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13SendHelloRetryRequest(TlsContext *context)
{
   error_t error;
   size_t length;
   Tls13HelloRetryRequest *message;

   //Point to the buffer where to format the message
   message = (Tls13HelloRetryRequest *) (context->txBuffer + context->txBufferLen);

   //When the server responds to a ClientHello with a HelloRetryRequest, the
   //value of ClientHello1 is replaced with a special synthetic handshake
   //message of handshake type MessageHash containing Hash(ClientHello1)
   error = tls13DigestClientHello1(context);

   //Check status code
   if(!error)
   {
      //Format HelloRetryRequest message
      error = tls13FormatHelloRetryRequest(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending HelloRetryRequest message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //For reasons of backward compatibility with middleboxes the
      //HelloRetryRequest message uses the same format as the ServerHello
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_SERVER_HELLO);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
      //DTLS implementations do not use the "compatibility mode" and must
      //not send ChangeCipherSpec messages (refer to RFC 9147, section 5)
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //In middlebox compatibility mode, the server sends a dummy
         //ChangeCipherSpec record immediately after its first handshake
         //message. This may either be after a ServerHello or a
         //HelloRetryRequest
         context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2;
      }
      else
#endif
      {
         //Wait for the second updated ClientHello
         context->state = TLS_STATE_CLIENT_HELLO_2;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send EncryptedExtensions message
 *
 * The server sends the EncryptedExtensions message immediately after the
 * ServerHello message. The EncryptedExtensions message contains extensions
 * that can be protected
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13SendEncryptedExtensions(TlsContext *context)
{
   error_t error;
   size_t length;
   Tls13EncryptedExtensions *message;

   //Point to the buffer where to format the message
   message = (Tls13EncryptedExtensions *) (context->txBuffer + context->txBufferLen);

   //Format EncryptedExtensions message
   error = tls13FormatEncryptedExtensions(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending EncryptedExtensions message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_ENCRYPTED_EXTENSIONS);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //PSK key exchange method?
      if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
      {
         //As the server is authenticating via a PSK, it does not send a
         //Certificate or a CertificateVerify message
         context->state = TLS_STATE_SERVER_FINISHED;
      }
      else
      {
         //A server can optionally request a certificate from the client
         context->state = TLS_STATE_CERTIFICATE_REQUEST;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send NewSessionTicket message
 *
 * At any time after the server has received the client Finished message, it
 * may send a NewSessionTicket message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13SendNewSessionTicket(TlsContext *context)
{
   error_t error;
   size_t length;
   Tls13NewSessionTicket *message;

   //Initialize status code
   error = NO_ERROR;

   //Send as many NewSessionTicket messages as requested
   if(context->newSessionTicketCount < TLS13_NEW_SESSION_TICKET_COUNT)
   {
      //Point to the buffer where to format the message
      message = (Tls13NewSessionTicket *) (context->txBuffer + context->txBufferLen);

      //Format NewSessionTicket message
      error = tls13FormatNewSessionTicket(context, message, &length);

      //Check status code
      if(!error)
      {
         //Increment the number of NewSessionTicket messages that have been sent
         context->newSessionTicketCount++;

         //Debug message
         TRACE_INFO("Sending NewSessionTicket message (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", message, length);

         //Send handshake message
         error = tlsSendHandshakeMessage(context, message, length,
            TLS_TYPE_NEW_SESSION_TICKET);
      }
   }
   else
   {
      //The client and server can now exchange application-layer data
      context->state = TLS_STATE_APPLICATION_DATA;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HelloRetryRequest message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the HelloRetryRequest message
 * @param[out] length Length of the resulting HelloRetryRequest message
 * @return Error code
 **/

error_t tls13FormatHelloRetryRequest(TlsContext *context,
   Tls13HelloRetryRequest *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   TlsExtensionList *extensionList;

   //In TLS 1.3, the client indicates its version preferences in the
   //SupportedVersions extension and the legacy_version field must be set
   //to 0x0303, which is the version number for TLS 1.2
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      message->serverVersion = HTONS(DTLS_VERSION_1_2);
   }
   else
   {
      message->serverVersion = HTONS(TLS_VERSION_1_2);
   }

   //For backward compatibility with middleboxes the HelloRetryRequest message
   //uses the same structure as the ServerHello, but with Random field set to
   //a special value
   osMemcpy(message->random, tls13HelloRetryRequestRandom, 32);

   //Point to the session ID
   p = message->sessionId;
   //Length of the handshake message
   *length = sizeof(Tls13HelloRetryRequest);

   //The legacy_session_id_echo echoes the contents of the client's
   //legacy_session_id field
   osMemcpy(message->sessionId, context->sessionId, context->sessionIdLen);
   message->sessionIdLen = (uint8_t) context->sessionIdLen;

   //Debug message
   TRACE_INFO("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLen);
   TRACE_INFO_ARRAY("  ", message->sessionId, message->sessionIdLen);

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

   //The legacy_compression_method field must have the value 0
   *p = TLS_COMPRESSION_METHOD_NULL;

   //Advance data pointer
   p += sizeof(uint8_t);
   //Adjust the length of the message
   *length += sizeof(uint8_t);

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);
   //Adjust the length of the message
   *length += sizeof(TlsExtensionList);

   //The HelloRetryRequest message must contain a SupportedVersions extension
   error = tls13FormatServerSupportedVersionsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;

   //The KeyShare extension contains the mutually supported group the server
   //intends to negotiate
   error = tls13FormatSelectedGroupExtension(context, p, &n);
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
   *length += htons(extensionList->length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format EncryptedExtensions message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the EncryptedExtensions message
 * @param[out] length Length of the resulting EncryptedExtensions message
 * @return Error code
 **/

error_t tls13FormatEncryptedExtensions(TlsContext *context,
   Tls13EncryptedExtensions *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Point to the extension of the list
   p = message->extensions;
   //Length of the handshake message
   *length = sizeof(Tls13EncryptedExtensions);

   //Total length of the extension list
   message->extensionsLen = 0;

#if (TLS_SNI_SUPPORT == ENABLED)
   //The server may include a SNI extension in the ServerHello
   error = tlsFormatServerSniExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   message->extensionsLen += (uint16_t) n;
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
   message->extensionsLen += (uint16_t) n;
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
   message->extensionsLen += (uint16_t) n;
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
   message->extensionsLen += (uint16_t) n;
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
   message->extensionsLen += (uint16_t) n;
   //Point to the next field
   p += n;

   //With the ServerCertType extension in the ServerHello, the TLS server
   //indicates the certificate type carried in the certificate payload
   error = tlsFormatServerCertTypeExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   message->extensionsLen += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //If the server intends to process the early data, then it returns its
   //own EarlyData extension in the EncryptedExtensions message
   error = tls13FormatServerEarlyDataExtension(context,
      TLS_TYPE_ENCRYPTED_EXTENSIONS, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   message->extensionsLen += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

   //Convert the length of the extension list to network byte order
   message->extensionsLen = htons(message->extensionsLen);
   //Total length of the message
   *length += htons(message->extensionsLen);

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

error_t tls13FormatNewSessionTicket(TlsContext *context,
   Tls13NewSessionTicket *message, size_t *length)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *p;
   Tls13Ticket *ticket;
   TlsExtensionList *extensionList;

   //Set the lifetime of the ticket, in seconds
   message->ticketLifetime = HTONL(TLS_TICKET_LIFETIME / 1000);

   //The ticket_age_add field is used to obscure the age of the ticket
   error = context->prngAlgo->read(context->prngContext,
      (uint8_t *) &message->ticketAgeAdd, sizeof(uint32_t));
   //Any error to report?
   if(error)
      return error;

   //Point to ticket nonce
   p = message->ticketNonce;
   //Length of the handshake message
   *length = sizeof(Tls13NewSessionTicket);

   //The ticket nonce is a per-ticket value that is unique across all tickets
   //issued on this connection
   context->ticketNonce++;

   //Copy ticket nonce
   STORE32BE(context->ticketNonce, message->ticketNonce);
   //Set the length of the nonce
   message->ticketNonceLen = sizeof(uint32_t);

   //Advance data pointer
   p += message->ticketNonceLen;
   //Adjust the length of the message
   *length += message->ticketNonceLen;

   //Point to the value of the ticket
   ticket = (Tls13Ticket *) p;

   //The ticket itself is an opaque label. It may be either a database lookup
   //key or a self-encrypted and self-authenticated value
   error = tls13GenerateTicket(context, message, ticket->data, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the ticket
   ticket->length = htons(n);

   //Advance data pointer
   p += sizeof(Tls13Ticket) + n;
   //Adjust the length of the message
   *length += sizeof(Tls13Ticket) + n;

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);
   //Adjust the length of the message
   *length += sizeof(TlsExtensionList);

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //The sole extension currently defined for NewSessionTicket is EarlyData
   //indicating that the ticket may be used to send 0-RTT data
   error = tls13FormatServerEarlyDataExtension(context,
      TLS_TYPE_NEW_SESSION_TICKET, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
#endif

   //Convert the length of the extension list to network byte order
   extensionList->length = htons(extensionList->length);
   //Total length of the message
   *length += htons(extensionList->length);

   //Successful processing
   return NO_ERROR;
#else
   //Session ticket mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
