/**
 * @file tls_server_fsm.c
 * @brief TLS state machine (TLS server)
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
#include "tls.h"
#include "tls_handshake.h"
#include "tls_server.h"
#include "tls_server_fsm.h"
#include "tls_common.h"
#include "tls_cache.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_server.h"
#include "tls13_common.h"
#include "tls13_key_material.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief TLS server handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsPerformServerHandshake(TlsContext *context)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   while(!error)
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Check current state
         if(context->state != TLS_STATE_INIT &&
            context->state != TLS_STATE_CLOSED)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
            //Any error to report?
            if(error)
               break;
         }
      }

      //Check whether the handshake is complete
      if(context->state == TLS_STATE_APPLICATION_DATA)
      {
         //At this is point, the handshake is complete and the server starts
         //to exchange application-layer data
         break;
      }

      //The TLS handshake is implemented as a state machine representing the
      //current location in the protocol
      switch(context->state)
      {
      //Initial state?
      case TLS_STATE_INIT:
         //TLS handshake initialization
         error = tlsInitHandshake(context);
         break;

      //Sending ServerHello message?
      case TLS_STATE_SERVER_HELLO:
      case TLS_STATE_SERVER_HELLO_2:
         //The server will send this message in response to a ClientHello
         //message when it was able to find an acceptable set of algorithms
         error = tlsSendServerHello(context);
         break;

      //Sending Certificate message?
      case TLS_STATE_SERVER_CERTIFICATE:
         //The server must send a Certificate message whenever the agreed-
         //upon key exchange method uses certificates for authentication. This
         //message will always immediately follow the ServerHello message
         error = tlsSendCertificate(context);
         break;

      //Sending Certificate message?
      case TLS_STATE_CERTIFICATE_REQUEST:
         //A non-anonymous server can optionally request a certificate from the
         //client, if appropriate for the selected cipher suite. This message,
         //if sent, will immediately follow the ServerKeyExchange message
         error = tlsSendCertificateRequest(context);
         break;

      //Sending NewSessionTicket message?
      case TLS_STATE_NEW_SESSION_TICKET:
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //TLS 1.3 currently selected?
         if(context->version == TLS_VERSION_1_3)
         {
            //At any time after the server has received the client Finished
            //message, it may send a NewSessionTicket message
            error = tls13SendNewSessionTicket(context);
         }
         else
#endif
         {
            //The NewSessionTicket message is sent by the server during the TLS
            //handshake before the ChangeCipherSpec message
            error = tlsSendNewSessionTicket(context);
         }

         break;

      //Sending ChangeCipherSpec message?
      case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
      case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2:
         //The ChangeCipherSpec message is sent by the server and to notify the
         //client that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsSendChangeCipherSpec(context);
         break;

      //Sending Finished message?
      case TLS_STATE_SERVER_FINISHED:
         //A Finished message is always sent immediately after a ChangeCipherSpec
         //message to verify that the key exchange and authentication processes
         //were successful
         error = tlsSendFinished(context);
         break;

#if (DTLS_SUPPORT == ENABLED)
      //Sending HelloVerifyRequest message?
      case TLS_STATE_HELLO_VERIFY_REQUEST:
         //When the client sends its ClientHello message to the server, the
         //server may respond with a HelloVerifyRequest message
         error = dtlsSendHelloVerifyRequest(context);
         break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Sending ServerKeyExchange message?
      case TLS_STATE_SERVER_KEY_EXCHANGE:
         //The ServerKeyExchange message is sent by the server only when the
         //server Certificate message (if sent) does not contain enough data
         //to allow the client to exchange a premaster secret
         error = tlsSendServerKeyExchange(context);
         break;

      //Sending ServerHelloDone message?
      case TLS_STATE_SERVER_HELLO_DONE:
         //The ServerHelloDone message is sent by the server to indicate the
         //end of the ServerHello and associated messages
         error = tlsSendServerHelloDone(context);
         break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Sending HelloRetryRequest message?
      case TLS_STATE_HELLO_RETRY_REQUEST:
         //The server sends a HelloRetryRequest message if the ClientHello
         //message does not contain sufficient information to proceed with
         //the handshake
         error = tls13SendHelloRetryRequest(context);
         break;

      //Handshake traffic key generation?
      case TLS_STATE_HANDSHAKE_TRAFFIC_KEYS:
         //Compute handshake traffic keys
         error = tls13GenerateHandshakeTrafficKeys(context);
         break;

      //Sending EncryptedExtensions message?
      case TLS_STATE_ENCRYPTED_EXTENSIONS:
         //The server sends the EncryptedExtensions message immediately after
         //the ServerHello message. The EncryptedExtensions message contains
         //extensions that can be protected
         error = tls13SendEncryptedExtensions(context);
         break;

      //Sending CertificateVerify message?
      case TLS_STATE_SERVER_CERTIFICATE_VERIFY:
         //Servers must send this message when authenticating via a
         //certificate. When sent, this message must appear immediately
         //after the Certificate message
         error = tlsSendCertificateVerify(context);
         break;

      //Server application traffic key generation?
      case TLS_STATE_SERVER_APP_TRAFFIC_KEYS:
         //Compute server application traffic keys
         error = tls13GenerateServerAppTrafficKeys(context);
         break;

      //Client application traffic key generation?
      case TLS_STATE_CLIENT_APP_TRAFFIC_KEYS:
         //Compute client application traffic keys
         error = tls13GenerateClientAppTrafficKeys(context);
         break;

      //Sending KeyUpdate message?
      case TLS_STATE_KEY_UPDATE:
         //The KeyUpdate handshake message is used to indicate that the sender
         //is updating its sending cryptographic keys
         error = tls13SendKeyUpdate(context);
         break;
#endif

      //Waiting for a message from the client?
      case TLS_STATE_CLIENT_HELLO:
      case TLS_STATE_CLIENT_HELLO_2:
      case TLS_STATE_CLIENT_CERTIFICATE:
      case TLS_STATE_CLIENT_KEY_EXCHANGE:
      case TLS_STATE_CLIENT_CERTIFICATE_VERIFY:
      case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
      case TLS_STATE_CLIENT_FINISHED:
         //Receive client's message
         error = tlsReceiveHandshakeMessage(context);
         break;

      //Sending Alert message?
      case TLS_STATE_CLOSING:
         //Mark the TLS connection as closed
         context->state = TLS_STATE_CLOSED;
         break;

      //TLS connection closed?
      case TLS_STATE_CLOSED:
         //Debug message
         TRACE_WARNING("TLS handshake failure!\r\n");
         //Report an error
         error = ERROR_HANDSHAKE_FAILED;
         break;

      //Invalid state?
      default:
         //Report an error
         error = ERROR_UNEXPECTED_STATE;
         break;
      }
   }

   //Successful TLS handshake?
   if(!error)
   {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
#if (TLS_TICKET_SUPPORT == ENABLED)
         //Any ticket presented by the client?
         if(context->sessionTicketExtReceived)
         {
            //If a ticket is presented by the client, the server must not
            //attempt to use the Session ID in the ClientHello for stateful
            //session resumption
         }
         else
#endif
         {
            //Save current session in the session cache for further reuse
            tlsSaveToCache(context);
         }
      }
#endif
   }
   else
   {
      //Send an alert message to the client, if applicable
      tlsProcessError(context, error);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse client's handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] msgType Handshake message type
 * @param[in] message Pointer to the handshake message to parse
 * @param[in] length Length of the handshake messaged
 * @return Error code
 **/

error_t tlsParseClientHandshakeMessage(TlsContext *context, uint8_t msgType,
   const void *message, size_t length)
{
   error_t error;

   //Check handshake message type
   switch(msgType)
   {
   //ClientHello message received?
   case TLS_TYPE_CLIENT_HELLO:
      //When a client first connects to a server, it is required to send the
      //ClientHello as its first message
      error = tlsParseClientHello(context, message, length);
      break;

   //Certificate message received?
   case TLS_TYPE_CERTIFICATE:
      //This is the first message the client can send after receiving a
      //ServerHelloDone message. This message is only sent if the server
      //requests a certificate
      error = tlsParseCertificate(context, message, length);
      break;

   //CertificateVerify message received?
   case TLS_TYPE_CERTIFICATE_VERIFY:
      //This message is used to provide explicit verification of a client
      //certificate. This message is only sent following a client certificate
      //that has signing capability. When sent, it must immediately follow
      //the clientKeyExchange message
      error = tlsParseCertificateVerify(context, message, length);
      break;

   //Finished message received?
   case TLS_TYPE_FINISHED:
      //A Finished message is always sent immediately after a ChangeCipherSpec
      //message to verify that the key exchange and authentication processes
      //were successful
      error = tlsParseFinished(context, message, length);
      break;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //ClientKeyExchange message received?
   case TLS_TYPE_CLIENT_KEY_EXCHANGE:
      //This message must immediately follow the client certificate message, if
      //it is sent. Otherwise, it must be the first message sent by the client
      //after it receives the ServerHelloDone message
      error = tlsParseClientKeyExchange(context, message, length);
      break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //KeyUpdate message received?
   case TLS_TYPE_KEY_UPDATE:
      //The KeyUpdate handshake message is used to indicate that the client is
      //updating its sending cryptographic keys. This message can be sent by
      //the client after it has sent a Finished message
      error = tls13ParseKeyUpdate(context, message, length);
      break;
#endif

   //Invalid handshake message received?
   default:
      //Report an error
      error = ERROR_UNEXPECTED_MESSAGE;
      break;
   }

   //Return status code
   return error;
}

#endif
