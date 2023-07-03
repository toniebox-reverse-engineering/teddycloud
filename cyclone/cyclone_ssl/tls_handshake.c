/**
 * @file tls_handshake.c
 * @brief TLS handshake
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
#include "tls_client_fsm.h"
#include "tls_server_fsm.h"
#include "tls_common.h"
#include "tls_transcript_hash.h"
#include "tls_record.h"
#include "tls13_server_misc.h"
#include "dtls_record.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief TLS handshake initialization
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsInitHandshake(TlsContext *context)
{
   //Allocate send buffer if necessary
   if(context->txBuffer == NULL)
   {
      //Allocate TX buffer
      context->txBuffer = tlsAllocMem(context->txBufferSize);

      //Failed to allocate memory?
      if(context->txBuffer == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Clear TX buffer
      osMemset(context->txBuffer, 0, context->txBufferSize);
   }

   //Allocate receive buffer if necessary
   if(context->rxBuffer == NULL)
   {
      //Allocate RX buffer
      context->rxBuffer = tlsAllocMem(context->rxBufferSize);

      //Failed to allocate memory?
      if(context->rxBuffer == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Clear RX buffer
      osMemset(context->rxBuffer, 0, context->rxBufferSize);
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Server mode?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //A server implementation may choose to reject the early data
      context->earlyDataRejected = TRUE;
   }
#endif

   //The client initiates the TLS handshake by sending a ClientHello message
   //to the server
   context->state = TLS_STATE_CLIENT_HELLO;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform TLS handshake
 *
 * TLS handshake protocol is responsible for the authentication and key
 * exchange necessary to establish a secure session
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsPerformHandshake(TlsContext *context)
{
   error_t error;

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Client mode?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Perform TLS handshake with the remote server
      error = tlsPerformClientHandshake(context);
   }
   else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
   //Server mode?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Perform TLS handshake with the remote client
      error = tlsPerformServerHandshake(context);
   }
   else
#endif
   //Unsupported mode of operation?
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Send handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the handshake message
 * @param[in] length Length of the handshake message
 * @param[in] type Handshake message type
 * @return Error code
 **/

error_t tlsSendHandshakeMessage(TlsContext *context, const void *data,
   size_t length, TlsMessageType type)
{
   error_t error;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsHandshake *message;

      //Point to the handshake message header
      message = (DtlsHandshake *) data;

      //Make room for the handshake message header
      osMemmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);
      //Message sequence number
      message->msgSeq = htons(context->txMsgSeq);
      //Fragment offset
      STORE24BE(0, message->fragOffset);
      //Fragment length
      STORE24BE(length, message->fragLength);

      //Whenever a new message is generated, the message sequence
      //number is incremented by one
      context->txMsgSeq++;

      //Total length of the handshake message
      length += sizeof(DtlsHandshake);
   }
   else
#endif
   //TLS protocol?
   {
      TlsHandshake *message;

      //Point to the handshake message header
      message = (TlsHandshake *) data;

      //Make room for the handshake message header
      osMemmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);

      //Total length of the handshake message
      length += sizeof(TlsHandshake);
   }

   //The HelloRequest message must not be included in the message hashes
   //that are maintained throughout the handshake and used in the Finished
   //messages and the CertificateVerify message
   if(type != TLS_TYPE_HELLO_REQUEST)
   {
      tlsUpdateTranscriptHash(context, data, length);
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Send handshake message
      error = dtlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }
   else
#endif
   //TLS protocol?
   {
      //Send handshake message
      error = tlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }

   //Return status code
   return error;
}


/**
 * @brief Receive peer's message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsReceiveHandshakeMessage(TlsContext *context)
{
   error_t error;
   size_t length;
   uint8_t *data;
   TlsContentType contentType;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //A message can be fragmented across several DTLS records
      error = dtlsReadProtocolData(context, &data, &length, &contentType);
   }
   else
#endif
   //TLS protocol?
   {
      //A message can be fragmented across several TLS records
      error = tlsReadProtocolData(context, &data, &length, &contentType);
   }

   //Check status code
   if(!error)
   {
      //Advance data pointer
      context->rxBufferPos += length;
      //Number of bytes still pending in the receive buffer
      context->rxBufferLen -= length;

      //Handshake message received?
      if(contentType == TLS_TYPE_HANDSHAKE)
      {
         //Parse handshake message
         error = tlsParseHandshakeMessage(context, data, length);
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by an endpoint to notify the
         //peer that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsParseChangeCipherSpec(context, (TlsChangeCipherSpec *) data,
            length);
      }
      //Alert message received?
      else if(contentType == TLS_TYPE_ALERT)
      {
         //Parse Alert message
         error = tlsParseAlert(context, (TlsAlert *) data, length);
      }
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Application data received?
      else if(contentType == TLS_TYPE_APPLICATION_DATA)
      {
#if (TLS_SERVER_SUPPORT == ENABLED)
         //Server mode?
         if(context->entity == TLS_CONNECTION_END_SERVER)
         {
            //Process early data
            error = tls13ProcessEarlyData(context, data, length);
         }
         else
#endif
         {
            //The server cannot transmit application data before the handshake
            //is completed
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
#endif
      //Unexpected message received?
      else
      {
         //Abort the handshake with an unexpected_message alert
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the handshake message to parse
 * @param[in] length Length of the handshake messaged
 * @return Error code
 **/

error_t tlsParseHandshakeMessage(TlsContext *context, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint8_t msgType;
   size_t n;
   const void *p;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Retrieve handshake message type
      msgType = ((DtlsHandshake *) message)->msgType;
      //Point to the handshake message
      p = message + sizeof(DtlsHandshake);
      //Calculate the length of the handshake message
      n = length - sizeof(DtlsHandshake);
   }
   else
#endif
   //TLS protocol?
   {
      //Retrieve handshake message type
      msgType = ((TlsHandshake *) message)->msgType;
      //Point to the handshake message
      p = message + sizeof(TlsHandshake);
      //Calculate the length of the handshake message
      n = length - sizeof(TlsHandshake);
   }

#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
   //Reset the count of consecutive KeyUpdate messages
   if(msgType != TLS_TYPE_KEY_UPDATE)
      context->keyUpdateCount = 0;
#endif

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Client mode?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Parse server's handshake message
      error = tlsParseServerHandshakeMessage(context, msgType, p, n);

      //Update the hash value with the incoming handshake message
      tlsUpdateTranscriptHash(context, message, length);
   }
   else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
   //Server mode?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Update the hash value with the incoming handshake message
      if(msgType == TLS_TYPE_CLIENT_KEY_EXCHANGE)
      {
         tlsUpdateTranscriptHash(context, message, length);
      }

      //Parse client's handshake message
      error = tlsParseClientHandshakeMessage(context, msgType, p, n);

      //Update the hash value with the incoming handshake message
      if(msgType != TLS_TYPE_CLIENT_KEY_EXCHANGE)
      {
         tlsUpdateTranscriptHash(context, message, length);
      }
   }
   else
#endif
   //Unsupported mode of operation?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
