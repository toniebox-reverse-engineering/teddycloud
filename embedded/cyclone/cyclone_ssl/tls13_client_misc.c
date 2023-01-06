/**
 * @file tls13_client_misc.c
 * @brief Helper functions for TLS 1.3 client
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
#include "tls_client.h"
#include "tls_common.h"
#include "tls_transcript_hash.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_client_misc.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Check whether an incoming ServerHello message is a HelloRetryRequest
 * @param[in] message Pointer to the ServerHello message
 * @param[in] length Length of the ServerHello message
 * @return TRUE is the message is a HelloRetryRequest, else FALSE
 **/

bool_t tls13IsHelloRetryRequest(const TlsServerHello *message, size_t length)
{
   bool_t res;

   //Initialize flag
   res = FALSE;

   //Check the length of the incoming ServerHello message
   if(length >= sizeof(TlsServerHello))
   {
      //Upon receiving a message with type ServerHello, implementations must
      //first examine the Random field
      if(!osMemcmp(&message->random, tls13HelloRetryRequestRandom,
         sizeof(tls13HelloRetryRequestRandom)))
      {
         //The Random field matches the special value
         res = TRUE;
      }
   }

   //Return TRUE is the message is a HelloRetryRequest, else FALSE
   return res;
}


/**
 * @brief Compute PSK binder values
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] identityList List of the identities that the client is willing
 *   to negotiate with the server
 * @param[in,out] binderList List of HMAC values, one for each PSK offered in
 *   the PreSharedKey extension
 * @return Error code
 **/

error_t tls13ComputePskBinders(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, const Tls13PskIdentityList *identityList,
   Tls13PskBinderList *binderList)
{
   error_t error;
   size_t n;
   size_t m;
   size_t truncatedClientHelloLen;
   uint8_t *q;
   const uint8_t *p;
   Tls13PskBinder *binder;
   const Tls13PskIdentity *identity;

   //Initialize status code
   error = NO_ERROR;

#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Check whether the ClientHello message contains a PreSharedKey extension
   if(identityList != NULL && binderList != NULL)
   {
      //Point to the list of the identities that the client is willing to
      //negotiate with the server
      p = identityList->value;
      n = ntohs(identityList->length);

      //Point to the list of HMAC values, one for each PSK offered in the
      //PreSharedKey extension
      q = binderList->value;
      m = ntohs(binderList->length);

      //Each entry in the binders list is computed as an HMAC over a transcript
      //hash containing a partial ClientHello up to the binders list itself
      truncatedClientHelloLen = (uint8_t *) binderList - (uint8_t *) clientHello;

      //Loop through the list of PSK identities
      while(n > 0)
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

         //Point to the PskBinderEntry
         binder = (Tls13PskBinder *) q;

         //Malformed PreSharedKey extension?
         if(m < sizeof(Tls13PskBinder))
            return ERROR_DECODING_FAILED;
         if(m < (sizeof(Tls13PskBinder) + binder->length))
            return ERROR_DECODING_FAILED;

         //Point to the next PskBinderEntry
         q += sizeof(Tls13PskBinder) + binder->length;
         m -= sizeof(Tls13PskBinder) + binder->length;

         //Fix the value of the PSK binder
         error = tls13ComputePskBinder(context, clientHello, clientHelloLen,
            truncatedClientHelloLen, identity, binder->value, binder->length);
         //Any error to report?
         if(error)
            break;
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Send early data to the remote TLS server
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[out] written Actual number of bytes written
 * @return Error code
 **/

error_t tls13SendEarlyData(TlsContext *context, const void *data,
   size_t length, size_t *written)
{
#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Actual number of bytes written
   *written = 0;

   //Valid PSK?
   if(tls13IsPskValid(context))
   {
      //Make sure a valid cipher suite has been provisioned
      if(context->pskCipherSuite == 0)
         return ERROR_END_OF_STREAM;
   }
   else if(tls13IsTicketValid(context))
   {
      //Make sure the cipher suite associated with the ticket is valid
      if(context->ticketCipherSuite == 0)
         return ERROR_END_OF_STREAM;
   }
   else
   {
      //The pre-shared key is not valid
      return ERROR_END_OF_STREAM;
   }

   //Initialize status code
   error = NO_ERROR;

   //TLS 1.3 allows clients to send data on the first flight
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

      //The TLS handshake is implemented as a state machine representing the
      //current location in the protocol
      if(context->state == TLS_STATE_INIT)
      {
         //TLS handshake initialization
         error = tlsInitHandshake(context);
      }
      else if(context->state == TLS_STATE_CLIENT_HELLO)
      {
         //If the client opts to send application data in its first flight
         //of messages, it must supply both the PreSharedKey and EarlyData
         //extensions
         context->earlyDataEnabled = TRUE;

         //When a client first connects to a server, it is required to send
         //the ClientHello as its first message
         error = tlsSendClientHello(context);
      }
      else if(context->state == TLS_STATE_SERVER_HELLO)
      {
         //Initialize handshake message hashing
         error = tlsInitTranscriptHash(context);

#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
         //DTLS implementations do not use the "compatibility mode" and must
         //not send ChangeCipherSpec messages (refer to RFC 9147, section 5)
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
         {
            //In middlebox compatibility mode, the client sends a dummy
            //ChangeCipherSpec record immediately before its second flight
            context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
         }
         else
#endif
         {
            //The client can send its second flight
            context->state = TLS_STATE_CLIENT_HELLO_2;
         }
      }
      else if(context->state == TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC)
      {
         //Send a dummy ChangeCipherSpec record
         error = tlsSendChangeCipherSpec(context);
      }
      else if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         //Compute early traffic keys
         error = tls13GenerateEarlyTrafficKeys(context);
      }
      else if(context->state == TLS_STATE_EARLY_DATA)
      {
         //Send as much data as possible
         if(*written < length &&
            context->earlyDataLen < context->maxEarlyDataSize)
         {
            //Calculate the number of bytes to write at a time
            n = MIN(context->txBufferMaxLen, length - *written);
            n = MIN(n, context->maxEarlyDataSize - context->earlyDataLen);

            //The record length must not exceed 16384 bytes
            n = MIN(n, TLS_MAX_RECORD_LENGTH);

            //Debug message
            TRACE_INFO("Sending early data (%" PRIuSIZE " bytes)...\r\n", n);

            //Send 0-RTT data
            error = tlsWriteProtocolData(context, data, n,
               TLS_TYPE_APPLICATION_DATA);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               data = (uint8_t *) data + n;
               //Update byte counter
               *written += n;

               //Total amount of 0-RTT data that have been sent by the client
               context->earlyDataLen += n;
            }
         }
         else
         {
            //Clients must not more than max_early_data_size bytes of 0-RTT data
            break;
         }
      }
      else
      {
         //Report an error
         error = ERROR_UNEXPECTED_STATE;
      }
   }

   //Check status code
   if(error == NO_ERROR && length != 0 && *written == 0)
   {
      error = ERROR_END_OF_STREAM;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
