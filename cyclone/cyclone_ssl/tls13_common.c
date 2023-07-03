/**
 * @file tls13_common.c
 * @brief Handshake message processing (TLS 1.3 client and server)
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
#include "tls_misc.h"
#include "tls13_common.h"
#include "tls13_key_material.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Send KeyUpdate message
 *
 * The KeyUpdate handshake message is used to indicate that the sender is
 * updating its sending cryptographic keys. This message can be sent by either
 * peer after it has sent a Finished message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13SendKeyUpdate(TlsContext *context)
{
   error_t error;
   size_t length;
   uint8_t *appTrafficSecret;
   Tls13KeyUpdate *message;
   const HashAlgo *hash;

   //Initialize pointer
   appTrafficSecret = NULL;

   //Point to the buffer where to format the message
   message = (Tls13KeyUpdate *) (context->txBuffer + context->txBufferLen);

   //Format KeyUpdate message
   error = tls13FormatKeyUpdate(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending KeyUpdate message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_KEY_UPDATE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The hash function used by HKDF is the cipher suite hash algorithm
      hash = context->cipherSuite.prfHashAlgo;

      //Make sure the hash algorithm is valid
      if(hash != NULL)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            appTrafficSecret = context->clientAppTrafficSecret;
         }
         else
         {
            appTrafficSecret = context->serverAppTrafficSecret;
         }

         //Compute the next generation of application traffic secret
         error = tls13HkdfExpandLabel(context->transportProtocol, hash,
            appTrafficSecret, hash->digestSize, "traffic upd", NULL, 0,
            appTrafficSecret, hash->digestSize);
      }
      else
      {
         //The hash algorithm is not valid
         error = ERROR_FAILURE;
      }
   }

   //Check status code
   if(!error)
   {
      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //All the traffic keying material is recomputed whenever the underlying
      //secret changes
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         context->entity, appTrafficSecret);
   }

   //Check status code
   if(!error)
   {
      //After sending a KeyUpdate message, the sender shall send all its
      //traffic using the next generation of keys
      context->state = TLS_STATE_APPLICATION_DATA;
   }

   //Return status code
   return error;
}


/**
 * @brief Format KeyUpdate message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the KeyUpdate message
 * @param[out] length Length of the resulting KeyUpdate message
 * @return Error code
 **/

error_t tls13FormatKeyUpdate(TlsContext *context, Tls13KeyUpdate *message,
   size_t *length)
{
   //The request_update field indicates whether the recipient of the KeyUpdate
   //should respond with its own KeyUpdate
   message->requestUpdate = TLS_KEY_UPDATE_NOT_REQUESTED;

   //The KeyUpdate message consists of a single byte
   *length = sizeof(Tls13KeyUpdate);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyUpdate message
 *
 * The KeyUpdate handshake message is used to indicate that the sender is
 * updating its sending cryptographic keys. This message can be sent by either
 * peer after it has sent a Finished message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming EncryptedExtensions message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tls13ParseKeyUpdate(TlsContext *context, const Tls13KeyUpdate *message,
   size_t length)
{
   error_t error;
   uint8_t *appTrafficSecret;
   TlsConnectionEnd entity;
   const HashAlgo *hash;

   //Debug message
   TRACE_INFO("KeyUpdate message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check the length of the KeyUpdate message
   if(length != sizeof(Tls13KeyUpdate))
      return ERROR_DECODING_FAILED;

   //Ensure the value of the request_update field is valid
   if(message->requestUpdate != TLS_KEY_UPDATE_NOT_REQUESTED &&
      message->requestUpdate != TLS_KEY_UPDATE_REQUESTED)
   {
      //If an implementation receives any other value, it must terminate the
      //connection with an illegal_parameter alert
      return ERROR_ILLEGAL_PARAMETER;
   }

   //Implementations that receive a KeyUpdate prior to receiving a Finished
   //message must terminate the connection with an unexpected_message alert
   if(context->state != TLS_STATE_APPLICATION_DATA &&
      context->state != TLS_STATE_CLOSING)
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
   //Increment the count of consecutive KeyUpdate messages
   context->keyUpdateCount++;

   //Do not allow too many consecutive KeyUpdate message
   if(context->keyUpdateCount > TLS_MAX_KEY_UPDATE_MESSAGES)
      return ERROR_UNEXPECTED_MESSAGE;
#endif

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Upon receiving a KeyUpdate, the receiver must update its receiving keys
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      entity = TLS_CONNECTION_END_SERVER;
      appTrafficSecret = context->serverAppTrafficSecret;
   }
   else
   {
      entity = TLS_CONNECTION_END_CLIENT;
      appTrafficSecret = context->clientAppTrafficSecret;
   }

   //Compute the next generation of application traffic secret
   error = tls13HkdfExpandLabel(context->transportProtocol, hash,
      appTrafficSecret, hash->digestSize, "traffic upd", NULL, 0,
      appTrafficSecret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //The implementation must verify that its receive buffer is empty before
   //rekeying
   if(context->rxBufferLen != 0)
      return ERROR_UNEXPECTED_MESSAGE;

   //Release decryption engine
   tlsFreeEncryptionEngine(&context->decryptionEngine);

   //All the traffic keying material is recomputed whenever the underlying
   //secret changes
   error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
      entity, appTrafficSecret);
   //Any error to report?
   if(error)
      return error;

   //Check the value of the request_update field
   if(message->requestUpdate == TLS_KEY_UPDATE_REQUESTED &&
      context->state == TLS_STATE_APPLICATION_DATA)
   {
#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
      if(context->keyUpdateCount == 1)
#endif
      {
         //If the request_update field is set to update_requested then the
         //receiver must send a KeyUpdate of its own with request_update set to
         //update_not_requested prior to sending its next application data
         context->state = TLS_STATE_KEY_UPDATE;
      }
   }

   //Successful processing
   return NO_ERROR;
}

#endif
