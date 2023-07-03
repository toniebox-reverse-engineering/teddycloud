/**
 * @file tls_ticket.c
 * @brief TLS session tickets
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
#include "tls_ticket.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_TICKET_SUPPORT == ENABLED)


/**
 * @brief Initialize ticket encryption context
 * @param[in] ticketContext Pointer to ticket encryption context
 * @return Error code
 **/

error_t tlsInitTicketContext(TlsTicketContext *ticketContext)
{
   //Make sure the ticket encryption context is valid
   if(ticketContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //Erase ticket encryption context
   osMemset(ticketContext, 0, sizeof(TlsTicketContext));

   //Create a mutex to prevent simultaneous access to the context
   if(!osCreateMutex(&ticketContext->mutex))
   {
      //Report an error
      return ERROR_OUT_OF_RESOURCES;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Session ticket encryption
 * @param[in] context Pointer to the TLS context
 * @param[in] plaintext Plaintext session state
 * @param[in] plaintextLen Length of the plaintext session state, in bytes
 * @param[out] ciphertext Encrypted ticket
 * @param[out] ciphertextLen Length of the encrypted ticket, in bytes
 * @param[in] param Pointer to the ticket encryption context
 * @return Error code
 **/

error_t tlsEncryptTicket(TlsContext *context, const uint8_t *plaintext,
   size_t plaintextLen, uint8_t *ciphertext, size_t *ciphertextLen, void *param)
{
   error_t error;
   uint8_t *iv;
   uint8_t *data;
   uint8_t *tag;
   systime_t time;
   TlsTicketContext *ticketContext;
   TlsTicketEncryptionState *state;

   //Check parameters
   if(context == NULL || param == NULL)
      return ERROR_INVALID_PARAMETER;
   if(plaintext == NULL || ciphertext == NULL || ciphertextLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   iv = NULL;
   data = NULL;
   tag = NULL;

   //Point to the ticket encryption context
   ticketContext = (TlsTicketContext *) param;

   //Acquire exclusive access to the ticket encryption context
   osAcquireMutex(&ticketContext->mutex);

   //The keys should be changed regularly (refer to RFC 5077, section 5.5)
   tlsCheckTicketKeyLifetime(&ticketContext->encryptionState);
   tlsCheckTicketKeyLifetime(&ticketContext->prevEncryptionState);

   //Point to the current ticket encryption state
   state = &ticketContext->encryptionState;

   //Check whether the ticket encryption state is valid
   if(state->valid)
   {
      //Get current time
      time = osGetSystemTime();

      //Check the validity of the encryption keys
      if((time - state->timestamp) >= TLS_TICKET_LIFETIME)
      {
         //Rotate keys
         ticketContext->prevEncryptionState = ticketContext->encryptionState;
         ticketContext->encryptionState.valid = FALSE;
      }
   }

   //Invalid set of keys?
   if(!state->valid)
   {
      //Generate a new set of keys
      error = tlsGenerateTicketKeys(ticketContext, context->prngAlgo,
         context->prngContext);
   }

   //Check status code
   if(!error)
   {
      //Point to the IV
      iv = ciphertext + TLS_TICKET_KEY_NAME_SIZE;
      //Point to the data
      data = iv + TLS_TICKET_IV_SIZE;
      //Point to the buffer where to store the authentication tag
      tag = data + plaintextLen;

      //Copy plaintext state
      osMemmove(data, plaintext, plaintextLen);
      //Copy key name
      osMemcpy(ciphertext, state->keyName, TLS_TICKET_KEY_NAME_SIZE);

      //Generate a random IV
      error = context->prngAlgo->read(context->prngContext, iv,
         TLS_TICKET_IV_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Initialize AES context
      error = aesInit(&ticketContext->aesContext, state->key,
         TLS_TICKET_KEY_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Initialize GCM context
      error = gcmInit(&ticketContext->gcmContext, AES_CIPHER_ALGO,
         &ticketContext->aesContext);
   }
   else
   {
      //Failed to initialize AES context
      state = NULL;
   }

   //Check status code
   if(!error)
   {
      //Calculate the length of the encrypted ticket
      *ciphertextLen = plaintextLen + TLS_TICKET_KEY_NAME_SIZE +
         TLS_TICKET_IV_SIZE + TLS_TICKET_TAG_SIZE;

      //The actual state information in encrypted using AES-GCM
      error = gcmEncrypt(&ticketContext->gcmContext, iv, TLS_TICKET_IV_SIZE,
         state->keyName, TLS_TICKET_KEY_NAME_SIZE, data, data, plaintextLen,
         tag, TLS_TICKET_TAG_SIZE);
   }

   //Erase AES context
   if(state != NULL)
   {
      aesDeinit(&ticketContext->aesContext);
   }

   //Release exclusive access to the ticket encryption context
   osReleaseMutex(&ticketContext->mutex);

   //Return status code
   return error;
}


/**
 * @brief Session ticket decryption
 * @param[in] context Pointer to the TLS context
 * @param[in] ciphertext Encrypted ticket
 * @param[in] ciphertextLen Length of the encrypted ticket, in bytes
 * @param[out] plaintext Plaintext session state
 * @param[out] plaintextLen Length of the plaintext session state, in bytes
 * @param[in] param Pointer to the ticket encryption context
 * @return Error code
 **/

error_t tlsDecryptTicket(TlsContext *context, const uint8_t *ciphertext,
   size_t ciphertextLen, uint8_t *plaintext, size_t *plaintextLen, void *param)
{
   error_t error;
   const uint8_t *iv;
   const uint8_t *data;
   const uint8_t *tag;
   TlsTicketContext *ticketContext;
   TlsTicketEncryptionState *state;

   //Check parameters
   if(context == NULL || param == NULL)
      return ERROR_INVALID_PARAMETER;
   if(ciphertext == NULL || plaintext == NULL || plaintextLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the encrypted ticket
   if(ciphertextLen < (TLS_TICKET_KEY_NAME_SIZE + TLS_TICKET_IV_SIZE +
      TLS_TICKET_TAG_SIZE))
   {
      //Report an error
      return ERROR_DECRYPTION_FAILED;
   }

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   iv = NULL;
   data = NULL;
   tag = NULL;
   state = NULL;

   //Point to the ticket encryption context
   ticketContext = (TlsTicketContext *) param;

   //Acquire exclusive access to the ticket encryption context
   osAcquireMutex(&ticketContext->mutex);

   //The keys should be changed regularly (refer to RFC 5077, section 5.5)
   tlsCheckTicketKeyLifetime(&ticketContext->encryptionState);
   tlsCheckTicketKeyLifetime(&ticketContext->prevEncryptionState);

   //Compare key names
   if(tlsCompareTicketKeyName(ciphertext, ciphertextLen,
      &ticketContext->encryptionState))
   {
      //Point to the current set of keys
      state = &ticketContext->encryptionState;
   }
   else if(tlsCompareTicketKeyName(ciphertext, ciphertextLen,
      &ticketContext->prevEncryptionState))
   {
      //Point to the previous set of keys
      state = &ticketContext->prevEncryptionState;
   }
   else
   {
      //Unknown key name
      error = ERROR_DECRYPTION_FAILED;
   }

   //Check status code
   if(!error)
   {
      //Point to the IV
      iv = ciphertext + TLS_TICKET_KEY_NAME_SIZE;
      //Point to the data
      data = iv + TLS_TICKET_IV_SIZE;
      //Point to the authentication tag
      tag = ciphertext + ciphertextLen - TLS_TICKET_TAG_SIZE;

      //Retrieve the length of the data
      *plaintextLen = ciphertextLen - TLS_TICKET_KEY_NAME_SIZE -
         TLS_TICKET_IV_SIZE - TLS_TICKET_TAG_SIZE;

      //Initialize AES context
      error = aesInit(&ticketContext->aesContext, state->key,
         TLS_TICKET_KEY_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Initialize GCM context
      error = gcmInit(&ticketContext->gcmContext, AES_CIPHER_ALGO,
         &ticketContext->aesContext);
   }
   else
   {
      //Failed to initialize AES context
      state = NULL;
   }

   //Check status code
   if(!error)
   {
      //The actual state information in encrypted using AES-GCM
      error = gcmDecrypt(&ticketContext->gcmContext, iv, TLS_TICKET_IV_SIZE,
         state->keyName, TLS_TICKET_KEY_NAME_SIZE, data, plaintext,
         *plaintextLen, tag, TLS_TICKET_TAG_SIZE);
   }

   //Erase AES context
   if(state != NULL)
   {
      aesDeinit(&ticketContext->aesContext);
   }

   //Release exclusive access to the ticket encryption context
   osReleaseMutex(&ticketContext->mutex);

   //Return status code
   return error;
}


/**
 * @brief Generate a new set of keys
 * @param[in] ticketContext Pointer to ticket encryption context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t tlsGenerateTicketKeys(TlsTicketContext *ticketContext,
   const PrngAlgo *prngAlgo, void *prngContext)
{
   error_t error;
   TlsTicketEncryptionState *state;

   //Point to the current ticket encryption state
   state = &ticketContext->encryptionState;

   //The set of keys is not valid anymore
   state->valid = FALSE;

   //The key name should be randomly generated to avoid collisions between
   //servers (refer to RFC 5077, section 4)
   error = prngAlgo->read(prngContext, state->keyName,
      TLS_TICKET_KEY_NAME_SIZE);
   //Any error to report?
   if(error)
      return error;

   //Generate a random encryption key
   error = prngAlgo->read(prngContext, state->key, TLS_TICKET_KEY_SIZE);
   //Any error to report?
   if(error)
      return error;

   //Save current time
   state->timestamp = osGetSystemTime();
   //The set of keys is valid
   state->valid = TRUE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check the validity of a given set of keys
 * @param[in] state Pointer to ticket encryption state
 **/

void tlsCheckTicketKeyLifetime(TlsTicketEncryptionState *state)
{
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Valid set of keys?
   if(state->valid)
   {
      //Check lifetime
      if((time - state->timestamp) >= (2 * TLS_TICKET_LIFETIME))
      {
         //Clear ticket keys
         osMemset(state, 0, sizeof(TlsTicketEncryptionState));
      }
   }
}


/**
 * @brief Key name comparison
 * @param[in] ticket Encrypted ticket
 * @param[in] ticketLen Length of the encrypted ticket, in bytes
 * @param[in] state Pointer to ticket encryption state
 **/

bool_t tlsCompareTicketKeyName(const uint8_t *ticket, size_t ticketLen,
   const TlsTicketEncryptionState *state)
{
   bool_t res;

   //Initialize flag
   res = FALSE;

   //Valid set of keys?
   if(state->valid)
   {
      //The key name serves to identify a particular set of keys used to
      //protect the ticket (refer to RFC 5077, section 4)
      if(ticketLen >= TLS_TICKET_KEY_NAME_SIZE)
      {
         //Compare key names
         if(osMemcmp(ticket, state->keyName, TLS_TICKET_KEY_NAME_SIZE) == 0)
         {
            //The key name is valid
            res = TRUE;
         }
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Properly dispose ticket encryption context
 * @param[in] ticketContext Pointer to ticket encryption context to be released
 **/

void tlsFreeTicketContext(TlsTicketContext *ticketContext)
{
   //Make sure the ticket encryption context is valid
   if(ticketContext != NULL)
   {
      //Release previously allocated resources
      osDeleteMutex(&ticketContext->mutex);

      //Erase ticket encryption context
      osMemset(ticketContext, 0, sizeof(TlsTicketContext));
   }
}

#endif
