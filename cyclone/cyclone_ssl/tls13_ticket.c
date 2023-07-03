/**
 * @file tls13_ticket.c
 * @brief TLS 1.3 session tickets
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
#include "tls_misc.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Check whether a session ticket is valid
 * @param[in] context Pointer to the TLS context
 * @return TRUE is the session ticket is valid, else FALSE
 **/

bool_t tls13IsTicketValid(TlsContext *context)
{
   bool_t valid = FALSE;

   //Make sure the hash algorithm associated with the ticket is valid
   if(tlsGetHashAlgo(context->ticketHashAlgo) != NULL)
   {
      //Valid ticket PSK?
      if(context->ticketPskLen > 0)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Valid ticket?
            if(context->ticket != NULL && context->ticketLen > 0)
            {
               valid = TRUE;
            }
         }
         else
         {
            valid = TRUE;
         }
      }
   }

   //Return TRUE is the ticket is valid, else FALSE
   return valid;
}


/**
 * @brief Save session ticket
 * @param[in] context Pointer to the TLS context
 * @param[out] session Pointer to the session state
 * @return Error code
 **/

error_t tls13SaveSessionTicket(const TlsContext *context,
   TlsSessionState *session)
{
   const HashAlgo *hashAlgo;

   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
      return ERROR_INVALID_VERSION;

   //Invalid session ticket?
   if(context->ticket == NULL || context->ticketLen == 0)
      return ERROR_INVALID_TICKET;

   //Invalid session parameters?
   if(context->cipherSuite.identifier == 0 ||
      context->cipherSuite.prfHashAlgo == NULL)
   {
      return ERROR_INVALID_SESSION;
   }

   //Point to the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;

   //Allocate a memory block to hold the ticket
   session->ticket = tlsAllocMem(context->ticketLen);
   //Failed to allocate memory?
   if(session->ticket == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Get current time
   session->timestamp = osGetSystemTime();

   //Save session parameters
   session->version = context->version;
   session->cipherSuite = context->cipherSuite.identifier;
   session->ticketTimestamp = context->ticketTimestamp;
   session->ticketLifetime = context->ticketLifetime;
   session->ticketAgeAdd = context->ticketAgeAdd;
   session->maxEarlyDataSize = context->maxEarlyDataSize;

   //Copy session ticket
   osMemcpy(session->ticket, context->ticket, context->ticketLen);
   session->ticketLen = context->ticketLen;

   //Each PSK established via the ticket mechanism is associated with a single
   //hash algorithm
   if(hashAlgo == tlsGetHashAlgo(TLS_HASH_ALGO_SHA256))
   {
      session->ticketHashAlgo = TLS_HASH_ALGO_SHA256;
   }
   else if(hashAlgo == tlsGetHashAlgo(TLS_HASH_ALGO_SHA384))
   {
      session->ticketHashAlgo = TLS_HASH_ALGO_SHA384;
   }
   else
   {
      session->ticketHashAlgo = TLS_HASH_ALGO_NONE;
   }

   //Copy ticket PSK
   osMemcpy(session->secret, context->ticketPsk, hashAlgo->digestSize);

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Valid ALPN protocol?
   if(context->selectedProtocol != NULL)
   {
      size_t n;

      //Retrieve the length of the ALPN protocol
      n = osStrlen(context->selectedProtocol);

      //Allocate a memory block to hold the ALPN protocol
      session->ticketAlpn = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(session->ticketAlpn == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Copy the ALPN protocol associated with the ticket
      osStrcpy(session->ticketAlpn, context->selectedProtocol);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Restore a TLS session using session ticket
 * @param[in] context Pointer to the TLS context
 * @param[in] session Pointer to the session state
 * @return Error code
 **/

error_t tls13RestoreSessionTicket(TlsContext *context,
   const TlsSessionState *session)
{
   systime_t serverTicketAge;

   //Check TLS version
   if(session->version != TLS_VERSION_1_3)
      return ERROR_INVALID_VERSION;

   //Invalid session ticket?
   if(session->ticket == NULL || session->ticketLen == 0)
      return ERROR_INVALID_TICKET;

   //Invalid session parameters?
   if(session->cipherSuite == 0 ||
      session->ticketHashAlgo == TLS_HASH_ALGO_NONE)
   {
      return ERROR_INVALID_SESSION;
   }

   //Compute the time since the ticket was issued
   serverTicketAge = osGetSystemTime() - session->ticketTimestamp;

   //Verify ticket's validity
   if(serverTicketAge >= (session->ticketLifetime * 1000))
      return ERROR_TICKET_EXPIRED;

   //Restore session parameters
   context->version = session->version;
   context->ticketCipherSuite = session->cipherSuite;
   context->ticketHashAlgo = session->ticketHashAlgo;
   context->ticketTimestamp = session->ticketTimestamp;
   context->ticketLifetime = session->ticketLifetime;
   context->ticketAgeAdd = session->ticketAgeAdd;
   context->maxEarlyDataSize = session->maxEarlyDataSize;
   context->sessionIdLen = 0;

   //Release existing session ticket, if any
   if(context->ticket != NULL)
   {
      osMemset(context->ticket, 0, context->ticketLen);
      tlsFreeMem(context->ticket);
      context->ticket = NULL;
      context->ticketLen = 0;
   }

   //Allocate a memory block to hold the ticket
   context->ticket = tlsAllocMem(session->ticketLen);
   //Failed to allocate memory?
   if(context->ticket == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy session ticket
   osMemcpy(context->ticket, session->ticket, session->ticketLen);
   context->ticketLen = session->ticketLen;

   //Each PSK established via the ticket mechanism is associated with a single
   //hash algorithm
   if(session->ticketHashAlgo == TLS_HASH_ALGO_SHA256)
   {
      context->ticketPskLen = SHA256_DIGEST_SIZE;
   }
   else if(session->ticketHashAlgo == TLS_HASH_ALGO_SHA384)
   {
      context->ticketPskLen = SHA384_DIGEST_SIZE;
   }
   else
   {
      context->ticketPskLen = 0;
   }

   //Copy ticket PSK
   osMemcpy(context->ticketPsk, session->secret, context->ticketPskLen);

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Release ALPN protocol, if any
   if(context->ticketAlpn != NULL)
   {
      tlsFreeMem(context->ticketAlpn);
      context->ticketAlpn = NULL;
   }

   //Valid ALPN protocol?
   if(session->ticketAlpn != NULL)
   {
      size_t n;

      //Retrieve the length of the ALPN protocol
      n = osStrlen(session->ticketAlpn);

      //Allocate a memory block to hold the ALPN protocol
      context->ticketAlpn = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(context->ticketAlpn == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Copy the ALPN protocol associated with the ticket
      osStrcpy(context->ticketAlpn, session->ticketAlpn);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Session ticket generation
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the NewSessionTicket message
 * @param[out] ticket Output stream where to write the session ticket
 * @param[out] length Length of the session ticket, in bytes
 * @return Error code
 **/

error_t tls13GenerateTicket(TlsContext *context,
   const Tls13NewSessionTicket *message, uint8_t *ticket, size_t *length)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   Tls13PlaintextSessionState *state;
   const HashAlgo *hashAlgo;

   //Point to the session state information
   state = (Tls13PlaintextSessionState *) ticket;

   //Save session state
   state->version = context->version;
   state->cipherSuite = context->cipherSuite.identifier;
   state->ticketTimestamp = osGetSystemTime();
   state->ticketLifetime = ntohl(message->ticketLifetime);
   state->ticketAgeAdd = ntohl(message->ticketAgeAdd);
   osMemcpy(state->ticketNonce, message->ticketNonce, message->ticketNonceLen);
   osMemset(state->ticketPsk, 0, TLS_MAX_HKDF_DIGEST_SIZE);

   //The hash function used by HKDF is the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hashAlgo == NULL)
      return ERROR_FAILURE;

   //Compute the PSK associated with the ticket
   error = tls13HkdfExpandLabel(context->transportProtocol, hashAlgo,
      context->resumptionMasterSecret, hashAlgo->digestSize, "resumption",
      message->ticketNonce, message->ticketNonceLen, state->ticketPsk,
      hashAlgo->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the ticket PSK
   state->ticketPskLen = hashAlgo->digestSize;

   //Compute the length of the session state
   n = sizeof(Tls13PlaintextSessionState);

   //Make sure a valid callback has been registered
   if(context->ticketEncryptCallback == NULL)
      return ERROR_FAILURE;

   //Encrypt the state information
   error = context->ticketEncryptCallback(context, (uint8_t *) state, n,
      ticket, length, context->ticketParam);
   //Any error to report?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
#else
   //Session ticket mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Session ticket verification
 * @param[in] context Pointer to the TLS context
 * @param[in] ticket Pointer to the encrypted ticket
 * @param[in] length Length of the encrypted ticket, in bytes
 * @param[in] obfuscatedTicketAge Obfuscated version of the ticket age
 * @return Error code
 **/

error_t tls13VerifyTicket(TlsContext *context, const uint8_t *ticket,
   size_t length, uint32_t obfuscatedTicketAge)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   error_t error;
   systime_t serverTicketAge;
   Tls13PlaintextSessionState *state;
   const HashAlgo *hashAlgo;
#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   systime_t delta;
   systime_t clientTicketAge;
#endif

   //Make sure a valid callback has been registered
   if(context->ticketDecryptCallback == NULL)
      return ERROR_DECRYPTION_FAILED;

   //Check the length of the ticket
   if(length == 0 || length > TLS13_MAX_TICKET_SIZE)
      return ERROR_DECRYPTION_FAILED;

   //Allocate a buffer to store the decrypted state information
   state = tlsAllocMem(length);
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Start of exception handling block
   do
   {
      //Decrypt the received ticket
      error = context->ticketDecryptCallback(context, ticket, length,
         (uint8_t *) state, &length, context->ticketParam);
      //Any error to report?
      if(error)
         break;

      //Check the length of the decrypted ticket
      if(length != sizeof(Tls13PlaintextSessionState))
      {
         //The ticket is malformed
         error = ERROR_INVALID_TICKET;
         break;
      }

      //Check TLS version
      if(state->version != TLS_VERSION_1_3)
      {
         //The ticket is not valid
         error = ERROR_INVALID_TICKET;
         break;
      }

      //Compute the time since the ticket was issued
      serverTicketAge = osGetSystemTime() - state->ticketTimestamp;

      //Verify ticket's validity
      if(serverTicketAge >= (state->ticketLifetime * 1000))
      {
         //The ticket is not valid
         error = ERROR_INVALID_TICKET;
         break;
      }

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
      //Compute the ticket age for the selected PSK identity by subtracting
      //ticket_age_add from obfuscated_ticket_age modulo 2^32
      clientTicketAge = obfuscatedTicketAge - state->ticketAgeAdd;

      //Calculate the difference between the client's view and the server's
      //view of the age of the ticket
      if(clientTicketAge < serverTicketAge)
      {
         delta = serverTicketAge - clientTicketAge;
      }
      else
      {
         delta = clientTicketAge - serverTicketAge;
      }

      //For PSKs provisioned via NewSessionTicket, the server must validate
      //that the ticket age for the selected PSK identity is within a small
      //tolerance of the time since the ticket was issued
      if(delta >= TLS13_TICKET_AGE_TOLERANCE)
      {
         //If it is not, the server should proceed with the handshake but
         //reject 0-RTT, and should not take any other action that assumes
         //that this ClientHello is fresh (refer to RFC 8446, 4.2.10)
         context->earlyDataRejected = TRUE;
      }
#endif

      //Any ticket must only be resumed with a cipher suite that has the same
      //KDF hash algorithm as that used to establish the original connection
      error = tlsSelectCipherSuite(context, state->cipherSuite);
      //Any error to report?
      if(error)
         break;

      //Point to the cipher suite hash algorithm
      hashAlgo = context->cipherSuite.prfHashAlgo;
      //Make sure the hash algorithm is valid
      if(hashAlgo == NULL)
      {
         //The ticket is malformed
         error = ERROR_INVALID_TICKET;
         break;
      }

      //The server must ensure that it selects a compatible PSK and cipher suite
      if(state->ticketPskLen != hashAlgo->digestSize)
      {
         //The ticket is malformed
         error = ERROR_INVALID_TICKET;
         break;
      }

      //Restore ticket PSK
      osMemcpy(context->ticketPsk, state->ticketPsk, state->ticketPskLen);
      context->ticketPskLen = state->ticketPskLen;

      //Retrieve the hash algorithm associated with the ticket
      if(hashAlgo == tlsGetHashAlgo(TLS_HASH_ALGO_SHA256))
      {
         context->ticketHashAlgo = TLS_HASH_ALGO_SHA256;
      }
      else if(hashAlgo == tlsGetHashAlgo(TLS_HASH_ALGO_SHA384))
      {
         context->ticketHashAlgo = TLS_HASH_ALGO_SHA384;
      }
      else
      {
         context->ticketHashAlgo = TLS_HASH_ALGO_NONE;
      }

      //End of exception handling block
   } while(0);

   //Release state information
   osMemset(state, 0, length);
   tlsFreeMem(state);

   //Return status code
   return error;
#else
   //Session ticket mechanism is not implemented
   return ERROR_DECRYPTION_FAILED;
#endif
}

#endif
