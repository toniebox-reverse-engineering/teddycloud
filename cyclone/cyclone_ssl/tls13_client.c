/**
 * @file tls13_client.c
 * @brief Handshake message processing (TLS 1.3 client)
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
#include "tls_cipher_suites.h"
#include "tls_handshake.h"
#include "tls_client_extensions.h"
#include "tls_client_misc.h"
#include "tls_extensions.h"
#include "tls_transcript_hash.h"
#include "tls_misc.h"
#include "tls13_client.h"
#include "tls13_client_extensions.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "tls13_misc.h"
#include "kdf/hkdf.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Send EndOfEarlyData message
 *
 * The EndOfEarlyData message indicates that all 0-RTT application data
 * messages, if any, have been transmitted and that the following records
 * are protected under handshake traffic keys
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13SendEndOfEarlyData(TlsContext *context)
{
#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   Tls13EndOfEarlyData *message;

   //Point to the buffer where to format the message
   message = (Tls13EndOfEarlyData *) (context->txBuffer + context->txBufferLen);

   //If the server has accepted early data, an EndOfEarlyData message will be
   //sent to indicate the key change
   error = tls13FormatEndOfEarlyData(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending EndOfEarlyData message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_END_OF_EARLY_DATA);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //Calculate client handshake traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientHsTrafficSecret);

      //Handshake traffic keys successfully calculated?
      if(!error)
      {
         //Send a Finished message to the server
         context->state = TLS_STATE_CLIENT_FINISHED;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format EndOfEarlyData message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the EndOfEarlyData message
 * @param[out] length Length of the resulting EndOfEarlyData message
 * @return Error code
 **/

error_t tls13FormatEndOfEarlyData(TlsContext *context,
   Tls13EndOfEarlyData *message, size_t *length)
{
   //The EndOfEarlyData message does not contain any data
   *length = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HelloRetryRequest message
 *
 * The server will send this message in response to a ClientHello message if
 * it is able to find an acceptable set of parameters but the ClientHello does
 * not contain sufficient information to proceed with the handshake
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming HelloRetryRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tls13ParseHelloRetryRequest(TlsContext *context,
   const Tls13HelloRetryRequest *message, size_t length)
{
   error_t error;
   uint16_t cipherSuite;
   uint8_t compressMethod;
   const uint8_t *p;
   const HashAlgo *hashAlgo;
   TlsHelloExtensions extensions;

   //Debug message
   TRACE_INFO("HelloRetryRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->versionMax != TLS_VERSION_1_3)
      return ERROR_UNEXPECTED_MESSAGE;

   //If a client receives a second HelloRetryRequest in the same connection,
   //it must abort the handshake with an unexpected_message alert
   if(context->state != TLS_STATE_SERVER_HELLO &&
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

   //Get the value of the legacy_compression_method field
   compressMethod = *p;
   //Point to the next field
   p += sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Legacy version
   TRACE_INFO("  legacyVersion = 0x%04" PRIX16 " (%s)\r\n",
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
   TRACE_DEBUG("  legacyCompressMethod = 0x%02" PRIX8 "\r\n", compressMethod);

   //The legacy_version field must be set to 0x0303, which is the version
   //number for TLS 1.2
   if(ntohs(message->serverVersion) != TLS_VERSION_1_2)
      return ERROR_VERSION_NOT_SUPPORTED;

   //A client which receives a legacy_session_id_echo field that does not
   //match what it sent in the ClientHello must abort the handshake with an
   //illegal_parameter alert (RFC 8446, section 4.1.4)
   if(message->sessionIdLen != context->sessionIdLen ||
      osMemcmp(message->sessionId, context->sessionId, message->sessionIdLen))
   {
      //The legacy_session_id_echo field is not valid
      return ERROR_ILLEGAL_PARAMETER;
   }

   //Upon receipt of a HelloRetryRequest, the client must check that the
   //legacy_compression_method is 0
   if(compressMethod != TLS_COMPRESSION_METHOD_NULL)
      return ERROR_DECODING_FAILED;

   //Parse the list of extensions offered by the server
   error = tlsParseHelloExtensions(TLS_TYPE_HELLO_RETRY_REQUEST, p, length,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //The HelloRetryRequest message must contain a SupportedVersions extension
   if(extensions.selectedVersion == NULL)
      return ERROR_VERSION_NOT_SUPPORTED;

   //TLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      //Release transcript hash context
      tlsFreeTranscriptHash(context);

      //Format initial ClientHello message
      error = tlsFormatInitialClientHello(context);
      //Any error to report?
      if(error)
         return error;
   }

   //The SupportedVersions extension contains the selected version
   error = tls13ParseServerSupportedVersionsExtension(context,
      extensions.selectedVersion);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions offered by the server
   error = tlsCheckHelloExtensions(TLS_TYPE_HELLO_RETRY_REQUEST,
      context->version, &extensions);
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

   //When the server responds to a ClientHello with a HelloRetryRequest, the
   //value of ClientHello1 is replaced with a special synthetic handshake
   //message of handshake type MessageHash containing Hash(ClientHello1)
   error = tls13DigestClientHello1(context);
   //Any error to report?
   if(error)
      return error;

   //When sending a HelloRetryRequest, the server may provide a Cookie
   //extension to the client
   error = tls13ParseCookieExtension(context, extensions.cookie);
   //Any error to report?
   if(error)
      return error;

   //The KeyShare extension contains the mutually supported group the server
   //intends to negotiate
   error = tls13ParseSelectedGroupExtension(context, extensions.selectedGroup);
   //Any error to report?
   if(error)
      return error;

   //Point to the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hashAlgo == NULL)
      return ERROR_FAILURE;

   //In addition, in its updated ClientHello, the client should not offer any
   //pre-shared keys associated with a hash other than that of the selected
   //cipher suite. This allows the client to avoid having to compute partial
   //hash transcripts for multiple hashes in the second ClientHello
   if(tls13IsPskValid(context))
   {
      //Remove any PSKs which are incompatible with the server's indicated
      //cipher suite
      if(tlsGetHashAlgo(context->pskHashAlgo) != hashAlgo)
      {
         context->pskHashAlgo = TLS_HASH_ALGO_NONE;
         context->ticketHashAlgo = TLS_HASH_ALGO_NONE;
      }
   }
   else if(tls13IsTicketValid(context))
   {
      //Remove any PSKs which are incompatible with the server's indicated
      //cipher suite
      if(tlsGetHashAlgo(context->ticketHashAlgo) != hashAlgo)
      {
         context->ticketHashAlgo = TLS_HASH_ALGO_NONE;
      }
   }

   //Any 0-RTT data sent by the client?
   if(context->earlyDataEnabled)
   {
      //A client must not include the EarlyData extension in its followup
      //ClientHello (refer to RFC 8446, section 4.2.10)
      context->earlyDataRejected = TRUE;
   }

   //Clients must abort the handshake with an illegal_parameter alert if the
   //HelloRetryRequest would not result in any change in the ClientHello
   if(context->cookieLen == 0 && context->namedGroup == context->preferredGroup)
   {
      //Report an error
      return ERROR_ILLEGAL_PARAMETER;
   }

   //Another handshake message cannot be packed in the same record as the
   //HelloRetryRequest
   if(context->rxBufferLen != 0)
      return ERROR_UNEXPECTED_MESSAGE;

#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
   //The middlebox compatibility mode improves the chance of successfully
   //connecting through middleboxes
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM &&
      context->state == TLS_STATE_SERVER_HELLO)
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

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EncryptedExtensions message
 *
 * The server sends the EncryptedExtensions message immediately after the
 * ServerHello message. The EncryptedExtensions message contains extensions
 * that can be protected
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming EncryptedExtensions message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tls13ParseEncryptedExtensions(TlsContext *context,
   const Tls13EncryptedExtensions *message, size_t length)
{
   error_t error;
   TlsHelloExtensions extensions;

   //Debug message
   TRACE_INFO("EncryptedExtensions message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_ENCRYPTED_EXTENSIONS)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check the length of the EncryptedExtensions message
   if(length < sizeof(Tls13EncryptedExtensions))
      return ERROR_DECODING_FAILED;

   //Parse the list of extensions offered by the server
   error = tlsParseHelloExtensions(TLS_TYPE_ENCRYPTED_EXTENSIONS,
      (uint8_t *) message, length, &extensions);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions offered by the server
   error = tlsCheckHelloExtensions(TLS_TYPE_ENCRYPTED_EXTENSIONS,
      context->version, &extensions);
   //Any error to report?
   if(error)
      return error;

#if (TLS_SNI_SUPPORT == ENABLED)
   //When the server includes a ServerName extension, the data field of
   //this extension may be empty
   error = tlsParseServerSniExtension(context, extensions.serverNameList);
   //Any error to report?
   if(error)
      return error;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED && TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //A client must treat receipt of both MaxFragmentLength and RecordSizeLimit
   //extensions as a fatal error, and it should generate an illegal_parameter
   //alert (refer to RFC 8449, section 5)
   if(extensions.maxFragLen != NULL && extensions.recordSizeLimit != NULL)
      return ERROR_ILLEGAL_PARAMETER;
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

#if (TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //Parse EarlyData extension
   error = tls13ParseServerEarlyDataExtension(context,
      TLS_TYPE_ENCRYPTED_EXTENSIONS, extensions.earlyDataIndication);
   //Any error to report?
   if(error)
      return error;

   //Check whether the server has accepted the early data
   if(context->earlyDataExtReceived)
   {
#if (TLS_ALPN_SUPPORT == ENABLED)
      //Valid ticket?
      if(!tls13IsPskValid(context) && tls13IsTicketValid(context))
      {
         //Enforce ALPN protocol
         if(context->selectedProtocol != NULL || context->ticketAlpn != NULL)
         {
            if(context->selectedProtocol != NULL && context->ticketAlpn != NULL)
            {
               //Compare the selected ALPN protocol against the expected value
               if(osStrcmp(context->selectedProtocol, context->ticketAlpn))
               {
                  //The selected ALPN protocol is not acceptable
                  return ERROR_HANDSHAKE_FAILED;
               }
            }
            else
            {
               //The selected ALPN protocol is not acceptable
               return ERROR_HANDSHAKE_FAILED;
            }
         }
      }
#endif

      //The EndOfEarlyData message is encrypted with the 0-RTT traffic keys
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //Calculate client early traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientEarlyTrafficSecret);
      //Any error to report?
      if(error)
         return error;

      //Restore sequence number
      context->encryptionEngine.seqNum = context->earlyDataSeqNum;
   }
#endif

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

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NewSessionTicket message
 *
 * At any time after the server has received the client Finished message, it
 * may send a NewSessionTicket message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming NewSessionTicket message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tls13ParseNewSessionTicket(TlsContext *context,
   const Tls13NewSessionTicket *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const Tls13Ticket *ticket;
   const HashAlgo *hashAlgo;
   TlsHelloExtensions extensions;

   //Debug message
   TRACE_INFO("NewSessionTicket message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_APPLICATION_DATA &&
      context->state != TLS_STATE_CLOSING)
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Check the length of the NewSessionTicket message
   if(length < sizeof(Tls13NewSessionTicket))
      return ERROR_DECODING_FAILED;

   //Point to the ticket nonce
   p = message->ticketNonce;
   //Remaining bytes to process
   length -= sizeof(Tls13NewSessionTicket);

   //Malformed NewSessionTicket message?
   if(length < message->ticketNonceLen)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += message->ticketNonceLen;
   //Remaining bytes to process
   length -= message->ticketNonceLen;

   //Malformed NewSessionTicket message?
   if(length < sizeof(Tls13Ticket))
      return ERROR_DECODING_FAILED;

   //Point to the session ticket
   ticket = (Tls13Ticket *) p;
   //Retrieve the length of the ticket
   n = ntohs(ticket->length);

   //Malformed NewSessionTicket message?
   if(length < (sizeof(Tls13Ticket) + n))
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(Tls13Ticket) + n;
   //Remaining bytes to process
   length -= sizeof(Tls13Ticket) + n;

   //The message includes a set of extension values for the ticket
   error = tlsParseHelloExtensions(TLS_TYPE_NEW_SESSION_TICKET, p, length,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions offered by the server
   error = tlsCheckHelloExtensions(TLS_TYPE_NEW_SESSION_TICKET,
      context->version, &extensions);
   //Any error to report?
   if(error)
      return error;

   //A ticket_lifetime value of zero indicates that the ticket should be
   //discarded immediately
   if(ntohl(message->ticketLifetime) > 0)
   {
      //Check the length of the session ticket
      if(n > 0 && n <= TLS13_MAX_TICKET_SIZE)
      {
         //Servers may send multiple tickets on a single connection
         if(context->ticket != NULL)
         {
            //Release memory
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
         osMemcpy(context->ticket, ticket->data, n);
         context->ticketLen = n;

         //The client's view of the age of a ticket is the time since the
         //receipt of the NewSessionTicket message
         context->ticketTimestamp = osGetSystemTime();

         //Save the lifetime of the ticket
         context->ticketLifetime = ntohl(message->ticketLifetime);

         //Clients must not cache tickets for longer than 7 days, regardless
         //of the ticket_lifetime value (refer to RFC 8446, section 4.6.1)
         context->ticketLifetime = MIN(context->ticketLifetime,
            TLS13_MAX_TICKET_LIFETIME);

         //Random value used to obscure the age of the ticket
         context->ticketAgeAdd = ntohl(message->ticketAgeAdd);

         //The sole extension currently defined for NewSessionTicket is
         //EarlyData indicating that the ticket may be used to send 0-RTT data
         error = tls13ParseServerEarlyDataExtension(context,
            TLS_TYPE_NEW_SESSION_TICKET, extensions.earlyDataIndication);
         //Any error to report?
         if(error)
            return error;

         //The hash function used by HKDF is the cipher suite hash algorithm
         hashAlgo = context->cipherSuite.prfHashAlgo;
         //Make sure the hash algorithm is valid
         if(hashAlgo == NULL)
            return ERROR_FAILURE;

         //Calculate the PSK associated with the ticket
         error = tls13HkdfExpandLabel(context->transportProtocol, hashAlgo,
            context->resumptionMasterSecret, hashAlgo->digestSize, "resumption",
            message->ticketNonce, message->ticketNonceLen, context->ticketPsk,
            hashAlgo->digestSize);
         //Any error to report?
         if(error)
            return error;

         //Set the length of the PSK associated with the ticket
         context->ticketPskLen = hashAlgo->digestSize;

         //Debug message
         TRACE_DEBUG("Ticket PSK:\r\n");
         TRACE_DEBUG_ARRAY("  ", context->ticketPsk, context->ticketPskLen);
      }
   }

   //Successful processing
   return NO_ERROR;
}

#endif
