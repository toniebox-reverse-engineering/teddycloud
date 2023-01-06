/**
 * @file tls13_key_material.c
 * @brief TLS 1.3 key schedule
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
#include "tls_misc.h"
#include "tls_key_material.h"
#include "tls_transcript_hash.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "kdf/hkdf.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief HKDF-Expand-Label function
 * @param[in] transportProtocol Transport protocol (TLS or DTLS)
 * @param[in] hash Hash function used by HKDF
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] context Pointer to the upper-layer context
 * @param[in] contextLen Length of the upper-layer context
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tls13HkdfExpandLabel(TlsTransportProtocol transportProtocol,
   const HashAlgo *hash, const uint8_t *secret, size_t secretLen,
   const char_t *label, const uint8_t *context, size_t contextLen,
   uint8_t *output, size_t outputLen)
{
   error_t error;
   size_t n;
   size_t labelLen;
   uint8_t *hkdfLabel;
   const char_t *prefix;

   //Check parameters
   if(label == NULL)
      return ERROR_INVALID_PARAMETER;
   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the label
   labelLen = osStrlen(label);

   //Check parameters
   if(labelLen > (255 - 6) || contextLen > 255)
      return ERROR_INVALID_LENGTH;

   //Compute the length of the HkdfLabel structure
   n = labelLen + contextLen + 10;
   //Allocate a memory buffer to hold the HkdfLabel structure
   hkdfLabel = tlsAllocMem(n);

   //Successful memory allocation?
   if(hkdfLabel != NULL)
   {
#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //For DTLS 1.3, the label prefix shall be "dtls13". This ensures key
         //separation between DTLS 1.3 and TLS 1.3. Note that there is no
         //trailing space (refer to RFC 9147, section 5.9)
         prefix = "dtls13";
      }
      else
#endif
      //TLS protocol?
      {
         //For TLS 1.3, the label prefix shall be "tls13 " (refer to RFC 8446,
         //section 7.1)
         prefix = "tls13 ";
      }

      //Format the HkdfLabel structure
      hkdfLabel[0] = MSB(outputLen);
      hkdfLabel[1] = LSB(outputLen);
      hkdfLabel[2] = (uint8_t) (labelLen + 6);
      osMemcpy(hkdfLabel + 3, prefix, 6);
      osMemcpy(hkdfLabel + 9, label, labelLen);
      hkdfLabel[labelLen + 9] = (uint8_t) contextLen;
      osMemcpy(hkdfLabel + labelLen + 10, context, contextLen);

      //Debug message
      TRACE_DEBUG("HkdfLabel (%" PRIuSIZE " bytes):\r\n", n);
      TRACE_DEBUG_ARRAY("  ", hkdfLabel, n);

      //Compute HKDF-Expand(Secret, HkdfLabel, Length)
      error = hkdfExpand(hash, secret, secretLen, hkdfLabel, n, output,
         outputLen);

      //Release previously allocated memory
      tlsFreeMem(hkdfLabel);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Derive-Secret function
 * @param[in] context Pointer to the TLS context
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] message Concatenation of the indicated handshake messages
 * @param[in] messageLen Length of the indicated handshake messages
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tls13DeriveSecret(TlsContext *context, const uint8_t *secret,
   size_t secretLen, const char_t *label, const char_t *message,
   size_t messageLen, uint8_t *output, size_t outputLen)
{
   error_t error;
   const HashAlgo *hash;
   uint8_t digest[TLS_MAX_HKDF_DIGEST_SIZE];

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;

   //Make sure the hash algorithm is valid
   if(hash != NULL)
   {
      //Any handshake messages specified?
      if(message != NULL)
      {
         //Compute Transcript-Hash(Messages);
         error = hash->compute(message, messageLen, digest);
      }
      else
      {
         //Implementations can implement the transcript by keeping a running
         //transcript hash value based on the negotiated hash
         error = tlsFinalizeTranscriptHash(context, hash,
            context->transcriptHashContext, "", digest);
      }

      //Debug message
      TRACE_DEBUG("Transcript hash (%" PRIuSIZE " bytes):\r\n", hash->digestSize);
      TRACE_DEBUG_ARRAY("  ", digest, hash->digestSize);

      //Check status code
      if(!error)
      {
         //Compute HKDF-Expand-Label(Secret, Label, Transcript-Hash, Hash.length)
         error = tls13HkdfExpandLabel(context->transportProtocol, hash, secret,
            secretLen, label, digest, hash->digestSize, output, outputLen);
      }
   }
   else
   {
      //Invalid HKDF hash algorithm
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute early traffic keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13GenerateEarlyTrafficKeys(TlsContext *context)
{
   error_t error;
   size_t ikmLen;
   const uint8_t *ikm;
   const HashAlgo *hash;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Although PSKs can be established out of band, PSKs can also be established
   //in a previous connection
   if(tls13IsPskValid(context))
   {
      //IKM is a pre-shared key established externally
      ikm = context->psk;
      ikmLen = context->pskLen;
   }
   else if(tls13IsTicketValid(context))
   {
      //IKM is a pre-shared key derived from the resumption master secret from
      //a previous connection
      ikm = context->ticketPsk;
      ikmLen = context->ticketPskLen;
   }
   else
   {
      //The pre-shared key is not valid
      return ERROR_FAILURE;
   }

   //Calculate early secret
   error = hkdfExtract(hash, ikm, ikmLen, NULL, 0, context->secret);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Early secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //Calculate client early traffic secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "c e traffic", NULL, 0, context->clientEarlyTrafficSecret,
      hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Client early secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->clientEarlyTrafficSecret, hash->digestSize);

   //The traffic keying material is generated from the traffic secret value
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Calculate client early traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientEarlyTrafficSecret);
   }
   else
   {
      //The implementation must verify that its receive buffer is empty
      if(context->rxBufferLen == 0)
      {
         //Calculate client early traffic keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_CLIENT, context->clientEarlyTrafficSecret);
      }
      else
      {
         //The receive buffer is not empty
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Failed to generate traffic keying material?
   if(error)
      return error;

   //Calculate early exporter master secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "e exp master", NULL, 0, context->exporterMasterSecret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Early exporter master secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->exporterMasterSecret, hash->digestSize);

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Log client early traffic secret
   tlsDumpSecret(context, "CLIENT_EARLY_TRAFFIC_SECRET",
      context->clientEarlyTrafficSecret, hash->digestSize);

   //Log early exporter master secret
   tlsDumpSecret(context, "EARLY_EXPORTER_SECRET",
      context->exporterMasterSecret, hash->digestSize);
#endif

   //When a PSK is used and early data is allowed for that PSK, the client can
   //send application data in its first flight of messages
   context->state = TLS_STATE_EARLY_DATA;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute handshake traffic keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13GenerateHandshakeTrafficKeys(TlsContext *context)
{
   error_t error;
   size_t ikmLen;
   const uint8_t *ikm;
   const HashAlgo *hash;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_ECDHE_KE_SUPPORT == ENABLED)
   //(EC)DHE key exchange method?
   if(context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_ECDHE)
   {
      //If PSK is not in use, IKM is a string of Hash-lengths bytes set to 0
      osMemset(context->secret, 0, hash->digestSize);

      //Point to the IKM argument
      ikm = context->secret;
      ikmLen = hash->digestSize;
   }
   else
#endif
#if (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //PSK-only or PSK with (EC)DHE key exchange method?
   if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
      context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
   {
      //Although PSKs can be established out of band, PSKs can also be
      //established in a previous connection
      if(tls13IsPskValid(context))
      {
         //IKM is a pre-shared key established externally
         ikm = context->psk;
         ikmLen = context->pskLen;
      }
      else if(tls13IsTicketValid(context))
      {
         //IKM is a pre-shared key derived from the resumption master secret
         //from a previous connection
         ikm = context->ticketPsk;
         ikmLen = context->ticketPskLen;
      }
      else
      {
         //The pre-shared key is not valid
         return ERROR_FAILURE;
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //Report an error
      return ERROR_FAILURE;
   }

   //Calculate early secret
   error = hkdfExtract(hash, ikm, ikmLen, NULL, 0, context->secret);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Early secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //Derive early secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "derived", "", 0, context->secret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Derived secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //PSK-only key exchange method?
   if(context->keyExchMethod == TLS13_KEY_EXCH_PSK)
   {
      //If the (EC)DHE shared secret is not available, then the 0-value
      //consisting of a string of Hash.length bytes set to zeros is used
      osMemset(context->premasterSecret, 0, hash->digestSize);
      context->premasterSecretLen = hash->digestSize;
   }

   //Calculate handshake secret
   error = hkdfExtract(hash, context->premasterSecret,
      context->premasterSecretLen, context->secret, hash->digestSize,
      context->secret);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Handshake secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //Calculate client handshake traffic secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "c hs traffic", NULL, 0, context->clientHsTrafficSecret,
      hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Client handshake secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->clientHsTrafficSecret, hash->digestSize);

   //Calculate server handshake traffic secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "s hs traffic", NULL, 0, context->serverHsTrafficSecret,
      hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Server handshake secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->serverHsTrafficSecret, hash->digestSize);

   //The implementation must verify that its receive buffer is empty before
   //switching to encrypted handshake
   if(context->rxBufferLen != 0)
      return ERROR_HANDSHAKE_FAILED;

   //The traffic keying material is generated from the traffic secret value
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //Calculate client handshake traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientHsTrafficSecret);

      //Check status code
      if(!error)
      {
         //Calculate server handshake traffic keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_SERVER, context->serverHsTrafficSecret);
      }
   }
   else
   {
      //Release decryption engine
      tlsFreeEncryptionEngine(&context->decryptionEngine);

      //Calculate client handshake traffic keys
      error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientHsTrafficSecret);

      //Check status code
      if(!error)
      {
         //Calculate server handshake traffic keys
         error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
            TLS_CONNECTION_END_SERVER, context->serverHsTrafficSecret);
      }
   }

   //Failed to generate traffic keying material?
   if(error)
      return error;

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Log client handshake traffic secret
   tlsDumpSecret(context, "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
      context->clientHsTrafficSecret, hash->digestSize);

   //Log server handshake traffic secret
   tlsDumpSecret(context, "SERVER_HANDSHAKE_TRAFFIC_SECRET",
      context->serverHsTrafficSecret, hash->digestSize);
#endif

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Because each epoch resets the sequence number space, a separate sliding
      //window is needed for each epoch (refer to RFC 9147, section 4.5.1)
      dtlsInitReplayWindow(context);
   }
#endif

   //In all handshakes, the server must send the EncryptedExtensions message
   //immediately after the ServerHello message
   context->state = TLS_STATE_ENCRYPTED_EXTENSIONS;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute server application traffic keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13GenerateServerAppTrafficKeys(TlsContext *context)
{
   error_t error;
   const HashAlgo *hash;
   uint8_t ikm[TLS_MAX_HKDF_DIGEST_SIZE];

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Derive handshake secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "derived", "", 0, context->secret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Derived secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //IKM is a string of Hash-lengths bytes set to 0
   osMemset(ikm, 0, hash->digestSize);

   //Calculate master secret
   error = hkdfExtract(hash, ikm, hash->digestSize, context->secret,
      hash->digestSize, context->secret);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Master secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

   //Calculate client application traffic secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "c ap traffic", NULL, 0, context->clientAppTrafficSecret,
      hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Client application secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->clientAppTrafficSecret, hash->digestSize);

   //Calculate server application traffic secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "s ap traffic", NULL, 0, context->serverAppTrafficSecret,
      hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Server application secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->serverAppTrafficSecret, hash->digestSize);

   //All the traffic keying material is recomputed when changing from the
   //handshake to application data keys
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The implementation must verify that its receive buffer is empty before
      //rekeying
      if(context->rxBufferLen == 0)
      {
         //Release decryption engine
         tlsFreeEncryptionEngine(&context->decryptionEngine);

         //Inform the record layer that subsequent records will be protected
         //under the new traffic keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_SERVER, context->serverAppTrafficSecret);
      }
      else
      {
         //The receive buffer is not empty
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //Inform the record layer that subsequent records will be protected
      //under the new traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_SERVER, context->serverAppTrafficSecret);
   }

   //Failed to generate traffic keying material?
   if(error)
      return error;

   //Calculate exporter master secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "exp master", NULL, 0, context->exporterMasterSecret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Exporter master secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->exporterMasterSecret, hash->digestSize);

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Log client application traffic secret
   tlsDumpSecret(context, "CLIENT_TRAFFIC_SECRET_0",
      context->clientAppTrafficSecret, hash->digestSize);

   //Log server application traffic secret
   tlsDumpSecret(context, "SERVER_TRAFFIC_SECRET_0",
      context->serverAppTrafficSecret, hash->digestSize);

   //Log exporter master secret
   tlsDumpSecret(context, "EXPORTER_SECRET",
      context->exporterMasterSecret, hash->digestSize);
#endif

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM &&
      context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Because each epoch resets the sequence number space, a separate sliding
      //window is needed for each epoch (refer to RFC 9147, section 4.5.1)
      dtlsInitReplayWindow(context);
   }
#endif

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //In DTLS 1.3, the EndOfEarlyData message is omitted both from the wire
      //and the handshake transcript. Because DTLS records have epochs,
      //EndOfEarlyData is not necessary to determine when the early data is
      //complete (refer to RFC 9147, section 5.6)
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM &&
         context->earlyDataEnabled && context->earlyDataExtReceived)
      {
         //If the server sent an EarlyData extension, the client must send an
         //EndOfEarlyData message after receiving the server Finished
         context->state = TLS_STATE_END_OF_EARLY_DATA;
      }
      else
      {
         //PSK key exchange method?
         if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
            context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
            context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
         {
            //Send a Finished message to the server
            context->state = TLS_STATE_CLIENT_FINISHED;
         }
         else
         {
            //Send a Certificate message if the server requests it
            context->state = TLS_STATE_CLIENT_CERTIFICATE;
         }
      }
   }
   else
   {
      //PSK key exchange method?
      if(context->keyExchMethod == TLS13_KEY_EXCH_PSK ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_DHE ||
         context->keyExchMethod == TLS13_KEY_EXCH_PSK_ECDHE)
      {
         //Wait for a Finished message from the client
         context->state = TLS_STATE_CLIENT_FINISHED;
      }
      else
      {
         //The client must send a Certificate message if the server requests it
         if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
         {
            context->state = TLS_STATE_CLIENT_CERTIFICATE;
         }
         else
         {
            context->state = TLS_STATE_CLIENT_FINISHED;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute client application traffic keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13GenerateClientAppTrafficKeys(TlsContext *context)
{
   error_t error;
   const HashAlgo *hash;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //At this point, the handshake is complete, and the client and server
   //derive the keying material required by the record layer to exchange
   //application-layer data protected through authenticated encryption
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);

      //Inform the record layer that subsequent records will be protected
      //under the new traffic keys
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         TLS_CONNECTION_END_CLIENT, context->clientAppTrafficSecret);
   }
   else
   {
      //The implementation must verify that its receive buffer is empty before
      //rekeying
      if(context->rxBufferLen == 0)
      {
         //Release decryption engine
         tlsFreeEncryptionEngine(&context->decryptionEngine);

         //Inform the record layer that subsequent records will be protected
         //under the new traffic keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_CLIENT, context->clientAppTrafficSecret);
      }
      else
      {
         //The receive buffer is not empty
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Failed to generate traffic keying material?
   if(error)
      return error;

   //Calculate resumption master secret
   error = tls13DeriveSecret(context, context->secret, hash->digestSize,
      "res master", NULL, 0, context->resumptionMasterSecret, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Resumption master secret:\r\n");
   TRACE_DEBUG_ARRAY("  ", context->resumptionMasterSecret, hash->digestSize);

   //Once all the values which are to be derived from a given secret have been
   //computed, that secret should be erased
   osMemset(context->secret, 0, TLS13_MAX_HKDF_DIGEST_SIZE);
   osMemset(context->clientEarlyTrafficSecret, 0, TLS13_MAX_HKDF_DIGEST_SIZE);
   osMemset(context->clientHsTrafficSecret, 0, TLS13_MAX_HKDF_DIGEST_SIZE);
   osMemset(context->serverHsTrafficSecret, 0, TLS13_MAX_HKDF_DIGEST_SIZE);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM &&
      context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Because each epoch resets the sequence number space, a separate sliding
      //window is needed for each epoch (refer to RFC 9147, section 4.5.1)
      dtlsInitReplayWindow(context);
   }
#endif

#if (TLS_TICKET_SUPPORT == ENABLED)
   //Check whether session ticket mechanism is enabled
   if(context->entity == TLS_CONNECTION_END_SERVER &&
      context->ticketEncryptCallback != NULL &&
      context->pskKeModeSupported)
   {
      //At any time after the server has received the client Finished message,
      //it may send a NewSessionTicket message
      context->state = TLS_STATE_NEW_SESSION_TICKET;
   }
   else
#endif
   {
      //At this point, the handshake is complete, and the client and server
      //can exchange application-layer data
      context->state = TLS_STATE_APPLICATION_DATA;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
