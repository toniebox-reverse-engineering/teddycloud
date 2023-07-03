/**
 * @file tls_common.c
 * @brief Handshake message processing (TLS client and server)
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
#include "tls_client.h"
#include "tls_server.h"
#include "tls_common.h"
#include "tls_certificate.h"
#include "tls_signature.h"
#include "tls_transcript_hash.h"
#include "tls_cache.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_signature.h"
#include "dtls_record.h"
#include "pkix/x509_common.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Send Certificate message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificate(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificate *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (TlsCertificate *) (context->txBuffer + context->txBufferLen);

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Client mode?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientCertRequested)
      {
         //Format Certificate message
         error = tlsFormatCertificate(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending Certificate message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE);
         }
      }
   }
   else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
   //Server mode?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //The server must send a Certificate message whenever the agreed-upon
      //key exchange method uses certificates for authentication
      if(context->cert != NULL)
      {
         //Format Certificate message
         error = tlsFormatCertificate(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending Certificate message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE);
         }
      }
   }
   else
#endif
   //Unsupported mode of operation?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
         }
         else
         {
            context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Clients must send a CertificateVerify message whenever
            //authenticating via a certificate
            if(context->clientCertRequested)
            {
               context->state = TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
            }
            else
            {
               context->state = TLS_STATE_CLIENT_FINISHED;
            }
         }
         else
         {
            //Servers must send a CertificateVerify message whenever
            //authenticating via a certificate
            context->state = TLS_STATE_SERVER_CERTIFICATE_VERIFY;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send CertificateVerify message
 *
 * The CertificateVerify message is used to provide explicit verification
 * of a client certificate. This message is only sent following a client
 * certificate that has signing capability
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificateVerify(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificateVerify *message;

   //Initialize status code
   error = NO_ERROR;

   //The CertificateVerify message is only sent following a client certificate
   //that has signing capability
   if(context->cert != NULL)
   {
      //Check certificate type
      if(context->cert->type == TLS_CERT_RSA_SIGN ||
         context->cert->type == TLS_CERT_RSA_PSS_SIGN ||
         context->cert->type == TLS_CERT_DSS_SIGN ||
         context->cert->type == TLS_CERT_ECDSA_SIGN ||
         context->cert->type == TLS_CERT_ED25519_SIGN ||
         context->cert->type == TLS_CERT_ED448_SIGN)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateVerify *) (context->txBuffer + context->txBufferLen);

         //Format CertificateVerify message
         error = tlsFormatCertificateVerify(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateVerify message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE_VERIFY);
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Send a ChangeCipherSpec message to the server
         context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
      }
      else
      {
         //Send a Finished message to the peer
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            context->state = TLS_STATE_CLIENT_FINISHED;
         }
         else
         {
            context->state = TLS_STATE_SERVER_FINISHED;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ChangeCipherSpec message
 *
 * The change cipher spec message is sent by both the client and the
 * server to notify the receiving party that subsequent records will be
 * protected under the newly negotiated CipherSpec and keys
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendChangeCipherSpec(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsChangeCipherSpec *message;

   //Point to the buffer where to format the message
   message = (TlsChangeCipherSpec *) (context->txBuffer + context->txBufferLen);

   //Format ChangeCipherSpec message
   error = tlsFormatChangeCipherSpec(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ChangeCipherSpec message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Send ChangeCipherSpec message
         error = dtlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_CHANGE_CIPHER_SPEC);
      }
      else
#endif
      //TLS protocol?
      {
         //Send ChangeCipherSpec message
         error = tlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_CHANGE_CIPHER_SPEC);
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
#if (DTLS_SUPPORT == ENABLED)
         //Release previous encryption engine first
         tlsFreeEncryptionEngine(&context->prevEncryptionEngine);

         //Save current encryption engine for later use
         context->prevEncryptionEngine = context->encryptionEngine;

         //Reset encryption engine
         osMemset(&context->encryptionEngine, 0, sizeof(TlsEncryptionEngine));
         context->encryptionEngine.epoch = context->prevEncryptionEngine.epoch;
#else
         //Release encryption engine first
         tlsFreeEncryptionEngine(&context->encryptionEngine);
#endif

         //Inform the record layer that subsequent records will be protected
         //under the newly negotiated encryption algorithm
         error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
            context->entity, NULL);

         //Check status code
         if(!error)
         {
            //Send a Finished message to the peer
            if(context->entity == TLS_CONNECTION_END_CLIENT)
            {
               context->state = TLS_STATE_CLIENT_FINISHED;
            }
            else
            {
               context->state = TLS_STATE_SERVER_FINISHED;
            }
         }
      }
      else
      {
#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
         //The middlebox compatibility mode improves the chance of successfully
         //connecting through middleboxes
         if(context->state == TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC ||
            context->state == TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2)
         {
            //The client can send its second flight
            context->state = TLS_STATE_CLIENT_HELLO_2;
         }
         else if(context->state == TLS_STATE_SERVER_CHANGE_CIPHER_SPEC ||
            context->state == TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC_2)
         {
            //All handshake messages after the ServerHello are now encrypted
            context->state = TLS_STATE_HANDSHAKE_TRAFFIC_KEYS;
         }
         else
#endif
         {
            //Middlebox compatibility mode is not implemented
            error = ERROR_UNEXPECTED_STATE;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send Finished message
 *
 * A Finished message is always sent immediately after a change
 * cipher spec message to verify that the key exchange and
 * authentication processes were successful. It is essential that a
 * change cipher spec message be received between the other handshake
 * messages and the Finished message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendFinished(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsFinished *message;

   //Point to the buffer where to format the message
   message = (TlsFinished *) (context->txBuffer + context->txBufferLen);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_CLIENT,
         context->clientVerifyData, &context->clientVerifyDataLen);
   }
   else
   {
      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_SERVER,
         context->serverVerifyData, &context->serverVerifyDataLen);
   }

   //Check status code
   if(!error)
   {
      //Format Finished message
      error = tlsFormatFinished(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending Finished message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_FINISHED);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Abbreviated or full handshake?
            if(context->resume)
            {
               //The client and server can now exchange application-layer data
               context->state = TLS_STATE_APPLICATION_DATA;
            }
            else
            {
#if (TLS_TICKET_SUPPORT == ENABLED)
               //The server uses the SessionTicket extension to indicate to
               //the client that it will send a new session ticket using the
               //NewSessionTicket handshake message
               if(context->sessionTicketExtReceived)
               {
                  //Wait for a NewSessionTicket message from the server
                  context->state = TLS_STATE_NEW_SESSION_TICKET;
               }
               else
#endif
               {
                  //Wait for a ChangeCipherSpec message from the server
                  context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
               }
            }
         }
         else
         {
            //Abbreviated or full handshake?
            if(context->resume)
            {
               //Wait for a ChangeCipherSpec message from the client
               context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
            }
            else
            {
               //The client and server can now exchange application-layer data
               context->state = TLS_STATE_APPLICATION_DATA;
            }
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Compute client application traffic keys
            context->state = TLS_STATE_CLIENT_APP_TRAFFIC_KEYS;
         }
         else
         {
            //Compute server application traffic keys
            context->state = TLS_STATE_SERVER_APP_TRAFFIC_KEYS;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] level Severity of the message (warning or fatal)
 * @param[in] description Description of the alert
 * @return Error code
 **/

error_t tlsSendAlert(TlsContext *context, uint8_t level, uint8_t description)
{
   error_t error;
   size_t length;
   TlsAlert *message;

   //Point to the buffer where to format the message
   message = (TlsAlert *) (context->txBuffer + context->txBufferLen);

   //Format Alert message
   error = tlsFormatAlert(context, level, description, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending Alert message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO_ARRAY("  ", message, length);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Send Alert message
         error = dtlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_ALERT);
      }
      else
#endif
      //TLS protocol?
      {
         //Send Alert message
         error = tlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_ALERT);
      }
   }

   //Alert messages convey the severity of the message
   if(level == TLS_ALERT_LEVEL_WARNING)
   {
      //If an alert with a level of warning is sent, generally the
      //connection can continue normally
      if(description == TLS_ALERT_CLOSE_NOTIFY)
      {
         //Either party may initiate a close by sending a close_notify alert
         context->closeNotifySent = TRUE;

         //Update FSM state
         context->state = TLS_STATE_CLOSING;
      }
   }
   else if(level == TLS_ALERT_LEVEL_FATAL)
   {
      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      context->fatalAlertSent = TRUE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         tlsRemoveFromCache(context);
      }
#endif

      //Servers and clients must forget any session identifiers
      osMemset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Update FSM state
      context->state = TLS_STATE_CLOSING;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Certificate message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the Certificate message
 * @param[out] length Length of the resulting Certificate message
 * @return Error code
 **/

error_t tlsFormatCertificate(TlsContext *context,
   TlsCertificate *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   TlsCertificateList *certificateList;

   //Point to the beginning of the handshake message
   p = message;
   //Length of the handshake message
   *length = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      Tls13CertRequestContext *certRequestContext;

      //Point to the certificate request context
      certRequestContext = (Tls13CertRequestContext *) p;

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //The value of the certificate_request_context field from server's
         //CertificateRequest message is echoed in the Certificate message
         if(context->certRequestContextLen > 0)
         {
            //Copy certificate request context
            osMemcpy(certRequestContext->value, context->certRequestContext,
               context->certRequestContextLen);
         }

         //The context is preceded by a length field
         certRequestContext->length = (uint8_t) context->certRequestContextLen;
      }
      else
      {
         //In the case of server authentication, this field shall be zero length
         certRequestContext->length = 0;
      }

      //Point to the next field
      p += sizeof(Tls13CertRequestContext) + certRequestContext->length;
      //Adjust the length of the Certificate message
      *length += sizeof(Tls13CertRequestContext) + certRequestContext->length;
   }
#endif

   //Point to the chain of certificates
   certificateList = (TlsCertificateList *) p;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check certificate type
   if(context->certFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
   {
      //Format the raw public key
      error = tlsFormatRawPublicKey(context, certificateList->value, &n);
   }
   else
#endif
   {
      //Format the certificate chain
      error = tlsFormatCertificateList(context, certificateList->value, &n);
   }

   //Check status code
   if(!error)
   {
      //A 3-byte length field shall precede the certificate list
      STORE24BE(n, certificateList->length);
      //Adjust the length of the Certificate message
      *length += sizeof(TlsCertificateList) + n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format CertificateVerify message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the CertificateVerify message
 * @param[out] length Length of the resulting CertificateVerify message
 * @return Error code
 **/

error_t tlsFormatCertificateVerify(TlsContext *context,
   TlsCertificateVerify *message, size_t *length)
{
   error_t error;

   //Length of the handshake message
   *length = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //In TLS version prior to 1.2, the digitally-signed element combines
      //MD5 and SHA-1
      error = tlsGenerateSignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //In TLS 1.2, the MD5/SHA-1 combination in the digitally-signed element
      //has been replaced with a single hash. The signed element now includes
      //a field that explicitly specifies the hash algorithm used
      error = tls12GenerateSignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //In TLS 1.3, the signed element specifies the signature algorithm used.
      //The content that is covered under the signature is the transcript hash
      //output
      error = tls13GenerateSignature(context, message, length);
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
 * @brief Format ChangeCipherSpec message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ChangeCipherSpec message
 * @param[out] length Length of the resulting ChangeCipherSpec message
 * @return Error code
 **/

error_t tlsFormatChangeCipherSpec(TlsContext *context,
   TlsChangeCipherSpec *message, size_t *length)
{
   //The message consists of a single byte of value 1
   message->type = 1;

   //Length of the ChangeCipherSpec message
   *length = sizeof(TlsChangeCipherSpec);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Finished message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the Finished message
 * @param[out] length Length of the resulting Finished message
 * @return Error code
 **/

error_t tlsFormatFinished(TlsContext *context,
   TlsFinished *message, size_t *length)
{
   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Copy the client's verify data
      osMemcpy(message, context->clientVerifyData, context->clientVerifyDataLen);
      //Length of the handshake message
      *length = context->clientVerifyDataLen;
   }
   else
   {
      //Copy the server's verify data
      osMemcpy(message, context->serverVerifyData, context->serverVerifyDataLen);
      //Length of the handshake message
      *length = context->serverVerifyDataLen;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] level Severity of the message (warning or fatal)
 * @param[in] description Description of the alert
 * @param[out] message Buffer where to format the Alert message
 * @param[out] length Length of the resulting Alert message
 * @return Error code
 **/

error_t tlsFormatAlert(TlsContext *context, uint8_t level,
   uint8_t description, TlsAlert *message, size_t *length)
{
   //Severity of the message
   message->level = level;
   //Description of the alert
   message->description = description;

   //Length of the Alert message
   *length = sizeof(TlsAlert);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SignatureAlgorithms extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the SignatureAlgorithms extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSignatureAlgorithmsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //This extension is not meaningful for TLS versions prior to 1.2. Clients
   //must not offer it if they are offering prior versions (refer to RFC 5246,
   //section 7.4.1.4.1)
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      TlsExtension *extension;
      TlsSignHashAlgos *supportedSignAlgos;

      //Add the SignatureAlgorithms extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SIGNATURE_ALGORITHMS);

      //Point to the list of the hash/signature algorithm pairs that the
      //server is able to verify
      supportedSignAlgos = (TlsSignHashAlgos *) extension->value;

      //Enumerate the hash/signature algorithm pairs in descending order
      //of preference
      n = 0;

#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED)
#if (TLS_ED25519_SUPPORT == ENABLED)
      //Ed25519 signature algorithm (PureEdDSA mode)
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ED25519;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
      //Ed448 signature algorithm (PureEdDSA mode)
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ED448;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //Any ECC cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
#if (TLS_SHA256_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-256
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-384
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-512
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
#endif
      }
#endif

#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //Check whether the X.509 parser supports RSA-PSS signatures
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
      {
#if (TLS_SHA256_SUPPORT == ENABLED)
         //RSASSA-PSS PSS signature algorithm with SHA-256
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
         //RSASSA-PSS PSS signature algorithm with SHA-384
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
         //RSASSA-PSS PSS signature algorithm with SHA-512
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
      }
#endif

#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA256_SUPPORT == ENABLED)
      //RSASSA-PSS RSAE signature algorithm with SHA-256
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
      //RSASSA-PSS RSAE signature algorithm with SHA-384
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
      //RSASSA-PSS RSAE signature algorithm with SHA-512
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
#endif
#endif

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA256_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-256
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-384
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-512
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
#endif
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //Any ECC cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
#if (TLS_SHA1_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-1
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
         //ECDSA signature algorithm with SHA-224
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
      }
#endif

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA1_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-1
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-224
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
#if (TLS_MD5_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature algorithm with MD5
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_MD5;
#endif
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA1_SUPPORT == ENABLED)
      //DSA signature algorithm with SHA-1
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
      //DSA signature algorithm with SHA-224
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
      //DSA signature algorithm with SHA-256
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif
#endif

      //Compute the length, in bytes, of the list
      n *= sizeof(TlsSignHashAlgo);
      //Fix the length of the list
      supportedSignAlgos->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSignHashAlgos);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SignatureAlgorithms extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SignatureAlgorithmsCert extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SignatureAlgorithmsCert extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSignatureAlgorithmsCertExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.2 implementations should also process this extension
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      TlsExtension *extension;
      TlsSignHashAlgos *supportedSignAlgos;

      //Add the SignatureAlgorithmsCert extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SIGNATURE_ALGORITHMS_CERT);

      //The SignatureAlgorithmsCert extension allows a client to indicate
      //which signature algorithms it can validate in X.509 certificates
      supportedSignAlgos = (TlsSignHashAlgos *) extension->value;

      //Enumerate the hash/signature algorithm pairs in descending order
      //of preference
      n = 0;

      //Ed25519 signature algorithm (PureEdDSA mode)
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ED25519))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ED25519;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //Ed448 signature algorithm (PureEdDSA mode)
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ED448))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ED448;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //ECDSA signature algorithm with SHA-256
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }

      //ECDSA signature algorithm with SHA-384
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }

      //ECDSA signature algorithm with SHA-512
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
      }

      //RSASSA-PSS PSS signature algorithm with SHA-256
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PSS PSS signature algorithm with SHA-384
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PSS PSS signature algorithm with SHA-512
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PSS RSAE signature algorithm with SHA-256
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PSS RSAE signature algorithm with SHA-384
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PSS RSAE signature algorithm with SHA-512
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_INTRINSIC;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-256
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-384
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-512
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
      }

      //ECDSA signature algorithm with SHA-1
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
      }

      //ECDSA signature algorithm with SHA-224
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-1
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with SHA-224
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
      }

      //RSASSA-PKCS1-v1_5 signature algorithm with MD5
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_MD5))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_MD5;
      }

      //DSA signature algorithm with SHA-1
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_DSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
      }

      //DSA signature algorithm with SHA-224
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_DSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
      }

      //DSA signature algorithm with SHA-256
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_DSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256))
      {
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }

      //Compute the length, in bytes, of the list
      n *= sizeof(TlsSignHashAlgo);
      //Fix the length of the list
      supportedSignAlgos->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSignHashAlgos);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SignatureAlgorithmsCert extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Certificate message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Certificate message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificate(TlsContext *context,
   const TlsCertificate *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const TlsCertificateList *certificateList;

   //Debug message
   TRACE_INFO("Certificate message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check current state
         if(context->state != TLS_STATE_SERVER_CERTIFICATE)
            return ERROR_UNEXPECTED_MESSAGE;
      }
      else
      {
         //The CertificateRequest message is optional
         if(context->state != TLS_STATE_CERTIFICATE_REQUEST &&
            context->state != TLS_STATE_SERVER_CERTIFICATE)
         {
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CERTIFICATE)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //Point to the beginning of the handshake message
   p = message;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      const Tls13CertRequestContext *certRequestContext;

      //Point to the certificate request context
      certRequestContext = (Tls13CertRequestContext *) p;

      //Malformed Certificate message?
      if(length < sizeof(Tls13CertRequestContext))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(Tls13CertRequestContext) + certRequestContext->length))
         return ERROR_DECODING_FAILED;

      //Point to the next field
      p += sizeof(Tls13CertRequestContext) + certRequestContext->length;
      //Remaining bytes to process
      length -= sizeof(Tls13CertRequestContext) + certRequestContext->length;
   }
#endif

   //Point to the chain of certificates
   certificateList = (TlsCertificateList *) p;

   //Malformed Certificate message?
   if(length < sizeof(TlsCertificateList))
      return ERROR_DECODING_FAILED;

   //Get the size occupied by the certificate list
   n = LOAD24BE(certificateList->length);
   //Remaining bytes to process
   length -= sizeof(TlsCertificateList);

   //Malformed Certificate message?
   if(n != length)
      return ERROR_DECODING_FAILED;

   //Non-empty certificate list?
   if(n > 0)
   {
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //Check certificate type
      if(context->peerCertFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
      {
         //Parse the raw public key
         error = tlsParseRawPublicKey(context, certificateList->value, n);
      }
      else
#endif
      {
         //Parse the certificate chain
         error = tlsParseCertificateList(context, certificateList->value, n);
      }
   }
   else
   {
#if (TLS_SERVER_SUPPORT == ENABLED)
      //Server mode?
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         //Check whether client authentication is required
         if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
         {
            //Version of TLS prior to TLS 1.3?
            if(context->version <= TLS_VERSION_1_2)
            {
               //If the client does not send any certificates, the server
               //responds with a fatal handshake_failure alert (refer to
               //RFC 5246, section 7.4.6)
               error = ERROR_HANDSHAKE_FAILED;
            }
            else
            {
               //If the client does not send any certificates, the server
               //aborts the handshake with a certificate_required alert (refer
               //to RFC 8446, section 4.4.2.4)
               error = ERROR_CERTIFICATE_REQUIRED;
            }
         }
         else
         {
            //The client did not send any certificates
            context->peerCertType = TLS_CERT_NONE;
            //The server may continue the handshake without client authentication
            error = NO_ERROR;
         }
      }
      else
#endif
      //Client mode?
      {
         //The server's certificate list must always be non-empty (refer to
         //RFC 8446, section 4.4.2)
         error = ERROR_DECODING_FAILED;
      }
   }

   //Check status code
   if(!error)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //The server does not send a ServerKeyExchange message when RSA
            //key exchange method is used
            if(context->keyExchMethod == TLS_KEY_EXCH_RSA)
            {
               context->state = TLS_STATE_CERTIFICATE_REQUEST;
            }
            else
            {
               context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
            }
         }
         else
         {
            //Wait for a ClientKeyExchange message from the client
            context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //The server must send a CertificateVerify message immediately
            //after the Certificate message
            context->state = TLS_STATE_SERVER_CERTIFICATE_VERIFY;
         }
         else
         {
            //The client must send a CertificateVerify message when the
            //Certificate message is non-empty
            if(context->peerCertType != TLS_CERT_NONE)
            {
               context->state = TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
            }
            else
            {
               context->state = TLS_STATE_CLIENT_FINISHED;
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse CertificateVerify message
 *
 * The CertificateVerify message is used to provide explicit verification
 * of a client certificate. This message is only sent following a client
 * certificate that has signing capability
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming CertificateVerify message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificateVerify(TlsContext *context,
   const TlsCertificateVerify *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("CertificateVerify message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_CERTIFICATE_VERIFY)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CERTIFICATE_VERIFY)
         return ERROR_UNEXPECTED_MESSAGE;
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //In TLS version prior to 1.2, the digitally-signed element combines
      //MD5 and SHA-1
      error = tlsVerifySignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //In TLS 1.2, the MD5/SHA-1 combination in the digitally-signed element
      //has been replaced with a single hash. The signed element now includes
      //a field that explicitly specifies the hash algorithm used
      error = tls12VerifySignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //In TLS 1.3, the signed element specifies the signature algorithm used.
      //The content that is covered under the signature is the transcript hash
      //output
      error = tls13VerifySignature(context, message, length);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Check status code
   if(!error)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Wait for a ChangeCipherSpec message from the client
         context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
      }
      else
      {
         //Wait for a Finished message from the peer
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            context->state = TLS_STATE_SERVER_FINISHED;
         }
         else
         {
            context->state = TLS_STATE_CLIENT_FINISHED;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ChangeCipherSpec message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ChangeCipherSpec message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseChangeCipherSpec(TlsContext *context,
   const TlsChangeCipherSpec *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("ChangeCipherSpec message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ChangeCipherSpec message
   if(length != sizeof(TlsChangeCipherSpec))
      return ERROR_DECODING_FAILED;

   //The message consists of a single byte of value 1
   if(message->type != 0x01)
      return ERROR_DECODING_FAILED;

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Check current state
         if(context->state != TLS_STATE_SERVER_CHANGE_CIPHER_SPEC)
            return ERROR_UNEXPECTED_MESSAGE;
      }
      else
      {
         //Check current state
         if(context->state != TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC)
            return ERROR_UNEXPECTED_MESSAGE;
      }

      //Release decryption engine first
      tlsFreeEncryptionEngine(&context->decryptionEngine);

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Initialize decryption engine using server write keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_SERVER, NULL);
         //Any error to report?
         if(error)
            return error;

         //Wait for a Finished message from the server
         context->state = TLS_STATE_SERVER_FINISHED;
      }
      else
      {
         //Initialize decryption engine using client write keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_CLIENT, NULL);
         //Any error to report?
         if(error)
            return error;

         //Wait for a Finished message from the client
         context->state = TLS_STATE_CLIENT_FINISHED;
      }

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Initialize sliding window
         dtlsInitReplayWindow(context);
      }
#endif
   }
   else
   {
      //In TLS 1.3, the ChangeCipherSpec message is used only for compatibility
      //purposes and must be dropped without further processing
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //A ChangeCipherSpec message received received before the first
         //ClientHello message or after the server's Finished message must
         //be treated as an unexpected record type
         if(context->state != TLS_STATE_SERVER_HELLO &&
            context->state != TLS_STATE_SERVER_HELLO_2 &&
            context->state != TLS_STATE_ENCRYPTED_EXTENSIONS &&
            context->state != TLS_STATE_CERTIFICATE_REQUEST &&
            context->state != TLS_STATE_SERVER_CERTIFICATE &&
            context->state != TLS_STATE_SERVER_CERTIFICATE_VERIFY &&
            context->state != TLS_STATE_SERVER_FINISHED)
         {
            //Report an error
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //A ChangeCipherSpec message received received before the first
         //ClientHello message or after the client's Finished message must
         //be treated as an unexpected record type
         if(context->state != TLS_STATE_CLIENT_HELLO_2 &&
            context->state != TLS_STATE_CLIENT_CERTIFICATE &&
            context->state != TLS_STATE_CLIENT_CERTIFICATE_VERIFY &&
            context->state != TLS_STATE_CLIENT_FINISHED)
         {
            //Report an error
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }

#if (TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES > 0)
      //Increment the count of consecutive ChangeCipherSpec messages
      context->changeCipherSpecCount++;

      //Do not allow too many consecutive ChangeCipherSpec messages
      if(context->changeCipherSpecCount > TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES)
         return ERROR_UNEXPECTED_MESSAGE;
#endif
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Finished message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Finished message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseFinished(TlsContext *context,
   const TlsFinished *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("Finished message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_FINISHED)
         return ERROR_UNEXPECTED_MESSAGE;

      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_SERVER,
         context->serverVerifyData, &context->serverVerifyDataLen);
      //Unable to generate the verify data?
      if(error)
         return error;

      //Check the length of the Finished message
      if(length != context->serverVerifyDataLen)
      {
#if (TLS_MAX_EMPTY_RECORDS > 0)
         return ERROR_INVALID_SIGNATURE;
#else
         return ERROR_DECODING_FAILED;
#endif
      }

      //Check the resulting verify data
      if(osMemcmp(message, context->serverVerifyData, context->serverVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_FINISHED)
         return ERROR_UNEXPECTED_MESSAGE;

      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_CLIENT,
         context->clientVerifyData, &context->clientVerifyDataLen);
      //Unable to generate the verify data?
      if(error)
         return error;

      //Check the length of the Finished message
      if(length != context->clientVerifyDataLen)
      {
#if (TLS_MAX_EMPTY_RECORDS > 0)
         return ERROR_INVALID_SIGNATURE;
#else
         return ERROR_DECODING_FAILED;
#endif
      }

      //Check the resulting verify data
      if(osMemcmp(message, context->clientVerifyData, context->clientVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;
   }

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Another handshake message cannot be packed in the same record as the
      //Finished
      if(context->rxBufferLen != 0)
         return ERROR_UNEXPECTED_MESSAGE;

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Abbreviated or full handshake?
         if(context->resume)
         {
            //Send a ChangeCipherSpec message to the server
            context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
         }
         else
         {
            //The client and server can now exchange application-layer data
            context->state = TLS_STATE_APPLICATION_DATA;
         }
      }
      else
      {
         //Abbreviated or full handshake?
         if(context->resume)
         {
            //The client and server can now exchange application-layer data
            context->state = TLS_STATE_APPLICATION_DATA;
         }
         else
         {
#if (TLS_TICKET_SUPPORT == ENABLED)
            //The server uses the SessionTicket extension to indicate to
            //the client that it will send a new session ticket using the
            //NewSessionTicket handshake message
            if(context->sessionTicketExtSent)
            {
               //Send a NewSessionTicket message to the client
               context->state = TLS_STATE_NEW_SESSION_TICKET;
            }
            else
#endif
            {
               //Send a ChangeCipherSpec message to the client
               context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
            }
         }
      }
   }
   else
   {
      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Compute server application traffic keys
         context->state = TLS_STATE_SERVER_APP_TRAFFIC_KEYS;
      }
      else
      {
         //Compute client application traffic keys
         context->state = TLS_STATE_CLIENT_APP_TRAFFIC_KEYS;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Alert message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseAlert(TlsContext *context,
   const TlsAlert *message, size_t length)
{
   //Debug message
   TRACE_INFO("Alert message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_INFO_ARRAY("  ", message, length);

   //Check message length
   if(length != sizeof(TlsAlert))
      return ERROR_INVALID_LENGTH;

   //Debug message
   TRACE_DEBUG("  Level = %" PRIu8 "\r\n", message->level);
   TRACE_DEBUG("  Description = %" PRIu8 "\r\n", message->description);

   //Alert messages convey the severity of the message
   if(message->level == TLS_ALERT_LEVEL_WARNING)
   {
#if (TLS_MAX_WARNING_ALERTS > 0)
      //Increment the count of consecutive warning alerts
      context->alertCount++;

      //Do not allow too many consecutive warning alerts
      if(context->alertCount > TLS_MAX_WARNING_ALERTS)
         return ERROR_UNEXPECTED_MESSAGE;
#endif

      //Check alert type
      if(message->description == TLS_ALERT_CLOSE_NOTIFY)
      {
         //A closure alert has been received
         context->closeNotifyReceived = TRUE;

         //Close down the connection immediately
         if(context->state == TLS_STATE_APPLICATION_DATA)
         {
            context->state = TLS_STATE_CLOSING;
         }
      }
      else if(message->description == TLS_ALERT_USER_CANCELED)
      {
         //This alert notifies the recipient that the sender is canceling the
         //handshake for some reason unrelated to a protocol failure
      }
      else
      {
         //TLS 1.3 currently selected?
         if(context->version == TLS_VERSION_1_3)
         {
            //Unknown alert types must be treated as error alerts
            return ERROR_DECODING_FAILED;
         }
      }
   }
   else if(message->level == TLS_ALERT_LEVEL_FATAL)
   {
      //A fatal alert message has been received
      context->fatalAlertReceived = TRUE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         tlsRemoveFromCache(context);
      }
#endif

      //Servers and clients must forget any session identifiers
      osMemset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      context->state = TLS_STATE_CLOSED;
   }
   else
   {
      //Report an error
      return ERROR_ILLEGAL_PARAMETER;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
