/**
 * @file tls_record.c
 * @brief TLS record protocol
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
#include "tls_record.h"
#include "tls_record_encryption.h"
#include "tls_record_decryption.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Write protocol data
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the data buffer
 * @param[in] length Number of data bytes to be written
 * @param[in] contentType Higher level protocol
 * @return Error code
 **/

error_t tlsWriteProtocolData(TlsContext *context,
   const uint8_t *data, size_t length, TlsContentType contentType)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Initialize status code
   error = NO_ERROR;

   //Fragmentation process
   while(!error)
   {
      if(context->txBufferLen == 0)
      {
         //Check the length of the data
         if(length > context->txBufferMaxLen)
         {
            //Report an error
            error = ERROR_MESSAGE_TOO_LONG;
         }
         else if(length > 0)
         {
            //Make room for the encryption overhead
            osMemmove(context->txBuffer + context->txBufferSize - length, data,
               length);

            //Save record type
            context->txBufferType = contentType;
            //Set the length of the buffer
            context->txBufferLen = length;
            //Point to the beginning of the buffer
            context->txBufferPos = 0;
         }
         else
         {
            //We are done
            break;
         }
      }
      else if(context->txBufferPos < context->txBufferLen)
      {
         //Number of bytes left to send
         n = context->txBufferLen - context->txBufferPos;
         //Point to the current fragment
         p = context->txBuffer + context->txBufferSize - n;

         //The record length must not exceed 16384 bytes
         n = MIN(n, TLS_MAX_RECORD_LENGTH);

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
         //Do not exceed the negotiated maximum fragment length
         n = MIN(n, context->maxFragLen);
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
         //The value of RecordSizeLimit is used to limit the size of records
         //that are created when encoding application data and the protected
         //handshake message into records
         if(context->encryptionEngine.cipherMode != CIPHER_MODE_NULL ||
            context->encryptionEngine.hashAlgo != NULL)
         {
            //An endpoint must not generate a protected record with plaintext
            //that is larger than the RecordSizeLimit value it receives from
            //its peer (refer to RFC 8449, section 4)
            n = MIN(n, context->encryptionEngine.recordSizeLimit);
         }
#endif
         //Send TLS record
         error = tlsWriteRecord(context, p, n, context->txBufferType);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            context->txBufferPos += n;
         }
      }
      else
      {
         //Prepare to send new protocol data
         context->txBufferLen = 0;
         context->txBufferPos = 0;

         //We are done
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Read protocol data
 * @param[in] context Pointer to the TLS context
 * @param[out] data Pointer to the received data
 * @param[out] length Number of data bytes that were received
 * @param[out] contentType Higher level protocol
 * @return Error code
 **/

error_t tlsReadProtocolData(TlsContext *context,
   uint8_t **data, size_t *length, TlsContentType *contentType)
{
   error_t error;
   size_t n;
   TlsContentType type;
   TlsHandshake *message;

   //Initialize status code
   error = NO_ERROR;

   //Fragment reassembly process
   do
   {
      //Empty receive buffer?
      if(context->rxBufferLen == 0)
      {
         //Read a TLS record
         error = tlsReadRecord(context, context->rxBuffer,
            context->rxBufferSize, &n, &type);

         //Check status code
         if(!error)
         {
            //Save record type
            context->rxBufferType = type;
            //Number of bytes available for reading
            context->rxBufferLen = n;
            //Rewind to the beginning of the buffer
            context->rxBufferPos = 0;
         }
      }
      //Imcomplete message received?
      else if(error == ERROR_MORE_DATA_REQUIRED)
      {
         //Make room at the end of the buffer
         if(context->rxBufferPos > 0)
         {
            //Move unread data to the beginning of the buffer
            osMemmove(context->rxBuffer, context->rxBuffer +
               context->rxBufferPos, context->rxBufferLen);

            //Rewind to the beginning of the buffer
            context->rxBufferPos = 0;
         }

         //Read a TLS record
         error = tlsReadRecord(context, context->rxBuffer + context->rxBufferLen,
            context->rxBufferSize - context->rxBufferLen, &n, &type);

         //Check status code
         if(!error)
         {
            //Fragmented records with mixed types cannot be interleaved
            if(type != context->rxBufferType)
               error = ERROR_UNEXPECTED_MESSAGE;
         }

         //Check status code
         if(!error)
         {
            //Number of bytes available for reading
            context->rxBufferLen += n;
         }
      }

      //Check status code
      if(!error)
      {
         //Handshake message received?
         if(context->rxBufferType == TLS_TYPE_HANDSHAKE)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsHandshake))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Point to the handshake message
               message = (TlsHandshake *) (context->rxBuffer + context->rxBufferPos);
               //Retrieve the length of the handshake message
               n = sizeof(TlsHandshake) + LOAD24BE(message->length);

               //A message may be fragmented across several records
               if(context->rxBufferLen < n)
               {
                  //Read an additional record
                  error = ERROR_MORE_DATA_REQUIRED;
               }
               else
               {
                  //Pass the handshake message to the higher layer
                  error = NO_ERROR;
               }
            }
         }
         //ChangeCipherSpec message received?
         else if(context->rxBufferType == TLS_TYPE_CHANGE_CIPHER_SPEC)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsChangeCipherSpec))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Length of the ChangeCipherSpec message
               n = sizeof(TlsChangeCipherSpec);
               //Pass the ChangeCipherSpec message to the higher layer
               error = NO_ERROR;
            }
         }
         //Alert message received?
         else if(context->rxBufferType == TLS_TYPE_ALERT)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsAlert))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Length of the Alert message
               n = sizeof(TlsAlert);
               //Pass the Alert message to the higher layer
               error = NO_ERROR;
            }
         }
         //Application data received?
         else if(context->rxBufferType == TLS_TYPE_APPLICATION_DATA)
         {
            //Length of the application data
            n = context->rxBufferLen;
            //Pass the application data to the higher layer
            error = NO_ERROR;
         }
         //Unknown content type?
         else
         {
            //Report an error
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }

      //Read as many records as necessary to reassemble the data
   } while(error == ERROR_MORE_DATA_REQUIRED);

   //Successful processing?
   if(!error)
   {
#if (TLS_MAX_WARNING_ALERTS > 0)
      //Reset the count of consecutive warning alerts
      if(context->rxBufferType != TLS_TYPE_ALERT)
         context->alertCount = 0;
#endif
#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
      //Reset the count of consecutive KeyUpdate messages
      if(context->rxBufferType != TLS_TYPE_HANDSHAKE)
         context->keyUpdateCount = 0;
#endif

      //Pointer to the received data
      *data = context->rxBuffer + context->rxBufferPos;
      //Length, in byte, of the data
      *length = n;
      //Protocol type
      *contentType = context->rxBufferType;
   }

   //Return status code
   return error;
}


/**
 * @brief Send a TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the record data
 * @param[in] length Length of the record data
 * @param[in] contentType Record type
 * @return Error code
 **/

error_t tlsWriteRecord(TlsContext *context, const uint8_t *data,
   size_t length, TlsContentType contentType)
{
   error_t error;
   size_t n;
   uint16_t legacyVersion;
   TlsRecord *record;
   TlsEncryptionEngine *encryptionEngine;

   //Point to the encryption engine
   encryptionEngine = &context->encryptionEngine;

   //Point to the TLS record
   record = (TlsRecord *) context->txBuffer;

   //Initialize status code
   error = NO_ERROR;

   //Send process
   while(!error)
   {
      //Send as much data as possible
      if(context->txRecordLen == 0)
      {
         //The record version must be set to 0x0303 for all records generated
         //by a TLS 1.3 implementation other than an initial ClientHello
         legacyVersion = MIN(context->version, TLS_VERSION_1_2);

         //Format TLS record
         record->type = contentType;
         record->version = htons(legacyVersion);
         record->length = htons(length);

         //Copy record data
         osMemmove(record->data, data, length);

         //Debug message
         TRACE_DEBUG("Sending TLS record (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

         //Protect record payload?
         if(encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
            encryptionEngine->hashAlgo != NULL)
         {
            //Encrypt TLS record
            error = tlsEncryptRecord(context, encryptionEngine, record);
         }

         //Check status code
         if(!error)
         {
            //Actual length of the record data
            context->txRecordLen = sizeof(TlsRecord) + ntohs(record->length);
            //Point to the beginning of the record
            context->txRecordPos = 0;
         }
      }
      else if(context->txRecordPos < context->txRecordLen)
      {
         //Total number of bytes that have been written
         n = 0;

         //Send more data
         error = context->socketSendCallback(context->socketHandle,
            context->txBuffer + context->txRecordPos,
            context->txRecordLen - context->txRecordPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            context->txRecordPos += n;
         }
         else
         {
            //The write operation has failed
            error = ERROR_WRITE_FAILED;
         }
      }
      else
      {
         //Prepare to send the next TLS record
         context->txRecordLen = 0;
         context->txRecordPos = 0;

         //We are done
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Receive a TLS record
 * @param[in] context Pointer to the TLS context
 * @param[out] data Buffer where to store the record data
 * @param[in] size Maximum acceptable size for the incoming record
 * @param[out] length Length of the record data
 * @param[out] contentType Record type
 * @return Error code
 **/

error_t tlsReadRecord(TlsContext *context, uint8_t *data,
   size_t size, size_t *length, TlsContentType *contentType)
{
   error_t error;
   size_t n;
   TlsRecord *record;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to store the incoming TLS record
   record = (TlsRecord *) data;

   //Receive process
   while(!error)
   {
      //Read as much data as possible
      if(context->rxRecordPos < sizeof(TlsRecord))
      {
         //Make sure that the buffer is large enough to hold the record header
         if(size >= sizeof(TlsRecord))
         {
            //Total number of bytes that have been received
            n = 0;

            //Read TLS record header
            error = context->socketReceiveCallback(context->socketHandle,
               data + context->rxRecordPos,
               sizeof(TlsRecord) - context->rxRecordPos, &n, 0);

            //Check status code
            if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Advance data pointer
               context->rxRecordPos += n;

               //TLS record header successfully received?
               if(context->rxRecordPos >= sizeof(TlsRecord))
               {
                  //Debug message
                  TRACE_DEBUG("Record header received:\r\n");
                  TRACE_DEBUG_ARRAY("  ", record, sizeof(TlsRecord));

                  //Retrieve the length of the TLS record
                  context->rxRecordLen = sizeof(TlsRecord) + ntohs(record->length);
               }
            }
            else
            {
               //The read operation has failed
               error = ERROR_READ_FAILED;
            }
         }
         else
         {
            //Report an error
            error = ERROR_RECORD_OVERFLOW;
         }
      }
      else if(context->rxRecordPos < context->rxRecordLen)
      {
         //Make sure that the buffer is large enough to hold the entire record
         if(size >= context->rxRecordLen)
         {
            //Total number of bytes that have been received
            n = 0;

            //Read TLS record contents
            error = context->socketReceiveCallback(context->socketHandle,
               data + context->rxRecordPos,
               context->rxRecordLen - context->rxRecordPos, &n, 0);

            //Check status code
            if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Advance data pointer
               context->rxRecordPos += n;
            }
            else
            {
               //The read operation has failed
               error = ERROR_READ_FAILED;
            }
         }
         else
         {
            //Report an error
            error = ERROR_RECORD_OVERFLOW;
         }
      }
      else
      {
         //Process the incoming TLS record
         error = tlsProcessRecord(context, record);

         //Check status code
         if(error == NO_ERROR)
         {
            //Actual length of the record data
            *length = ntohs(record->length);
            //Record type
            *contentType = (TlsContentType) record->type;

            //Debug message
            TRACE_DEBUG("TLS record received (%" PRIuSIZE " bytes)...\r\n", *length);
            TRACE_DEBUG_ARRAY("  ", record, *length + sizeof(TlsRecord));

            //Discard record header
            osMemmove(data, record->data, *length);

            //Prepare to receive the next TLS record
            context->rxRecordLen = 0;
            context->rxRecordPos = 0;

            //We are done
            break;
         }
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         else if(error == ERROR_BAD_RECORD_MAC)
         {
            //Check current state
            if(context->version == TLS_VERSION_1_3 &&
               context->entity == TLS_CONNECTION_END_SERVER &&
               context->state == TLS_STATE_CLIENT_FINISHED &&
               context->rxBufferLen == 0)
            {
               //Early data received?
               if(!context->updatedClientHelloReceived &&
                  context->earlyDataExtReceived)
               {
                  //Amount of 0-RTT data received by the server
                  context->earlyDataLen += ntohs(record->length);

                  //Discard records which fail deprotection (up to the configured
                  //max_early_data_size)
                  if(context->earlyDataLen <= context->maxEarlyDataSize)
                  {
                     //Debug message
                     TRACE_INFO("Discarding early data (%" PRIu16 " bytes)...\r\n",
                        ntohs(record->length));

                     //Prepare to receive the next TLS record
                     context->rxRecordLen = 0;
                     context->rxRecordPos = 0;

                     //Catch exception
                     error = NO_ERROR;
                  }
               }
            }
         }
#endif
         else
         {
            //Invalid record received
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the received TLS record
 * @return Error code
 **/

error_t tlsProcessRecord(TlsContext *context, TlsRecord *record)
{
   error_t error;
   TlsEncryptionEngine *decryptionEngine;

   //Point to the decryption engine
   decryptionEngine = &context->decryptionEngine;

   //Check current state
   if(context->state > TLS_STATE_SERVER_HELLO)
   {
      //Once the server has sent the ServerHello message, enforce the version
      //of incoming records. In TLS 1.3, this field is deprecated. It may be
      //validated to match the fixed constant value 0x0303
      if(ntohs(record->version) != MIN(context->version, TLS_VERSION_1_2))
         return ERROR_VERSION_NOT_SUPPORTED;
   }
   else
   {
      //Compliant servers must accept any value {03,XX} as the record layer
      //version number for ClientHello
      if(LSB(record->version) != MSB(TLS_VERSION_1_0))
         return ERROR_VERSION_NOT_SUPPORTED;
   }

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check whether the record payload is protected
      if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
         decryptionEngine->hashAlgo != NULL)
      {
         //Decrypt TLS record
         error = tlsDecryptRecord(context, decryptionEngine, record);
         //Any error to report?
         if(error)
            return error;
      }
   }
   else
   {
      //An implementation may receive an unencrypted ChangeCipherSpec at a point
      //at the handshake where the implementation is expecting protected records
      //and so it is necessary to detect this condition prior to attempting to
      //deprotect the record
      if(record->type != TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
#if (TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES > 0)
         //Reset the count of consecutive ChangeCipherSpec messages
         context->changeCipherSpecCount = 0;
#endif
         //Check whether the record payload is protected
         if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
            decryptionEngine->hashAlgo != NULL)
         {
            //Decrypt TLS record
            error = tlsDecryptRecord(context, decryptionEngine, record);
            //Any error to report?
            if(error)
               return error;
         }

         //Abort the handshake with an unexpected_message alert if a protected
         //ChangeCipherSpec record was received
         if(record->type == TLS_TYPE_CHANGE_CIPHER_SPEC)
            return ERROR_UNEXPECTED_MESSAGE;
      }

      //Implementations must not send Handshake and Alert records that have a
      //zero-length plaintext content (refer to RFC 8446, section 5.4)
      if(record->type == TLS_TYPE_HANDSHAKE ||
         record->type == TLS_TYPE_ALERT)
      {
         //If such a message is received, the receiving implementation must
         //terminate the connection with an unexpected_message alert
         if(ntohs(record->length) == 0)
            return ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //The length of the plaintext record must not exceed 2^14 bytes
   if(ntohs(record->length) > TLS_MAX_RECORD_LENGTH)
      return ERROR_RECORD_OVERFLOW;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //Check whether the RecordSizeLimit extension has been negotiated
   if(context->recordSizeLimitExtReceived)
   {
      //The value of RecordSizeLimit is used to limit the size of records
      //that are created when encoding application data and the protected
      //handshake message into records
      if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
         decryptionEngine->hashAlgo != NULL)
      {
         //A TLS endpoint that receives a record larger than its advertised
         //limit must generate a fatal record_overflow alert
         if(ntohs(record->length) > decryptionEngine->recordSizeLimit)
            return ERROR_RECORD_OVERFLOW;
      }
   }
#endif

#if (TLS_MAX_EMPTY_RECORDS > 0)
   //Empty record received?
   if(ntohs(record->length) == 0)
   {
      //Increment the count of consecutive empty records
      context->emptyRecordCount++;

      //Do not allow too many consecutive empty records
      if(context->emptyRecordCount > TLS_MAX_EMPTY_RECORDS)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Reset the count of consecutive empty records
      context->emptyRecordCount = 0;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set TLS record type
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @param[in] type Record type
 **/

void tlsSetRecordType(TlsContext *context, void *record, uint8_t type)
{
#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Set the type of the DTLS record
      ((DtlsRecord *) record)->type = type;
   }
   else
#endif
   //TLS protocol?
   {
      //Set the type of the DTLS record
      ((TlsRecord *) record)->type = type;
   }
}


/**
 * @brief Get TLS record type
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @return Record type
 **/

uint8_t tlsGetRecordType(TlsContext *context, void *record)
{
   uint8_t type;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Get the type of the DTLS record
      type = ((DtlsRecord *) record)->type;
   }
   else
#endif
   //TLS protocol?
   {
      //Get the type of the TLS record
      type = ((TlsRecord *) record)->type;
   }

   //Return the content type of the record
   return type;
}


/**
 * @brief Set TLS record length
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @param[in] length Record length
 **/

void tlsSetRecordLength(TlsContext *context, void *record, size_t length)
{
#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Set the length of the DTLS record
      ((DtlsRecord *) record)->length = htons(length);
   }
   else
#endif
   //TLS protocol?
   {
      //Set the length of the DTLS record
      ((TlsRecord *) record)->length = htons(length);
   }
}


/**
 * @brief Get TLS record length
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @return Record length
 **/

size_t tlsGetRecordLength(TlsContext *context, void *record)
{
   size_t length;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Get the length of the DTLS record
      length = ((DtlsRecord *) record)->length;
   }
   else
#endif
   //TLS protocol?
   {
      //Get the length of the TLS record
      length = ((TlsRecord *) record)->length;
   }

   //Convert the length field to host byte order
   return htons(length);
}


/**
 * @brief Get TLS record payload
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @return Pointer to the first byte of the payload
 **/

uint8_t *tlsGetRecordData(TlsContext *context, void *record)
{
   uint8_t *data;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Point to the payload of the DTLS record
      data = ((DtlsRecord *) record)->data;
   }
   else
#endif
   //TLS protocol?
   {
      //Point to the payload of the TLS record
      data = ((TlsRecord *) record)->data;
   }

   //Return a pointer to the first byte of the payload
   return data;
}


/**
 * @brief Format additional authenticated data (AAD)
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] record Pointer to the TLS record
 * @param[out] aad Pointer to the buffer where to store the resulting AAD
 * @param[out] aadLen Length of the AAD, in bytes
 **/

void tlsFormatAad(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   const void *record, uint8_t *aad, size_t *aadLen)
{
#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      const DtlsRecord *dtlsRecord;

      //Point to the DTLS record
      dtlsRecord = (DtlsRecord *) record;

      //Additional data to be authenticated
      osMemcpy(aad, (void *) &dtlsRecord->epoch, 2);
      osMemcpy(aad + 2, &dtlsRecord->seqNum, 6);
      osMemcpy(aad + 8, &dtlsRecord->type, 3);
      osMemcpy(aad + 11, (void *) &dtlsRecord->length, 2);

      //Length of the additional data, in bytes
      *aadLen = 13;
   }
   else
#endif
   //TLS protocol?
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Additional data to be authenticated
         osMemcpy(aad, &encryptionEngine->seqNum, 8);
         osMemcpy(aad + 8, record, 5);

         //Length of the additional data, in bytes
         *aadLen = 13;
      }
      else
      {
         //The additional data input is the record header (refer to RFC 8446,
         //section 5.2)
         osMemcpy(aad, record, 5);

         //Length of the additional data, in bytes
         *aadLen = 5;
      }
   }
}


/**
 * @brief Format nonce
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] recordIv Explicit part of the nonce
 * @param[out] nonce Pointer to the buffer where to store the resulting nonce
 * @param[out] nonceLen Length of the nonce, in bytes
 **/

void tlsFormatNonce(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   const void *record, const uint8_t *recordIv, uint8_t *nonce, size_t *nonceLen)
{
   size_t i;
   size_t n;

   //Check the length of the nonce explicit part
   if(encryptionEngine->recordIvLen != 0)
   {
      //Calculate the total length of the nonce
      n = encryptionEngine->fixedIvLen + encryptionEngine->recordIvLen;

      //The salt is the implicit part of the nonce and is not sent in the packet
      osMemcpy(nonce, encryptionEngine->iv, encryptionEngine->fixedIvLen);

      //The explicit part of the nonce is chosen by the sender
      osMemcpy(nonce + encryptionEngine->fixedIvLen, recordIv,
         encryptionEngine->recordIvLen);
   }
   else
   {
      //Calculate the total length of the nonce
      n = encryptionEngine->fixedIvLen;

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         const DtlsRecord *dtlsRecord;

         //Point to the DTLS record
         dtlsRecord = (DtlsRecord *) record;

         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value
         osMemcpy(nonce + n - 8, (void *) &dtlsRecord->epoch, 2);
         osMemcpy(nonce + n - 6, &dtlsRecord->seqNum, 6);
      }
      else
#endif
      //TLS protocol?
      {
         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value
         osMemcpy(nonce + n - 8, &encryptionEngine->seqNum, 8);
      }

      //The 64-bit record sequence number is padded on the left by zeros
      osMemset(nonce, 0, n - 8);

      //The padded sequence number is XORed with the IV to form the nonce
      for(i = 0; i < n; i++)
      {
         nonce[i] ^= encryptionEngine->iv[i];
      }
   }

   //Return the total length of the nonce
   *nonceLen = n;
}


/**
 * @brief Increment sequence number
 * @param[in,out] seqNum Pointer to the 64-bit sequence number
 **/

void tlsIncSequenceNumber(TlsSequenceNumber *seqNum)
{
   uint16_t temp;

   //Sequence numbers are stored MSB first
   temp = seqNum->b[7] + 1;
   seqNum->b[7] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[6];
   seqNum->b[6] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[5];
   seqNum->b[5] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[4];
   seqNum->b[4] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[3];
   seqNum->b[3] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[2];
   seqNum->b[2] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[1];
   seqNum->b[1] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[0];
   seqNum->b[0] = temp & 0xFF;
}

#endif
