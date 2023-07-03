/**
 * @file tls_record_encryption.c
 * @brief TLS record encryption
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
#include "tls_misc.h"
#include "cipher_modes/cbc.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Encrypt an outgoing TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

error_t tlsEncryptRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
   error_t error;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Perform authenticated encryption
      error = tlsEncryptAeadRecord(context, encryptionEngine, record);
   }
   else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
   //CBC block cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //Compute message authentication code
      error = tlsAppendMessageAuthCode(context, encryptionEngine, record);

      //Check status code
      if(!error)
      {
         //Encrypt the contents of the record
         error = tlsEncryptCbcRecord(context, encryptionEngine, record);
      }
   }
   else
#endif
#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
   //Stream cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM)
   {
      //Compute message authentication code
      error = tlsAppendMessageAuthCode(context, encryptionEngine, record);

      //Check status code
      if(!error)
      {
         //Encrypt the contents of the record
         error = tlsEncryptStreamRecord(context, encryptionEngine, record);
      }
   }
   else
#endif
#if (TLS_NULL_CIPHER_SUPPORT == ENABLED)
   //NULL cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      //Compute message authentication code
      error = tlsAppendMessageAuthCode(context, encryptionEngine, record);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Return status code
   return error;
}


/**
 * @brief Record encryption (AEAD cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

__weak_func error_t tlsEncryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   size_t aadLen;
   size_t nonceLen;
   uint8_t *data;
   uint8_t *tag;
   uint8_t aad[13];
   uint8_t nonce[12];

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //TLS 1.3 currently selected?
   if(encryptionEngine->version == TLS_VERSION_1_3)
   {
      //The type field indicates the higher-level protocol used to process the
      //enclosed fragment
      data[length++] = tlsGetRecordType(context, record);

      //In TLS 1.3, the outer opaque_type field of a TLS record is always set
      //to the value 23 (application data)
      tlsSetRecordType(context, record, TLS_TYPE_APPLICATION_DATA);

      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length +
         encryptionEngine->authTagLen);
   }

   //Additional data to be authenticated
   tlsFormatAad(context, encryptionEngine, record, aad, &aadLen);

   //Check the length of the nonce explicit part
   if(encryptionEngine->recordIvLen != 0)
   {
      //Make room for the explicit nonce at the beginning of the record
      osMemmove(data + encryptionEngine->recordIvLen, data, length);

      //The explicit part of the nonce is chosen by the sender and is
      //carried in each TLS record
      error = context->prngAlgo->read(context->prngContext, data,
         encryptionEngine->recordIvLen);
      //Any error to report?
      if(error)
         return error;
   }

   //Generate the nonce
   tlsFormatNonce(context, encryptionEngine, record, data, nonce,
      &nonceLen);

   //Point to the plaintext
   data += encryptionEngine->recordIvLen;
   //Point to the buffer where to store the authentication tag
   tag = data + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM)
   {
      //Authenticated encryption using CCM
      error = ccmEncrypt(encryptionEngine->cipherAlgo,
         encryptionEngine->cipherContext, nonce, nonceLen, aad, aadLen,
         data, data, length, tag, encryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Authenticated encryption using GCM
      error = gcmEncrypt(encryptionEngine->gcmContext, nonce, nonceLen,
         aad, aadLen, data, data, length, tag, encryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Authenticated encryption using ChaCha20Poly1305
      error = chacha20Poly1305Encrypt(encryptionEngine->encKey,
         encryptionEngine->encKeyLen, nonce, nonceLen, aad, aadLen,
         data, data, length, tag, encryptionEngine->authTagLen);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Failed to encrypt data?
   if(error)
      return error;

   //Compute the length of the resulting message
   length += encryptionEngine->recordIvLen + encryptionEngine->authTagLen;
   //Fix length field
   tlsSetRecordLength(context, record, length);

   //Increment sequence number
   tlsIncSequenceNumber(&encryptionEngine->seqNum);

   //Debug message
   TRACE_DEBUG("Encrypted record (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Successful processing
   return NO_ERROR;
#else
   //AEAD ciphers are not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Record encryption (CBC block cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

__weak_func error_t tlsEncryptCbcRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t length;
   size_t paddingLen;
   uint8_t *data;
   const CipherAlgo *cipherAlgo;

   //Point to the cipher algorithm
   cipherAlgo = encryptionEngine->cipherAlgo;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_MAX_VERSION >= TLS_VERSION_1_1 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.1 and 1.2 use an explicit IV
   if(encryptionEngine->version >= TLS_VERSION_1_1)
   {
      //Make room for the IV at the beginning of the data
      osMemmove(data + encryptionEngine->recordIvLen, data, length);

      //The initialization vector should be chosen at random
      error = context->prngAlgo->read(context->prngContext, data,
         encryptionEngine->recordIvLen);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the message
      length += encryptionEngine->recordIvLen;
   }
#endif

   //Get the actual amount of bytes in the last block
   paddingLen = (length + 1) % cipherAlgo->blockSize;

   //Padding is added to force the length of the plaintext to be an integral
   //multiple of the cipher's block length
   if(paddingLen > 0)
   {
      paddingLen = cipherAlgo->blockSize - paddingLen;
   }

   //Write padding bytes
   for(i = 0; i <= paddingLen; i++)
   {
      data[length + i] = (uint8_t) paddingLen;
   }

   //Compute the length of the resulting message
   length += paddingLen + 1;
   //Fix length field
   tlsSetRecordLength(context, record, length);

   //Debug message
   TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //CBC encryption
   error = cbcEncrypt(cipherAlgo, encryptionEngine->cipherContext,
      encryptionEngine->iv, data, data, length);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Encrypted record (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Successful processing
   return NO_ERROR;
#else
   //CBC cipher mode is not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Record encryption (stream cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

error_t tlsEncryptStreamRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
   size_t length;
   uint8_t *data;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Encrypt record contents
   encryptionEngine->cipherAlgo->encryptStream(
      encryptionEngine->cipherContext, data, data, length);

   //Debug message
   TRACE_DEBUG("Encrypted record (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Successful processing
   return NO_ERROR;
#else
   //Stream ciphers are not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Append message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be authenticated
 * @return Error code
 **/

error_t tlsAppendMessageAuthCode(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
   error_t error;
   size_t length;
   uint8_t *data;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(encryptionEngine->version >= TLS_VERSION_1_0 &&
      encryptionEngine->version <= TLS_VERSION_1_2)
   {
      //TLS uses a HMAC construction
      error = tlsComputeMac(context, encryptionEngine, record, data,
         length, data + length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(encryptionEngine->version == TLS_VERSION_1_3)
   {
      //The type field indicates the higher-level protocol used to process the
      //enclosed fragment
      data[length++] = tlsGetRecordType(context, record);

      //In TLS 1.3, the outer opaque_type field of a TLS record is always set
      //to the value 23 (application data)
      tlsSetRecordType(context, record, TLS_TYPE_APPLICATION_DATA);

      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length +
         encryptionEngine->hashAlgo->digestSize);

      //The record is protected using HMAC SHA-256 or SHA-384
      error = tls13ComputeMac(context, encryptionEngine, record, data,
         length, data + length);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Write sequence number:\r\n");
   TRACE_DEBUG_ARRAY("  ", &encryptionEngine->seqNum, sizeof(TlsSequenceNumber));
   TRACE_DEBUG("Computed MAC:\r\n");
   TRACE_DEBUG_ARRAY("  ", data + length, encryptionEngine->hashAlgo->digestSize);

   //Adjust the length of the message
   length += encryptionEngine->hashAlgo->digestSize;
   //Fix length field
   tlsSetRecordLength(context, record, length);

   //Increment sequence number
   tlsIncSequenceNumber(&encryptionEngine->seqNum);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record data
 * @param[in] dataLen Length of the data
 * @param[out] mac The computed MAC value
 * @return Error code
 **/

__weak_func error_t tlsComputeMac(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, const void *record,
   const uint8_t *data, size_t dataLen, uint8_t *mac)
{
   HmacContext *hmacContext;

   //Point to the HMAC context
   hmacContext = encryptionEngine->hmacContext;

   //Initialize HMAC calculation
   hmacInit(hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->macKey, encryptionEngine->macKeyLen);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      const DtlsRecord *dtlsRecord;

      //Point to the DTLS record
      dtlsRecord = (DtlsRecord *) record;

      //Compute the MAC over the 64-bit value formed by concatenating the
      //epoch and the sequence number in the order they appear on the wire
      hmacUpdate(hmacContext, (void *) &dtlsRecord->epoch, 2);
      hmacUpdate(hmacContext, &dtlsRecord->seqNum, 6);

      //Compute MAC over the record contents
      hmacUpdate(hmacContext, &dtlsRecord->type, 3);
      hmacUpdate(hmacContext, (void *) &dtlsRecord->length, 2);
      hmacUpdate(hmacContext, data, dataLen);
   }
   else
#endif
   //TLS protocol?
   {
      const TlsRecord *tlsRecord;

      //Point to the TLS record
      tlsRecord = (TlsRecord *) record;

      //Compute MAC over the implicit sequence number
      hmacUpdate(hmacContext, &encryptionEngine->seqNum,
         sizeof(TlsSequenceNumber));

      //Compute MAC over the record contents
      hmacUpdate(hmacContext, tlsRecord, sizeof(TlsRecord));
      hmacUpdate(hmacContext, data, dataLen);
   }

   //Finalize HMAC computation
   hmacFinal(hmacContext, mac);

   //Successful processing
   return NO_ERROR;
}

#endif
