/**
 * @file tls_record_decryption.c
 * @brief TLS record decryption
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
#include "tls_record_decryption.h"
#include "tls_record_encryption.h"
#include "tls_misc.h"
#include "cipher_modes/cbc.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Decrypt an incoming TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

error_t tlsDecryptRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
   error_t error;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      decryptionEngine->cipherMode == CIPHER_MODE_GCM ||
      decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Perform authenticated decryption
      error = tlsDecryptAeadRecord(context, decryptionEngine, record);
   }
   else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
   //CBC block cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //Decrypt record and check message authentication code (constant time)
      error = tlsDecryptCbcRecord(context, decryptionEngine, record);
   }
   else
#endif
#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
   //Stream cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_STREAM)
   {
      //Decrypt the contents of the record
      error = tlsDecryptStreamRecord(context, decryptionEngine, record);

      //Check status code
      if(!error)
      {
         //Verify message authentication code
         error = tlsVerifyMessageAuthCode(context, decryptionEngine, record);
      }
   }
   else
#endif
#if (TLS_NULL_CIPHER_SUPPORT == ENABLED)
   //NULL cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      //Verify message authentication code
      error = tlsVerifyMessageAuthCode(context, decryptionEngine, record);
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
 * @brief Record decryption (AEAD cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

__weak_func error_t tlsDecryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   size_t aadLen;
   size_t nonceLen;
   uint8_t *data;
   uint8_t *ciphertext;
   uint8_t *tag;
   uint8_t aad[13];
   uint8_t nonce[12];

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Make sure the message length is acceptable
   if(length < (decryptionEngine->recordIvLen + decryptionEngine->authTagLen))
      return ERROR_BAD_RECORD_MAC;

   //Calculate the length of the ciphertext
   length -= decryptionEngine->recordIvLen + decryptionEngine->authTagLen;

   //Version of TLS prior to TLS 1.3?
   if(decryptionEngine->version <= TLS_VERSION_1_2)
   {
      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length);
   }
   else
   {
      //The length must not exceed 2^14 octets + 1 octet for ContentType + the
      //maximum AEAD expansion. An endpoint that receives a record that exceeds
      //this length must terminate the connection with a record_overflow alert
      if(length > (TLS_MAX_RECORD_LENGTH + 1))
         return ERROR_RECORD_OVERFLOW;

      //In TLS 1.3, the outer opaque_type field of a TLS record is always set
      //to the value 23 (application data)
      if(tlsGetRecordType(context, record) != TLS_TYPE_APPLICATION_DATA)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //Additional data to be authenticated
   tlsFormatAad(context, decryptionEngine, record, aad, &aadLen);

   //Generate the nonce
   tlsFormatNonce(context, decryptionEngine, record, data, nonce,
      &nonceLen);

   //Point to the ciphertext
   ciphertext = data + decryptionEngine->recordIvLen;
   //Point to the authentication tag
   tag = ciphertext + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CCM)
   {
      //Authenticated decryption using CCM
      error = ccmDecrypt(decryptionEngine->cipherAlgo,
         decryptionEngine->cipherContext, nonce, nonceLen, aad, aadLen,
         ciphertext, ciphertext, length, tag, decryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Authenticated decryption using GCM
      error = gcmDecrypt(decryptionEngine->gcmContext, nonce, nonceLen,
         aad, aadLen, ciphertext, ciphertext, length, tag,
         decryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Authenticated decryption using ChaCha20Poly1305
      error = chacha20Poly1305Decrypt(decryptionEngine->encKey,
         decryptionEngine->encKeyLen, nonce, 12, aad, aadLen, data,
         data, length, tag, decryptionEngine->authTagLen);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Wrong authentication tag?
   if(error)
      return ERROR_BAD_RECORD_MAC;

   //Discard the explicit part of the nonce
   if(decryptionEngine->recordIvLen != 0)
   {
      osMemmove(data, data + decryptionEngine->recordIvLen, length);
   }

   //TLS 1.3 currently selected?
   if(decryptionEngine->version == TLS_VERSION_1_3)
   {
      //Upon successful decryption of an encrypted record, the receiving
      //implementation scans the field from the end toward the beginning
      //until it finds a non-zero octet
      while(length > 0 && data[length - 1] == 0)
      {
         length--;
      }

      //If a receiving implementation does not find a non-zero octet in the
      //cleartext, it must terminate the connection with an unexpected_message
      //alert
      if(length == 0)
         return ERROR_UNEXPECTED_MESSAGE;

      //Retrieve the length of the plaintext
      length--;

      //The actual content type of the record is found in the type field
      tlsSetRecordType(context, record, data[length]);
      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length);
   }

   //Increment sequence number
   tlsIncSequenceNumber(&decryptionEngine->seqNum);

   //Debug message
   TRACE_DEBUG("Decrypted record (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Successful processing
   return NO_ERROR;
#else
   //AEAD ciphers are not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Record decryption (CBC block cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

__weak_func error_t tlsDecryptCbcRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
   error_t error;
   uint32_t bad;
   size_t m;
   size_t n;
   size_t length;
   size_t paddingLen;
   uint8_t *data;
   const CipherAlgo *cipherAlgo;
   const HashAlgo *hashAlgo;
   uint8_t mac[MAX_HASH_DIGEST_SIZE];

   //Point to the cipher algorithm
   cipherAlgo = decryptionEngine->cipherAlgo;
   //Point to the hash algorithm
   hashAlgo = decryptionEngine->hashAlgo;

   //Get the length of the ciphertext
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Calculate the minimum acceptable length of the ciphertext
   n = MAX(cipherAlgo->blockSize, hashAlgo->digestSize + 1);

   //TLS 1.1 and 1.2 use an explicit IV
   if(decryptionEngine->version >= TLS_VERSION_1_1)
   {
      n += decryptionEngine->recordIvLen;
   }

   //Malformed TLS record?
   if(length < n)
      return ERROR_BAD_RECORD_MAC;

   //The length of the ciphertext must be a multiple of the block size
   if((length % cipherAlgo->blockSize) != 0)
      return ERROR_BAD_RECORD_MAC;

   //Perform CBC decryption
   error = cbcDecrypt(cipherAlgo, decryptionEngine->cipherContext,
      decryptionEngine->iv, data, data, length);
   //Any error to report?
   if(error)
      return error;

   //TLS 1.1 and 1.2 use an explicit IV
   if(decryptionEngine->version >= TLS_VERSION_1_1)
   {
      //Adjust the length of the message
      length -= decryptionEngine->recordIvLen;
      //Discard the first cipher block (corresponding to the explicit IV)
      osMemmove(data, data + decryptionEngine->recordIvLen, length);
   }

   //Debug message
   TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //The receiver must check the padding
   bad = tlsVerifyPadding(data, length, &paddingLen);

   //Actual length of the payload
   n = length - paddingLen - 1;
   //Maximum possible length of the payload
   m = length - 1;

   //Extract the MAC from the TLS record
   bad |= tlsExtractMac(decryptionEngine, data, n, m, mac);

   //Fix the length of the padding string if the format of the plaintext
   //is not valid
   paddingLen = CRYPTO_SELECT_32(paddingLen, 0, bad);

   //Actual length of the plaintext data
   n = length - hashAlgo->digestSize - paddingLen - 1;
   //Maximum possible length of the plaintext data
   m = length - hashAlgo->digestSize - 1;

   //Fix the length field of the TLS record
   tlsSetRecordLength(context, record, n);

   //TLS uses a HMAC construction
   bad |= tlsVerifyMac(context, decryptionEngine, record, data, n, m, mac);

   //Increment sequence number
   tlsIncSequenceNumber(&decryptionEngine->seqNum);

   //Return status code
   return bad ? ERROR_BAD_RECORD_MAC : NO_ERROR;
#else
   //CBC cipher mode is not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Record decryption (stream cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

error_t tlsDecryptStreamRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
   size_t length;
   uint8_t *data;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Decrypt record contents
   decryptionEngine->cipherAlgo->decryptStream(decryptionEngine->cipherContext,
      data, data, length);

   //Debug message
   TRACE_DEBUG("Decrypted record (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Successful processing
   return NO_ERROR;
#else
   //Stream ciphers are not supported
   return ERROR_UNSUPPORTED_CIPHER_MODE;
#endif
}


/**
 * @brief Check message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be authenticated
 * @return Error code
 **/

error_t tlsVerifyMessageAuthCode(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
   error_t error;
   size_t i;
   size_t length;
   uint8_t mask;
   uint8_t *data;
   uint8_t *digest;
   const HashAlgo *hashAlgo;

   //Point to the hash algorithm
   hashAlgo = decryptionEngine->hashAlgo;
   //Point to the buffer where to store the calculated HMAC value
   digest = decryptionEngine->hmacContext->digest;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Debug message
   TRACE_DEBUG("Record to be authenticated (%" PRIuSIZE " bytes):\r\n", length);
   TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

   //Make sure the message length is acceptable
   if(length < hashAlgo->digestSize)
      return ERROR_BAD_RECORD_MAC;

   //Adjust the length of the message
   length -= hashAlgo->digestSize;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(decryptionEngine->version >= TLS_VERSION_1_0 &&
      decryptionEngine->version <= TLS_VERSION_1_2)
   {
      //Fix the length field of the record
      tlsSetRecordLength(context, record, length);

      //TLS uses a HMAC construction
      error = tlsComputeMac(context, decryptionEngine, record, data, length,
         digest);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(decryptionEngine->version == TLS_VERSION_1_3)
   {
      //The length must not exceed 2^14 octets + 1 octet for ContentType + the
      //maximum AEAD expansion. An endpoint that receives a record that exceeds
      //this length must terminate the connection with a record_overflow alert
      if(length > (TLS_MAX_RECORD_LENGTH + 1))
         return ERROR_RECORD_OVERFLOW;

      //In TLS 1.3, the outer opaque_type field of a TLS record is always set
      //to the value 23 (application data)
      if(tlsGetRecordType(context, record) != TLS_TYPE_APPLICATION_DATA)
         return ERROR_UNEXPECTED_MESSAGE;

      //The record is protected using HMAC SHA-256 or SHA-384
      error = tls13ComputeMac(context, decryptionEngine, record, data, length,
         digest);
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
   TRACE_DEBUG("Read sequence number:\r\n");
   TRACE_DEBUG_ARRAY("  ", &decryptionEngine->seqNum, sizeof(TlsSequenceNumber));
   TRACE_DEBUG("Computed MAC:\r\n");
   TRACE_DEBUG_ARRAY("  ", digest, hashAlgo->digestSize);

   //The calculated MAC is bitwise compared to the received message
   //authentication code
   for(mask = 0, i = 0; i < hashAlgo->digestSize; i++)
   {
      mask |= data[length + i] ^ digest[i];
   }

   //Invalid message authentication code?
   if(mask != 0)
      return ERROR_BAD_RECORD_MAC;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(decryptionEngine->version == TLS_VERSION_1_3)
   {
      //Upon successful decryption of an encrypted record, the receiving
      //implementation scans the field from the end toward the beginning
      //until it finds a non-zero octet
      while(length > 0 && data[length - 1] == 0)
      {
         length--;
      }

      //If a receiving implementation does not find a non-zero octet in the
      //cleartext, it must terminate the connection with an unexpected_message
      //alert
      if(length == 0)
         return ERROR_UNEXPECTED_MESSAGE;

      //Retrieve the length of the plaintext
      length--;

      //The actual content type of the record is found in the type field
      tlsSetRecordType(context, record, data[length]);
      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length);
   }
#endif

   //Increment sequence number
   tlsIncSequenceNumber(&decryptionEngine->seqNum);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief CBC padding verification (constant time)
 * @param[in] data Pointer to the record payload
 * @param[in] dataLen Length of the payload
 * @param[out] paddingLen Length of the padding string
 * @return The function returns 0 if the padding is correct, 1 on failure
 **/

uint32_t tlsVerifyPadding(const uint8_t *data, size_t dataLen,
   size_t *paddingLen)
{
   size_t i;
   size_t n;
   uint8_t b;
   uint8_t mask;
   uint32_t c;
   uint32_t bad;

   //Retrieve the length of the padding string
   n = data[dataLen - 1];

   //Make sure the padding length is valid
   bad = CRYPTO_TEST_GTE_32(n, dataLen);

   //Each byte in the padding data must be filled with the padding length value
   for(i = 1; i < dataLen && i < 256; i++)
   {
      //Read current byte
      b = data[dataLen - 1 - i];

      //Verify that the padding string is correct
      c = CRYPTO_TEST_LTE_32(i, n);
      mask = CRYPTO_SELECT_8(b, n, c);
      bad |= CRYPTO_TEST_NEQ_8(b, mask);
   }

   //Save the length of the padding string
   *paddingLen = CRYPTO_SELECT_32(n, 0, bad);

   //Return status code
   return bad;
}


/**
 * @brief MAC verification (constant time)
 *
 * Calculate and verify the MAC in constant time without leaking information
 * about what the make-up of the plaintext blocks is in terms of message, MAC
 * field and padding, and whether the format is valid (Adam Langley's method)
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record payload
 * @param[in] dataLen Actual length of the plaintext data (secret information)
 * @param[in] maxDataLen Maximum possible length of the plaintext data
 * @param[in] mac Message authentication code
 * @return The function returns 0 if the MAC verification is successful, else 1
 **/

__weak_func uint32_t tlsVerifyMac(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, const void *record,
   const uint8_t *data, size_t dataLen, size_t maxDataLen, const uint8_t *mac)
{
   size_t i;
   size_t j;
   size_t n;
   size_t headerLen;
   size_t paddingLen;
   size_t blockSizeMask;
   uint8_t b;
   uint32_t c;
   uint64_t bitLen;
   const HashAlgo *hashAlgo;
   HmacContext *hmacContext;
   uint8_t temp[MAX_HASH_DIGEST_SIZE];

   //Point to the hash algorithm to be used
   hashAlgo = decryptionEngine->hashAlgo;
   //Point to the HMAC context
   hmacContext = decryptionEngine->hmacContext;

   //The size of the block depends on the hash algorithm
   blockSizeMask = hashAlgo->blockSize - 1;

   //Calculate the length of the additional data that will be hashed in
   //prior to the application data
   headerLen = hashAlgo->blockSize + sizeof(TlsSequenceNumber) +
      sizeof(TlsRecord);

   //Calculate the length of the padding string
   paddingLen = (headerLen + dataLen + hashAlgo->minPadSize - 1) & blockSizeMask;
   paddingLen = hashAlgo->blockSize - paddingLen;

   //Check whether the length field is larger than 64 bits
   if(hashAlgo->minPadSize > 9)
   {
      //The most significant bytes will be padded with zeroes
      paddingLen += hashAlgo->minPadSize - 9;
   }

   //Length of the message, in bits
   bitLen = (headerLen + dataLen) << 3;

   //Check endianness
   if(hashAlgo->bigEndian)
   {
      //Encode the length field as a big-endian integer
      bitLen = swapInt64(bitLen);
   }

   //Total number of bytes to process
   n = headerLen + maxDataLen + hashAlgo->minPadSize;
   n = (n + hashAlgo->blockSize - 1) & ~blockSizeMask;
   n -= headerLen;

   //Initialize HMAC calculation
   hmacInit(hmacContext, hashAlgo, decryptionEngine->macKey,
      decryptionEngine->macKeyLen);

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
   }
   else
#endif
   //TLS protocol?
   {
      const TlsRecord *tlsRecord;

      //Point to the TLS record
      tlsRecord = (TlsRecord *) record;

      //Compute MAC over the implicit sequence number
      hmacUpdate(hmacContext, &decryptionEngine->seqNum,
         sizeof(TlsSequenceNumber));

      //Compute MAC over the record contents
      hmacUpdate(hmacContext, tlsRecord, sizeof(TlsRecord));
   }

   //If intermediate hash calculation is supported by the hardware accelerator,
   //then compute the MAC in constant time without leaking information
   if(hashAlgo->finalRaw != NULL)
   {
      //Point to the first byte of the plaintext data
      i = 0;

      //We can process the first blocks normally because the (secret) padding
      //length cannot affect them
      if(maxDataLen > 255)
      {
         //Digest the first part of the plaintext data
         hmacUpdate(hmacContext, data, maxDataLen - 255);
         i += maxDataLen - 255;
      }

      //The last blocks need to be handled carefully
      while(i < n)
      {
         //Initialize the value of the current byte
         b = 0;

         //Generate the contents of each block in constant time
         c = CRYPTO_TEST_LT_32(i, dataLen);
         b = CRYPTO_SELECT_8(b, data[i], c);

         c = CRYPTO_TEST_EQ_32(i, dataLen);
         b = CRYPTO_SELECT_8(b, 0x80, c);

         j = dataLen + paddingLen;
         c = CRYPTO_TEST_GTE_32(i, j);
         j += 8;
         c &= CRYPTO_TEST_LT_32(i, j);
         b = CRYPTO_SELECT_8(b, bitLen & 0xFF, c);
         bitLen = CRYPTO_SELECT_64(bitLen, bitLen >> 8, c);

         //Digest the current byte
         hashAlgo->update(&hmacContext->hashContext, &b, sizeof(uint8_t));

         //Increment byte counter
         i++;

         //End of block detected?
         if(((i + headerLen) & blockSizeMask) == 0)
         {
            //For each block we serialize the hash
            hashAlgo->finalRaw(&hmacContext->hashContext, temp);

            //Check whether the current block of data is the final block
            c = CRYPTO_TEST_EQ_32(i, dataLen + paddingLen + 8);

            //The hash is copied with a mask so that only the correct hash value
            //is copied out, but the amount of computation remains constant
            for(j = 0; j < hashAlgo->digestSize; j++)
            {
               hmacContext->digest[j] = CRYPTO_SELECT_8(hmacContext->digest[j],
                  temp[j], c);
            }
         }
      }

      //Finalize HMAC computation
      hmacFinalRaw(hmacContext, temp);
   }
   else
   {
      //Intermediate hash calculation is not supported by the hardware
      //accelerator
      hmacUpdate(hmacContext, data, dataLen);
      hmacFinal(hmacContext, temp);
   }

   //Debug message
   TRACE_DEBUG("Read sequence number:\r\n");
   TRACE_DEBUG_ARRAY("  ", &decryptionEngine->seqNum, sizeof(TlsSequenceNumber));
   TRACE_DEBUG("Computed MAC:\r\n");
   TRACE_DEBUG_ARRAY("  ", temp, hashAlgo->digestSize);

   //The calculated MAC is bitwise compared to the received message
   //authentication code
   for(b = 0, i = 0; i < hashAlgo->digestSize; i++)
   {
      b |= mac[i] ^ temp[i];
   }

   //Return 0 if the message authentication code is correct, else 1
   return CRYPTO_TEST_NEQ_8(b, 0);
}


/**
 * @brief Extract the MAC from the TLS record (constant time)
 *
 * Extract the MAC from the record in constant time without leaking information
 * about what the make-up of the plaintext blocks is in terms of message, MAC
 * field and padding, and whether the format is valid (Emilia Kasper and Bodo
 * Moller's method)
 *
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] data Pointer to the record payload
 * @param[in] dataLen Actual length of the payload (secret information)
 * @param[in] maxDataLen Maximum possible length of the payload
 * @param[out] mac Message authentication code
 * @return The function returns 0 if the MAC has been successfully extracted, else 1
 **/

uint32_t tlsExtractMac(TlsEncryptionEngine *decryptionEngine,
   const uint8_t *data, size_t dataLen, size_t maxDataLen, uint8_t *mac)
{
   bool_t bad;
   uint32_t c;
   size_t i;
   size_t j;
   size_t n;
   size_t offset;
   size_t macSize;
   size_t minDataLen;
   uint8_t temp[MAX_HASH_DIGEST_SIZE];

   //Retrieve the length of the message authentication code
   macSize = decryptionEngine->hashAlgo->digestSize;

   //Calculate the minimum possible length of the plaintext data
   if(maxDataLen > (macSize + 255))
   {
      minDataLen = maxDataLen - macSize - 255;
   }
   else
   {
      minDataLen = 0;
   }

   //Check whether the length of the payload is correct
   bad = CRYPTO_TEST_LT_32(dataLen, macSize);
   //Retrieve the length of the plaintext data
   dataLen = CRYPTO_SELECT_32(dataLen - macSize, 0, bad);

   //Clear MAC value
   osMemset(mac, 0, macSize);
   offset = 0;

   //Read every location where the MAC might be found
   for(i = minDataLen, j = 0; i < maxDataLen; i++)
   {
      //Save the start offset of the MAC in the output buffer
      c = CRYPTO_TEST_EQ_32(i, dataLen);
      offset = CRYPTO_SELECT_32(offset, j, c);

      //The MAC may be byte-wise rotated by this copy
      c = CRYPTO_TEST_GTE_32(i, dataLen);
      c &= CRYPTO_TEST_LT_32(i, dataLen + macSize);
      mac[j] = CRYPTO_SELECT_8(mac[j], data[i], c);

      //Increment index and wrap around if necessary
      if(++j >= macSize)
      {
         j = 0;
      }
   }

   //Debug message
   TRACE_DEBUG("MAC before rotation (offset = %" PRIuSIZE "):\r\n", offset);
   TRACE_DEBUG_ARRAY("  ", mac, macSize);

   //Rotate the MAC in constant-time (since the start offset is also secret)
   for(n = 1; n < macSize; n <<= 1)
   {
      //Check whether the current step should be performed
      c = CRYPTO_TEST_NEQ_32(offset & n, 0);

      //Rotate the MAC value by n bytes to the left
      for(i = 0, j = n; i < macSize; i++)
      {
         //Process current byte
         temp[i] = CRYPTO_SELECT_8(mac[i], mac[j], c);

         //Increment index and wrap around if necessary
         if(++j >= macSize)
         {
            j = 0;
         }
      }

      //Copy the value of the rotated MAC
      osMemcpy(mac, temp, macSize);
   }

   //Debug message
   TRACE_DEBUG("MAC after rotation:\r\n");
   TRACE_DEBUG_ARRAY("  ", mac, macSize);

   //Return 0 if the MAC has been successfully extracted, else 1
   return bad;
}

#endif
