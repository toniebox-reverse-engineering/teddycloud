/**
 * @file tls13_misc.c
 * @brief TLS 1.3 helper functions
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
#include "tls_extensions.h"
#include "tls_certificate.h"
#include "tls_signature.h"
#include "tls_transcript_hash.h"
#include "tls_ffdhe.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "tls13_misc.h"
#include "kdf/hkdf.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)

//Downgrade protection mechanism (TLS 1.1 or below)
const uint8_t tls11DowngradeRandom[8] =
{
   0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

//Downgrade protection mechanism (TLS 1.2)
const uint8_t tls12DowngradeRandom[8] =
{
   0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

//Special random value for HelloRetryRequest message
const uint8_t tls13HelloRetryRequestRandom[32] =
{
   0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
   0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
   0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
   0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};


/**
 * @brief Compute PSK binder value
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] truncatedClientHelloLen Length of the partial ClientHello message
 * @param[in] identity Pointer to the PSK identity
 * @param[out] binder Buffer where to store the resulting PSK binder
 * @param[in] binderLen Expected length of the PSK binder
 * @return Error code
 **/

error_t tls13ComputePskBinder(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, size_t truncatedClientHelloLen,
   const Tls13PskIdentity *identity, uint8_t *binder, size_t binderLen)
{
   error_t error;
   const HashAlgo *hash;
   uint8_t *hashContext;
   uint8_t key[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t digest[TLS_MAX_HKDF_DIGEST_SIZE];

   //Check parameters
   if(truncatedClientHelloLen >= clientHelloLen)
      return ERROR_INVALID_PARAMETER;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Check the length of the PSK binder
   if(binderLen != hash->digestSize)
      return ERROR_INVALID_LENGTH;

   //Allocate a memory buffer to hold the hash context
   hashContext = tlsAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Intialize transcript hash
   if(context->transcriptHashContext != NULL)
   {
      osMemcpy(hashContext, context->transcriptHashContext, hash->contextSize);
   }
   else
   {
      hash->init(hashContext);
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsHandshake header;

      //Handshake message type
      header.msgType = TLS_TYPE_CLIENT_HELLO;
      //Number of bytes in the message
      STORE24BE(clientHelloLen, header.length);
      //Message sequence number
      header.msgSeq = htons(context->txMsgSeq);
      //Fragment offset
      STORE24BE(0, header.fragOffset);
      //Fragment length
      STORE24BE(clientHelloLen, header.fragLength);

      //Digest the handshake message header
      hash->update(hashContext, &header, sizeof(DtlsHandshake));
   }
   else
#endif
   //TLS protocol?
   {
      TlsHandshake header;

      //Handshake message type
      header.msgType = TLS_TYPE_CLIENT_HELLO;
      //Number of bytes in the message
      STORE24BE(clientHelloLen, header.length);

      //Digest the handshake message header
      hash->update(hashContext, &header, sizeof(TlsHandshake));
   }

   //Digest the partial ClientHello
   hash->update(hashContext, clientHello, truncatedClientHelloLen);
   //Calculate transcript hash
   hash->final(hashContext, digest);

   //Release previously allocated memory
   tlsFreeMem(hashContext);

   //Debug message
   TRACE_DEBUG("Transcript hash (partial ClientHello):\r\n");
   TRACE_DEBUG_ARRAY("  ", digest, hash->digestSize);

   //Although PSKs can be established out of band, PSKs can also be established
   //in a previous connection
   if(tls13IsPskValid(context))
   {
      //Calculate early secret
      error = hkdfExtract(hash, context->psk, context->pskLen, NULL, 0,
         context->secret);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("Early secret:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

      //Calculate binder key
      error = tls13DeriveSecret(context, context->secret, hash->digestSize,
         "ext binder", "", 0, key, hash->digestSize);
      //Any error to report?
      if(error)
         return error;
   }
   else if(tls13IsTicketValid(context))
   {
      //Calculate early secret
      error = hkdfExtract(hash, context->ticketPsk, context->ticketPskLen,
         NULL, 0, context->secret);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("Early secret:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

      //Calculate binder key
      error = tls13DeriveSecret(context, context->secret, hash->digestSize,
         "res binder", "", 0, key, hash->digestSize);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //The pre-shared key is not valid
      return ERROR_FAILURE;
   }

   //Debug message
   TRACE_DEBUG("Binder key:\r\n");
   TRACE_DEBUG_ARRAY("  ", key, hash->digestSize);

   //The PskBinderEntry is computed in the same way as the Finished message
   //but with the base key being the binder key
   error = tls13HkdfExpandLabel(context->transportProtocol, hash, key,
      hash->digestSize, "finished", NULL, 0, key, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Finished key:\r\n");
   TRACE_DEBUG_ARRAY("  ", key, hash->digestSize);

   //Compute PSK binder
   error = hmacCompute(hash, key, hash->digestSize, digest, hash->digestSize,
      binder);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("PSK binder:\r\n");
   TRACE_DEBUG_ARRAY("  ", binder, binderLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Key share generation
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return Error code
 **/

error_t tls13GenerateKeyShare(TlsContext *context, uint16_t namedGroup)
{
   error_t error;

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(tls13IsEcdheGroupSupported(context, namedGroup))
   {
      const EcCurveInfo *curveInfo;

      //Retrieve the elliptic curve to be used
      curveInfo = tlsGetCurveInfo(context, namedGroup);

      //Valid elliptic curve?
      if(curveInfo != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params, curveInfo);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = ecdhGenerateKeyPair(&context->ecdhContext, context->prngAlgo,
               context->prngContext);
         }
      }
      else
      {
         //Unsupported elliptic curve
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
   //Finite field group?
   if(tls13IsFfdheGroupSupported(context, namedGroup))
   {
#if (TLS_FFDHE_SUPPORT == ENABLED)
      const TlsFfdheGroup *ffdheGroup;

      //Get the FFDHE parameters that match the specified named group
      ffdheGroup = tlsGetFfdheGroup(context, namedGroup);

      //Valid FFDHE group?
      if(ffdheGroup != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Load FFDHE parameters
         error = tlsLoadFfdheParameters(&context->dhContext.params, ffdheGroup);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = dhGenerateKeyPair(&context->dhContext, context->prngAlgo,
               context->prngContext);
         }
      }
      else
#endif
      {
         //The specified FFDHE group is not supported
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   //Unknown group?
   {
      //Report an error
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief (EC)DHE shared secret generation
 * @param[in] context Pointer to the TLS context
 * @param[in] keyShare Pointer to the peer's (EC)DHE parameters
 * @param[in] length Length of the (EC)DHE parameters, in bytes
 * @return Error code
 **/

error_t tls13GenerateSharedSecret(TlsContext *context, const uint8_t *keyShare,
   size_t length)
{
   error_t error;

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(tls13IsEcdheGroupSupported(context, context->namedGroup))
   {
      //Read peer's public key (refer to RFC 8446, section 4.2.8.2)
      error = ecImport(&context->ecdhContext.params,
         &context->ecdhContext.qb.q, keyShare, length);

      //Check status code
      if(!error)
      {
         //Verify peer's public key
         error = ecdhCheckPublicKey(&context->ecdhContext.params,
            &context->ecdhContext.qb.q);
      }

      //Check status code
      if(!error)
      {
         //ECDH shared secret calculation is performed according to IEEE Std
         //1363-2000 (refer to RFC 8446, section 7.4.2)
         error = ecdhComputeSharedSecret(&context->ecdhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }
   }
   else
#endif
#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
   //Finite field group?
   if(tls13IsFfdheGroupSupported(context, context->namedGroup))
   {
#if (TLS_FFDHE_SUPPORT == ENABLED)
      size_t n;

      //Retrieve the length of the modulus
      n = mpiGetByteLength(&context->dhContext.params.p);

      //For a given Diffie-Hellman group, the padding results in all public
      //keys having the same length (refer to RFC 8446, section 4.2.8.1)
      if(length == n)
      {
         //The Diffie-Hellman public value is encoded as a big-endian integer
         error = mpiImport(&context->dhContext.yb, keyShare, length,
            MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Verify peer's public key
            error = dhCheckPublicKey(&context->dhContext.params,
               &context->dhContext.yb);
         }

         //Check status code
         if(!error)
         {
            //The negotiated key (Z) is converted to a byte string by encoding
            //in big-endian and left padded with zeros up to the size of the
            //prime (refer to RFC 8446, section 7.4.1)
            error = dhComputeSharedSecret(&context->dhContext,
               context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
               &context->premasterSecretLen);
         }
      }
      else
      {
         //The length of the public key is not valid
         error = ERROR_ILLEGAL_PARAMETER;
      }
#else
      //The specified FFDHE group is not supported
      error = ERROR_HANDSHAKE_FAILED;
#endif
   }
   else
#endif
   //Unknown group?
   {
      //Report an error
      error = ERROR_HANDSHAKE_FAILED;
   }

   //Return status code
   return error;
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

error_t tls13ComputeMac(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   void *record, const uint8_t *data, size_t dataLen, uint8_t *mac)
{
   size_t aadLen;
   size_t nonceLen;
   uint8_t aad[13];
   uint8_t nonce[12];
   HmacContext *hmacContext;

   //Point to the HMAC context
   hmacContext = encryptionEngine->hmacContext;

   //Initialize HMAC calculation
   hmacInit(hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->encKey, encryptionEngine->encKeyLen);

   //Additional data to be authenticated
   tlsFormatAad(context, encryptionEngine, record, aad, &aadLen);

   //Generate the nonce
   tlsFormatNonce(context, encryptionEngine, record, data, nonce,
      &nonceLen);

   //Compute HMAC(write_key, nonce || additional_data || plaintext)
   hmacUpdate(hmacContext, nonce, nonceLen);
   hmacUpdate(hmacContext, aad, aadLen);
   hmacUpdate(hmacContext, data, dataLen);

   //Finalize HMAC computation
   hmacFinal(hmacContext, mac);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Hash ClientHello1 in the transcript when HelloRetryRequest is used
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13DigestClientHello1(TlsContext *context)
{
   TlsHandshake *message;
   const HashAlgo *hash;

   //Invalid hash context?
   if(context->transcriptHashContext == NULL)
      return ERROR_FAILURE;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Point to the buffer where to format the handshake message
   message = (TlsHandshake *) context->txBuffer;

   //Handshake message type
   message->msgType = TLS_TYPE_MESSAGE_HASH;
   //Number of bytes in the message
   STORE24BE(hash->digestSize, message->length);

   //Compute Hash(ClientHello1)
   hash->final(context->transcriptHashContext, message->data);
   //Re-initialize hash algorithm context
   hash->init(context->transcriptHashContext);

   //When the server responds to a ClientHello with a HelloRetryRequest, the
   //value of ClientHello1 is replaced with a special synthetic handshake
   //message of handshake type MessageHash containing Hash(ClientHello1)
   hash->update(context->transcriptHashContext, message,
      hash->digestSize + sizeof(TlsHandshake));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether an externally established PSK is valid
 * @param[in] context Pointer to the TLS context
 * @return TRUE is the PSK is valid, else FALSE
 **/

bool_t tls13IsPskValid(TlsContext *context)
{
   bool_t valid = FALSE;

   //Make sure the hash algorithm associated with the PSK is valid
   if(tlsGetHashAlgo(context->pskHashAlgo) != NULL)
   {
      //Valid PSK?
      if(context->psk != NULL && context->pskLen > 0)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Valid PSK identity?
            if(context->pskIdentity != NULL)
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

   //Return TRUE is the PSK is valid, else FALSE
   return valid;
}


/**
 * @brief Check whether a given named group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the named group is supported, else FALSE
 **/

bool_t tls13IsGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

   //Check whether the ECDHE of FFDHE group is supported
   if(tls13IsEcdheGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else if(tls13IsFfdheGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else
   {
      acceptable = FALSE;
   }

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given ECDHE group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the ECDHE group is supported, else FALSE
 **/

bool_t tls13IsEcdheGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(namedGroup == TLS_GROUP_SECP256R1 ||
      namedGroup == TLS_GROUP_SECP384R1 ||
      namedGroup == TLS_GROUP_SECP521R1 ||
      namedGroup == TLS_GROUP_ECDH_X25519 ||
      namedGroup == TLS_GROUP_ECDH_X448 ||
      namedGroup == TLS_GROUP_BRAINPOOLP256R1_TLS13 ||
      namedGroup == TLS_GROUP_BRAINPOOLP384R1_TLS13 ||
      namedGroup == TLS_GROUP_BRAINPOOLP512R1_TLS13)
   {
      //Check whether the ECDHE group is supported
      if(tlsGetCurveInfo(context, namedGroup) != NULL)
      {
         acceptable = TRUE;
      }
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given FFDHE group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the FFDHE group is supported, else FALSE
 **/

bool_t tls13IsFfdheGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
   //Finite field group?
   if(namedGroup == TLS_GROUP_FFDHE2048 ||
      namedGroup == TLS_GROUP_FFDHE3072 ||
      namedGroup == TLS_GROUP_FFDHE4096 ||
      namedGroup == TLS_GROUP_FFDHE6144 ||
      namedGroup == TLS_GROUP_FFDHE8192)
   {
#if (TLS_FFDHE_SUPPORT == ENABLED)
      //Check whether the FFDHE group is supported
      if(tlsGetFfdheGroup(context, namedGroup) != NULL)
      {
         acceptable = TRUE;
      }
#endif
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether the specified key share group is a duplicate
 * @param[in] namedGroup Named group
 * @param[in] p List of key share entries
 * @param[in] length Length of the list, in bytes
 * @return Error code
 **/

error_t tls13CheckDuplicateKeyShare(uint16_t namedGroup, const uint8_t *p,
   size_t length)
{
   size_t n;
   const Tls13KeyShareEntry *keyShareEntry;

   //Parse the list of key share entries offered by the peer
   while(length > 0)
   {
      //Malformed extension?
      if(length < sizeof(Tls13KeyShareEntry))
         return ERROR_DECODING_FAILED;

      //Point to the current key share entry
      keyShareEntry = (Tls13KeyShareEntry *) p;
      //Retrieve the length of the key_exchange field
      n = ntohs(keyShareEntry->length);

      //Malformed extension?
      if(length < (sizeof(Tls13KeyShareEntry) + n))
         return ERROR_DECODING_FAILED;

      //Clients must not offer multiple KeyShareEntry values for the same
      //group. Servers may check for violations of this rule and abort the
      //handshake with an illegal_parameter alert
      if(ntohs(keyShareEntry->group) == namedGroup)
         return ERROR_ILLEGAL_PARAMETER;

      //Jump to the next key share entry
      p += sizeof(Tls13KeyShareEntry) + n;
      //Number of bytes left to process
      length -= sizeof(Tls13KeyShareEntry) + n;
   }

   //Successful verification
   return NO_ERROR;
}


/**
 * @brief Format certificate extensions
 * @param[in] p Output stream where to write the list of extensions
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatCertExtensions(uint8_t *p, size_t *written)
{
   TlsExtensionList *extensionList;

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Extensions in the Certificate message from the server must correspond to
   //ones from the ClientHello message. Extensions in the Certificate message
   //from the client must correspond to extensions in the CertificateRequest
   //message from the server
   extensionList->length = HTONS(0);

   //Total number of bytes that have been written
   *written = sizeof(TlsExtensionList);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse certificate extensions
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tls13ParseCertExtensions(const uint8_t *p, size_t length,
   size_t *consumed)
{
   error_t error;
   size_t n;
   TlsHelloExtensions extensions;
   const TlsExtensionList *extensionList;

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Malformed CertificateEntry?
   if(length < sizeof(TlsExtensionList))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the list
   n = sizeof(TlsExtensionList) + ntohs(extensionList->length);

   //Malformed CertificateEntry?
   if(length < n)
      return ERROR_DECODING_FAILED;

   //Parse the list of extensions for the current CertificateEntry
   error = tlsParseHelloExtensions(TLS_TYPE_CERTIFICATE, p, n,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions
   error = tlsCheckHelloExtensions(TLS_TYPE_CERTIFICATE, TLS_VERSION_1_3,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been consumed
   *consumed = n;

   //Successful processing
   return NO_ERROR;
}

#endif
