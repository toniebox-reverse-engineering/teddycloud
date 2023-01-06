/**
 * @file tls13_signature.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
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
#include "tls_signature.h"
#include "tls_transcript_hash.h"
#include "tls_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Digital signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls13GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   Tls13DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls13DigitalSignature *) p;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hashAlgo == NULL)
      return ERROR_FAILURE;

   //Calculate the length of the content covered by the digital signature
   n = hashAlgo->digestSize + 98;

   //Allocate a memory buffer
   buffer = tlsAllocMem(n);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Form a string that consists of octet 32 (0x20) repeated 64 times
   osMemset(buffer, ' ', 64);

   //Append the context string. It is used to provide separation between
   //signatures made in different contexts, helping against potential
   //cross-protocol attacks
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      osMemcpy(buffer + 64, "TLS 1.3, client CertificateVerify", 33);
   }
   else
   {
      osMemcpy(buffer + 64, "TLS 1.3, server CertificateVerify", 33);
   }

   //Append a single 0 byte which serves as the separator
   buffer[97] = 0x00;

   //Compute the transcript hash
   error = tlsFinalizeTranscriptHash(context, hashAlgo,
      context->transcriptHashContext, "", buffer + 98);

   //Check status code
   if(!error)
   {
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSA-PSS signature scheme?
      if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384 ||
         context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
      {
         RsaPrivateKey privateKey;

         //Initialize RSA private key
         rsaInitPrivateKey(&privateKey);

         //The algorithm field specifies the signature scheme and the
         //corresponding hash algorithm
         if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
         {
            //Select rsa_pss_rsae_sha256 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
         {
            //Select rsa_pss_rsae_sha384 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
         {
            //Select rsa_pss_rsae_sha512 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256)
         {
            //Select rsa_pss_pss_sha256 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384)
         {
            //Select rsa_pss_pss_sha384 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512)
         {
            //Select rsa_pss_pss_sha512 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
         }
         else
         {
            //Invalid signature algorithm
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }

         //Check status code
         if(!error)
         {
            //Pre-hash the content covered by the digital signature
            if(hashAlgo != NULL)
            {
               error = hashAlgo->compute(buffer, n, context->clientVerifyData);
            }
            else
            {
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
         }

         //Check status code
         if(!error)
         {
            //Retrieve the RSA private key corresponding to the certificate sent
            //in the previous message
            error = pemImportRsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLen, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //RSA signatures must use an RSASSA-PSS algorithm, regardless of
            //whether RSASSA-PKCS1-v1_5 algorithms appear in SignatureAlgorithms
            error = rsassaPssSign(context->prngAlgo, context->prngContext,
               &privateKey, hashAlgo, hashAlgo->digestSize,
               context->clientVerifyData, signature->value, length);
         }

         //Release previously allocated resources
         rsaFreePrivateKey(&privateKey);
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature scheme?
      if(context->signAlgo == TLS_SIGN_ALGO_ECDSA)
      {
         //The algorithm field specifies the signature scheme, the corresponding
         //curve and the corresponding hash algorithm
         if(context->cert->namedCurve == TLS_GROUP_SECP256R1 &&
            context->signHashAlgo == TLS_HASH_ALGO_SHA256)
         {
            //Select ecdsa_secp256r1_sha256 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
         }
         else if(context->cert->namedCurve == TLS_GROUP_SECP384R1 &&
            context->signHashAlgo == TLS_HASH_ALGO_SHA384)
         {
            //Select ecdsa_secp384r1_sha384 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
         }
         else if(context->cert->namedCurve == TLS_GROUP_SECP521R1 &&
            context->signHashAlgo == TLS_HASH_ALGO_SHA512)
         {
            //Select ecdsa_secp521r1_sha512 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512);
            hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
         }
         else
         {
            //Invalid signature algorithm
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }

         //Check status code
         if(!error)
         {
            //Pre-hash the content covered by the digital signature
            if(hashAlgo != NULL)
            {
               error = hashAlgo->compute(buffer, n, context->clientVerifyData);
            }
            else
            {
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
         }

         //Check status code
         if(!error)
         {
            //Generate an ECDSA signature
            error = tlsGenerateEcdsaSignature(context, context->clientVerifyData,
               hashAlgo->digestSize, signature->value, length);
         }
      }
      else
#endif
#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED)
      //EdDSA signature scheme?
      if(context->signAlgo == TLS_SIGN_ALGO_ED25519 ||
         context->signAlgo == TLS_SIGN_ALGO_ED448)
      {
         //The algorithm field specifies the signature algorithm used
         if(context->signAlgo == TLS_SIGN_ALGO_ED25519)
         {
            //Select ed25519 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_ED25519);
         }
         else if(context->signAlgo == TLS_SIGN_ALGO_ED448)
         {
            //Select ed448 signature algorithm
            signature->algorithm = HTONS(TLS_SIGN_SCHEME_ED448);
         }
         else
         {
            //Invalid signature algorithm
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }

         //Check status code
         if(!error)
         {
            EddsaMessageChunk messageChunks[2];

            //Data to be signed is run through the EdDSA algorithm without
            //pre-hashing
            messageChunks[0].buffer = buffer;
            messageChunks[0].length = n;
            messageChunks[1].buffer = NULL;
            messageChunks[1].length = 0;

            //Generate a signature in PureEdDSA mode
            error = tlsGenerateEddsaSignature(context, messageChunks,
               signature->value, length);
         }
      }
      else
#endif
      //Invalid signature scheme?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Release memory buffer
   tlsFreeMem(buffer);

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(*length);
      //Total length of the digitally-signed element
      *length += sizeof(Tls13DigitalSignature);
   }

   //Return status code
   return error;
}


/**
 * @brief Digital signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Pointer to the digitally-signed element to be verified
 * @param[in] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls13VerifySignature(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   Tls13SignatureScheme signAlgo;
   const Tls13DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls13DigitalSignature *) p;

   //Malformed CertificateVerify message?
   if(length < sizeof(Tls13DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(Tls13DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hashAlgo == NULL)
      return ERROR_FAILURE;

   //Calculate the length of the content covered by the digital signature
   n = hashAlgo->digestSize + 98;

   //Allocate a memory buffer
   buffer = tlsAllocMem(n);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Form a string that consists of octet 32 (0x20) repeated 64 times
   osMemset(buffer, ' ', 64);

   //Append the context string. It is used to provide separation between
   //signatures made in different contexts, helping against potential
   //cross-protocol attacks
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      osMemcpy(buffer + 64, "TLS 1.3, server CertificateVerify", 33);
   }
   else
   {
      osMemcpy(buffer + 64, "TLS 1.3, client CertificateVerify", 33);
   }

   //Append a single 0 byte which serves as the separator
   buffer[97] = 0x00;

   //Compute the transcript hash
   error = tlsFinalizeTranscriptHash(context, hashAlgo,
      context->transcriptHashContext, "", buffer + 98);

   //Check status code
   if(!error)
   {
      //The algorithm field specifies the signature scheme
      signAlgo = (Tls13SignatureScheme) ntohs(signature->algorithm);

#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSASSA-PSS signature scheme?
      if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
         signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
         signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
         signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
         signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
         signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
      {
         //Enforce the type of the certificate provided by the peer
         if(context->peerCertType == TLS_CERT_RSA_SIGN)
         {
            //Retrieve the hash algorithm used for signing
            if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256)
            {
               //Select SHA-256 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384)
            {
               //Select SHA-384 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512)
            {
               //Select SHA-512 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
            }
            else
            {
               //Invalid signature scheme
               hashAlgo = NULL;
            }
         }
         else if(context->peerCertType == TLS_CERT_RSA_PSS_SIGN)
         {
            //Retrieve the hash algorithm used for signing
            if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
            {
               //Select SHA-256 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
            {
               //Select SHA-384 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
            {
               //Select SHA-512 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
            }
            else
            {
               //Invalid signature scheme
               hashAlgo = NULL;
            }
         }
         else
         {
            //Invalid certificate
            hashAlgo = NULL;
         }

         //Pre-hash the content covered by the digital signature
         if(hashAlgo != NULL)
         {
            error = hashAlgo->compute(buffer, n, context->clientVerifyData);
         }
         else
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }

         //Check status code
         if(!error)
         {
            //Verify RSASSA-PSS signature
            error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
               hashAlgo->digestSize, context->clientVerifyData,
               signature->value, ntohs(signature->length));
         }
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature scheme?
      if(signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 ||
         signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 ||
         signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512)
      {
         //Enforce the type of the certificate provided by the peer
         if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
         {
            //Retrieve the hash algorithm used for signing
            if(context->peerEcParams.name == NULL)
            {
               //Invalid signature scheme
               hashAlgo = NULL;
            }
            else if(signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 &&
               osStrcmp(context->peerEcParams.name, "secp256r1") == 0)
            {
               //Select SHA-256 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 &&
               osStrcmp(context->peerEcParams.name, "secp384r1") == 0)
            {
               //Select SHA-384 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
            }
            else if(signAlgo == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 &&
               osStrcmp(context->peerEcParams.name, "secp521r1") == 0)
            {
               //Select SHA-512 hash algorithm
               hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
            }
            else
            {
               //Invalid signature scheme
               hashAlgo = NULL;
            }
         }
         else
         {
            //Invalid certificate
            hashAlgo = NULL;
         }

         //Pre-hash the content covered by the digital signature
         if(hashAlgo != NULL)
         {
            error = hashAlgo->compute(buffer, n, context->clientVerifyData);
         }
         else
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }

         //Check status code
         if(!error)
         {
            //Verify ECDSA signature
            error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
               hashAlgo->digestSize, signature->value, ntohs(signature->length));
         }
      }
      else
#endif
#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED && TLS_ED25519_SUPPORT == ENABLED)
      //Ed25519 signature scheme?
      if(signAlgo == TLS_SIGN_SCHEME_ED25519)
      {
         //Enforce the type of the certificate provided by the peer
         if(context->peerCertType == TLS_CERT_ED25519_SIGN)
         {
            EddsaMessageChunk messageChunks[2];

            //Data to be verified is run through the EdDSA algorithm without
            //pre-hashing
            messageChunks[0].buffer = buffer;
            messageChunks[0].length = n;
            messageChunks[1].buffer = NULL;
            messageChunks[1].length = 0;

            //Verify EdDSA signature (PureEdDSA mode)
            error = tlsVerifyEddsaSignature(context, messageChunks,
               signature->value, ntohs(signature->length));
         }
         else
         {
            //Invalid certificate
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
#endif
#if (TLS_EDDSA_SIGN_SUPPORT == ENABLED && TLS_ED448_SUPPORT == ENABLED)
      //Ed448 signature scheme?
      if(signAlgo == TLS_SIGN_SCHEME_ED448)
      {
         //Enforce the type of the certificate provided by the peer
         if(context->peerCertType == TLS_CERT_ED448_SIGN)
         {
            EddsaMessageChunk messageChunks[2];

            //Data to be verified is run through the EdDSA algorithm without
            //pre-hashing
            messageChunks[0].buffer = buffer;
            messageChunks[0].length = n;
            messageChunks[1].buffer = NULL;
            messageChunks[1].length = 0;

            //Verify EdDSA signature (PureEdDSA mode)
            error = tlsVerifyEddsaSignature(context, messageChunks,
               signature->value, ntohs(signature->length));
         }
         else
         {
            //Invalid certificate
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
#endif
      //Unknown signature scheme?
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }

   //Release memory buffer
   tlsFreeMem(buffer);

   //Return status code
   return error;
}

#endif
