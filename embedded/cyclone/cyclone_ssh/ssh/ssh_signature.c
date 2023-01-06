/**
 * @file ssh_signature.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_signature.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_cert_import.h"
#include "ssh/ssh_cert_parse.h"
#include "ssh/ssh_misc.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;
   SshString name;
   const char_t *signFormatId;

   //Total length of the signature encoding
   *written = 0;

   //Get the name of the public key algorithm
   name.value = publicKeyAlgo;
   name.length = osStrlen(publicKeyAlgo);

   //Public key/certificate formats that do not explicitly specify a signature
   //format identifier must use the public key/certificate format identifier
   //as the signature identifier (refer to RFC 4253, section 6.6)
   signFormatId = sshGetSignFormatId(&name);

   //Valid signature format identifier?
   if(signFormatId != NULL)
   {
      //Format signature format identifier
      error = sshFormatString(signFormatId, p, &n);

      //Check status code
      if(!error)
      {
         //Point to the signature blob
         p += n;
         *written += n;

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
         //Valid signature generation callback function?
         if(connection->context->signGenCallback != NULL)
         {
            //Invoke user-defined callback
            error = connection->context->signGenCallback(connection,
               signFormatId, hostKey, sessionId, message, p, &n);
         }
         else
#endif
         {
            //No callback function registered
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }

         //Check status code
         if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO ||
            error == ERROR_UNKOWN_KEY)
         {
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
            //RSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-rsa") ||
               sshCompareAlgo(signFormatId, "rsa-sha2-256") ||
               sshCompareAlgo(signFormatId, "rsa-sha2-512"))
            {
               //Generate an RSA signature using the host private key
               error = sshGenerateRsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-dss"))
            {
               //Generate a DSA signature using the host private key
               error = sshGenerateDsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp256") ||
               sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp384") ||
               sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp521"))
            {
               //Generate an ECDSA signature using the host private key
               error = sshGenerateEcdsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
            //Ed22519 signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-ed25519"))
            {
               //Generate an EdDSA signature using the host private key
               error = sshGenerateEd25519Signature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
            //Ed448 signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-ed448"))
            {
               //Generate an EdDSA signature using the host private key
               error = sshGenerateEd448Signature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
            //Unknown signature algorithm?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
         }
      }

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been written
         *written += n;
      }
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateRsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const HashAlgo *hashAlgo;
   HashContext hashContext;

#if (SSH_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ssh-rsa"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "rsa-sha2-256"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "rsa-sha2-512"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown host key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      RsaPrivateKey rsaPrivateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&rsaPrivateKey);

      //Initialize hash context
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

      //Import RSA private key
      error = sshImportRsaPrivateKey(hostKey->privateKey,
         hostKey->privateKeyLen, &rsaPrivateKey);

      //Check status code
      if(!error)
      {
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(&rsaPrivateKey, hashAlgo,
            hashContext.digest, p + 4, &n);
      }

      //Check status code
      if(!error)
      {
         //The resulting RSA signature blob is encoded as a string
         STORE32BE(n, p);
         //Total number of bytes that have been written
         *written = sizeof(uint32_t) + n;
      }

      //Free previously allocated memory
      rsaFreePrivateKey(&rsaPrivateKey);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateDsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   SshContext *context;
   DsaPrivateKey dsaPrivateKey;
   DsaSignature dsaSignature;
   Sha1Context sha1Context;

   //Initialize variable
   n = 0;

   //Point to the SSH context
   context = connection->context;

   //Initialize DSA private key
   dsaInitPrivateKey(&dsaPrivateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Initialize hash context
   sha1Init(&sha1Context);

   //Valid session identifier?
   if(sessionId != NULL)
   {
      uint8_t temp[4];

      //Encode the length of the session identifier as a 32-bit big-endian
      //integer
      STORE32BE(sessionId->length, temp);

      //Digest the length field
      sha1Update(&sha1Context, temp, sizeof(temp));
      //Digest the session identifier
      sha1Update(&sha1Context, sessionId->value, sessionId->length);
   }

   //Digest the message
   sha1Update(&sha1Context, message->value, message->length);
   sha1Final(&sha1Context, NULL);

   //Import DSA private key
   error = sshImportDsaPrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &dsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(context->prngAlgo, context->prngContext,
         &dsaPrivateKey, sha1Context.digest, SHA1_DIGEST_SIZE, &dsaSignature);
   }

   //Check status code
   if(!error)
   {
      //The DSA signature blob contains R followed by S (which are 160-bit
      //integers)
      n = mpiGetByteLength(&dsaPrivateKey.params.q);

      //Encode integer R
      error = mpiExport(&dsaSignature.r, p + 4, n, MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Encode integer S
      error = mpiExport(&dsaSignature.s, p + n + 4, n, MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //The resulting DSA signature blob is encoded as a string
      STORE32BE(2 * n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + 2 * n;
   }

   //Free previously allocated resources
   dsaFreePrivateKey(&dsaPrivateKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEcdsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t rLen;
   size_t sLen;
   SshContext *context;
   const HashAlgo *hashAlgo;
   const EcCurveInfo *curveInfo;
   HashContext hashContext;

   //Point to the SSH context
   context = connection->context;

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp256"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP256R1_CURVE;
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp384"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP384R1_CURVE;
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp521"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP521R1_CURVE;
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      curveInfo = NULL;
      hashAlgo = NULL;
   }

   //Valid parameters?
   if(curveInfo != NULL && hashAlgo != NULL)
   {
      EcDomainParameters ecParams;
      EcPrivateKey ecPrivateKey;
      EcdsaSignature ecdsaSignature;

      //Initialize EC domain parameters
      ecInitDomainParameters(&ecParams);
      //Initialize EC private key
      ecInitPrivateKey(&ecPrivateKey);
      //Initialize ECDSA signature
      ecdsaInitSignature(&ecdsaSignature);

      //Initialize hash context
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

      //Import EC domain parameters
      error = ecLoadDomainParameters(&ecParams, curveInfo);

      //Check status code
      if(!error)
      {
         //Import ECDSA private key
         error = sshImportEcdsaPrivateKey(hostKey->privateKey,
            hostKey->privateKeyLen, &ecPrivateKey);
      }

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature
         error = ecdsaGenerateSignature(context->prngAlgo, context->prngContext,
            &ecParams, &ecPrivateKey, hashContext.digest, hashAlgo->digestSize,
            &ecdsaSignature);
      }

      //Check status code
      if(!error)
      {
         //Encode integer R
         error = sshFormatMpint(&ecdsaSignature.r, p + 4, &rLen);
      }

      //Check status code
      if(!error)
      {
         //Encode integer S
         error = sshFormatMpint(&ecdsaSignature.s, p + rLen + 4, &sLen);
      }

      //Check status code
      if(!error)
      {
         //The resulting ECDSA signature blob is encoded as a string
         STORE32BE(rLen + sLen, p);
         //Total number of bytes that have been written
         *written = sizeof(uint32_t) + rLen + sLen;
      }

      //Free previously allocated resources
      ecFreeDomainParameters(&ecParams);
      ecFreePrivateKey(&ecPrivateKey);
      ecdsaFreeSignature(&ecdsaSignature);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd25519Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED25519_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import Ed25519 private key
   error = sshImportEd25519PrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve raw private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED25519_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Generate Ed25519 signature (PureEdDSA mode)
      error = ed25519GenerateSignatureEx(d, NULL, messageChunks, NULL, 0, 0,
         p + 4);

      //The Ed25519 signature consists of 32 octets
      n = ED25519_SIGNATURE_LEN;
   }

   //Check status code
   if(!error)
   {
      //The resulting EdDSA signature is encoded as a string
      STORE32BE(n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + n;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&eddsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd448Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED448_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import Ed448 private key
   error = sshImportEd448PrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve raw private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED448_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Generate Ed448 signature (PureEdDSA mode)
      error = ed448GenerateSignatureEx(d, NULL, messageChunks, NULL, 0, 0,
         p + 4);

      //The Ed448 signature consists of 57 octets
      n = ED448_SIGNATURE_LEN;
   }

   //Check status code
   if(!error)
   {
      //The resulting EdDSA signature is encoded as a string
      STORE32BE(n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + n;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&eddsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t sshVerifySignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   const SshBinaryString *signature)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   SshString keyFormatId;
   SshString signFormatId;
   SshBinaryString signatureBlob;
   const char_t *expectedKeyFormatId;
   const char_t *expectedSignFormatId;

   //Point to the first field of the signature
   p = signature->value;
   n = signature->length;

   //Decode signature format identifier
   error = sshParseString(p, n, &signFormatId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signFormatId.length;
   n -= sizeof(uint32_t) + signFormatId.length;

   //Decode signature blob
   error = sshParseBinaryString(p, n, &signatureBlob);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signatureBlob.length;
   n -= sizeof(uint32_t) + signatureBlob.length;

   //Malformed signature?
   if(n != 0)
      return ERROR_INVALID_MESSAGE;

   //Extract key format identifier from public key blob
   error = sshParseString(publicKeyBlob->value, publicKeyBlob->length,
      &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Each public key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Inconsistent key format identifier?
   if(!sshCompareString(&keyFormatId, expectedKeyFormatId))
      return ERROR_INVALID_SIGNATURE;

   //Public key/certificate formats that do not explicitly specify a signature
   //format identifier must use the public key/certificate format identifier
   //as the signature identifier (refer to RFC 4253, section 6.6)
   expectedSignFormatId = sshGetSignFormatId(publicKeyAlgo);

   //Inconsistent signature format identifier?
   if(!sshCompareString(&signFormatId, expectedSignFormatId))
      return ERROR_INVALID_SIGNATURE;

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature verification callback function?
   if(connection->context->signVerifyCallback != NULL)
   {
      //Invoke user-defined callback
      error = connection->context->signVerifyCallback(connection,
         publicKeyAlgo, publicKeyBlob, sessionId, message, &signatureBlob);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO)
   {
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
      //RSA signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-rsa") ||
         sshCompareString(&signFormatId, "rsa-sha2-256") ||
         sshCompareString(&signFormatId, "rsa-sha2-512"))
      {
         //RSA signature verification
         error = sshVerifyRsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-dss"))
      {
         //DSA signature verification
         error = sshVerifyDsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature algorithm?
      if(sshCompareString(&signFormatId, "ecdsa-sha2-nistp256") ||
         sshCompareString(&signFormatId, "ecdsa-sha2-nistp384") ||
         sshCompareString(&signFormatId, "ecdsa-sha2-nistp521"))
      {
         //ECDSA signature verification
         error = sshVerifyEcdsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
      //Ed22519 signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-ed25519"))
      {
         //Ed25519 signature verification
         error = sshVerifyEd25519Signature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
      //Ed448 signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-ed448"))
      {
         //Ed448 signature verification
         error = sshVerifyEd448Signature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
      //Unknown public key type?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyRsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   const HashAlgo *hashAlgo;
   HashContext hashContext;

#if (SSH_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ssh-rsa") ||
      sshCompareString(publicKeyAlgo, "ssh-rsa-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-256") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-256-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-512") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-512-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      RsaPublicKey rsaPublicKey;

      //Initialize RSA public key
      rsaInitPublicKey(&rsaPublicKey);

      //Initialize hash context
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

#if (SSH_CERT_SUPPORT == ENABLED)
      //RSA certificate?
      if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
      {
         SshCertificate cert;

         //Parse RSA certificate structure
         error = sshParseCertificate(publicKeyBlob->value,
            publicKeyBlob->length, &cert);

         //Check status
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaCertPublicKey(&cert, &rsaPublicKey);
         }
      }
      else
#endif
      //RSA public key?
      {
         SshRsaHostKey hostKey;

         //Parse RSA host key structure
         error = sshParseRsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
            &hostKey);

         //Check status code
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaHostKey(&hostKey, &rsaPublicKey);
         }
      }

      //Check status code
      if(!error)
      {
         //Verify RSA signature
         error = rsassaPkcs1v15Verify(&rsaPublicKey, hashAlgo,
            hashContext.digest, signatureBlob->value, signatureBlob->length);
      }

      //Free previously allocated resources
      rsaFreePublicKey(&rsaPublicKey);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyDsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   DsaPublicKey dsaPublicKey;
   DsaSignature dsaSignature;
   Sha1Context sha1Context;

   //The DSA signature blob contains R followed by S (which are 160-bit
   //integers)
   if(signatureBlob->length != 40)
      return ERROR_INVALID_MESSAGE;

   //Initialize DSA public key
   dsaInitPublicKey(&dsaPublicKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Initialize hash context
   sha1Init(&sha1Context);

   //Valid session identifier?
   if(sessionId != NULL)
   {
      uint8_t temp[4];

      //Encode the length of the session identifier as a 32-bit big-endian
      //integer
      STORE32BE(sessionId->length, temp);

      //Digest the length field
      sha1Update(&sha1Context, temp, sizeof(temp));
      //Digest the session identifier
      sha1Update(&sha1Context, sessionId->value, sessionId->length);
   }

   //Digest the message
   sha1Update(&sha1Context, message->value, message->length);
   sha1Final(&sha1Context, NULL);

#if (SSH_CERT_SUPPORT == ENABLED)
   //DSA certificate?
   if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
   {
      SshCertificate cert;

      //Parse DSA certificate structure
      error = sshParseCertificate(publicKeyBlob->value, publicKeyBlob->length,
         &cert);

      //Check status
      if(!error)
      {
         //Import DSA public key
         error = sshImportDsaCertPublicKey(&cert, &dsaPublicKey);
      }
   }
   else
#endif
   //DSA public key?
   {
      SshDsaHostKey hostKey;

      //Parse DSA host key structure
      error = sshParseDsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
         &hostKey);

      //Check status code
      if(!error)
      {
         //Import DSA public key
         error = sshImportDsaHostKey(&hostKey, &dsaPublicKey);
      }
   }

   //Check status code
   if(!error)
   {
      //Import integer R
      error = mpiImport(&dsaSignature.r, signatureBlob->value, 20,
         MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Import integer S
      error = mpiImport(&dsaSignature.s, signatureBlob->value + 20, 20,
         MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Verify DSA signature
      error = dsaVerifySignature(&dsaPublicKey, sha1Context.digest,
         SHA1_DIGEST_SIZE, &dsaSignature);
   }

   //Free previously allocated resources
   dsaFreePublicKey(&dsaPublicKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEcdsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   SshEcdsaSignature signature;
   const HashAlgo *hashAlgo;
   HashContext hashContext;

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      EcDomainParameters ecParams;
      EcPublicKey ecPublicKey;
      EcdsaSignature ecdsaSignature;

      //Initialize EC domain parameters
      ecInitDomainParameters(&ecParams);
      //Initialize EC public key
      ecInitPublicKey(&ecPublicKey);
      //Initialize ECDSA signature
      ecdsaInitSignature(&ecdsaSignature);

      //Initialize hash context
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

#if (SSH_CERT_SUPPORT == ENABLED)
      //ECDSA certificate?
      if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
      {
         SshCertificate cert;

         //Parse ECDSA certificate structure
         error = sshParseCertificate(publicKeyBlob->value,
            publicKeyBlob->length, &cert);

         //Check status
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaCertPublicKey(&cert, &ecParams, &ecPublicKey);
         }
      }
      else
#endif
      //ECDSA public key?
      {
         SshEcdsaHostKey hostKey;

         //Parse ECDSA host key structure
         error = sshParseEcdsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
            &hostKey);

         //Check status code
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaHostKey(&hostKey, &ecParams, &ecPublicKey);
         }
      }

      //Check status code
      if(!error)
      {
         //Parse ECDSA signature structure
         error = sshParseEcdsaSignature(signatureBlob->value,
            signatureBlob->length, &signature);
      }

      //Check status code
      if(!error)
      {
         //Import integer R
         error = mpiImport(&ecdsaSignature.r, signature.r.value,
            signature.r.length, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Import integer S
         error = mpiImport(&ecdsaSignature.s, signature.s.value,
            signature.s.length, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature
         error = ecdsaVerifySignature(&ecParams, &ecPublicKey,
            hashContext.digest, hashAlgo->digestSize, &ecdsaSignature);
      }

      //Free previously allocated resources
      ecFreeDomainParameters(&ecParams);
      ecFreePublicKey(&ecPublicKey);
      ecdsaFreeSignature(&ecdsaSignature);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd25519Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *ed25519PublicKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];

   //The Ed25519 signature consists of 32 octets
   if(signatureBlob->length != ED25519_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

#if (SSH_CERT_SUPPORT == ENABLED)
   //Ed22519 certificate?
   if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
   {
      SshCertificate cert;

      //Parse Ed25519 certificate structure
      error = sshParseCertificate(publicKeyBlob->value, publicKeyBlob->length,
         &cert);

      //Check status
      if(!error)
      {
         //The Ed25519 public key consists of 32 octets
         ed25519PublicKey = cert.publicKey.ed25519PublicKey.q.value;
      }
   }
   else
#endif
   //Ed25519 public key?
   {
      SshEddsaHostKey hostKey;

      //Parse Ed25519 host key structure
      error = sshParseEd25519HostKey(publicKeyBlob->value,
         publicKeyBlob->length, &hostKey);

      //Check status
      if(!error)
      {
         //The Ed25519 public key consists of 32 octets
         ed25519PublicKey = hostKey.q.value;
      }
   }

   //Check status
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Verify Ed25519 signature (PureEdDSA mode)
      error = ed25519VerifySignatureEx(ed25519PublicKey, messageChunks, NULL,
         0, 0, signatureBlob->value);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd448Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   SshEddsaHostKey hostKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];

   //The Ed448 signature consists of 57 octets
   if(signatureBlob->length != ED448_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

   //Parse Ed448 host key structure
   error = sshParseEd448HostKey(publicKeyBlob->value, publicKeyBlob->length,
      &hostKey);

   //Check status
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Verify Ed448 signature (PureEdDSA mode)
      error = ed448VerifySignatureEx(hostKey.q.value, messageChunks, NULL,
         0, 0, signatureBlob->value);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an ECDSA signature
 * @param[in] signature ECDSA signature
 * @param[out] p  Output stream where to write the ECDSA signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatEcdsaSignature(const SshEcdsaSignature *signature,
   uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t rLen;
   size_t sLen;

   //Encode integer R
   error = sshConvertArrayToMpint(signature->r.value, signature->r.length,
      p + 4, &rLen);

   //Check status code
   if(!error)
   {
      //Encode integer S
      error = sshConvertArrayToMpint(signature->s.value, signature->s.length,
         p + rLen + 4, &sLen);
   }

   //Check status code
   if(!error)
   {
      //The resulting ECDSA signature blob is encoded as a string
      STORE32BE(rLen + sLen, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + rLen + sLen;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an ECDSA signature
 * @param[in] data Pointer to the ECDSA signature structure
 * @param[in] length Length of the ECDSA signature structure, in bytes
 * @param[out] signature Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEcdsaSignature(const uint8_t *data, size_t length,
   SshEcdsaSignature *signature)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode integer R
   error = sshParseBinaryString(data, length, &signature->r);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + signature->r.length;
   length -= sizeof(uint32_t) + signature->r.length;

   //Decode integer S
   error = sshParseBinaryString(data, length, &signature->s);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + signature->s.length;
   length -= sizeof(uint32_t) + signature->s.length;

   //Malformed signature?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
