/**
 * @file ssh_key_parse.c
 * @brief SSH key parsing
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
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_misc.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Parse host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] keyFormatId Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseHostKey(const uint8_t *data, size_t length,
   SshString *keyFormatId)
{
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, keyFormatId);

   //Check status code
   if(!error)
   {
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
      //RSA public key?
      if(sshCompareString(keyFormatId, "ssh-rsa"))
      {
         SshRsaHostKey hostKey;

         //Parse RSA host key structure
         error = sshParseRsaHostKey(data, length, &hostKey);
      }
      else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
      //DSA public key?
      if(sshCompareString(keyFormatId, "ssh-dss"))
      {
         SshDsaHostKey hostKey;

         //Parse DSA host key structure
         error = sshParseDsaHostKey(data, length, &hostKey);
      }
      else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA public key?
      if(sshCompareString(keyFormatId, "ecdsa-sha2-nistp256") ||
         sshCompareString(keyFormatId, "ecdsa-sha2-nistp384") ||
         sshCompareString(keyFormatId, "ecdsa-sha2-nistp521"))
      {
         SshEcdsaHostKey hostKey;

         //Parse ECDSA host key structure
         error = sshParseEcdsaHostKey(data, length, &hostKey);
      }
      else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
      //Ed22519 public key?
      if(sshCompareString(keyFormatId, "ssh-ed25519"))
      {
         SshEddsaHostKey hostKey;

         //Parse Ed25519 host key structure
         error = sshParseEd25519HostKey(data, length, &hostKey);
      }
      else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
      //Ed448 public key?
      if(sshCompareString(keyFormatId, "ssh-ed448"))
      {
         SshEddsaHostKey hostKey;

         //Parse Ed448 host key structure
         error = sshParseEd448HostKey(data, length, &hostKey);
      }
      else
#endif
      //Unknown public key type?
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse an RSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseRsaHostKey(const uint8_t *data, size_t length,
   SshRsaHostKey *hostKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-rsa"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse RSA public exponent
   error = sshParseBinaryString(data, length, &hostKey->e);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->e.length;
   length -= sizeof(uint32_t) + hostKey->e.length;

   //Parse RSA modulus
   error = sshParseBinaryString(data, length, &hostKey->n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->n.length;
   length -= sizeof(uint32_t) + hostKey->n.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse a DSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseDsaHostKey(const uint8_t *data, size_t length,
   SshDsaHostKey *hostKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-dss"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse DSA prime modulus
   error = sshParseBinaryString(data, length, &hostKey->p);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->p.length;
   length -= sizeof(uint32_t) + hostKey->p.length;

   //Parse DSA group order
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Parse DSA group generator
   error = sshParseBinaryString(data, length, &hostKey->g);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->g.length;
   length -= sizeof(uint32_t) + hostKey->g.length;

   //Parse DSA public key value
   error = sshParseBinaryString(data, length, &hostKey->y);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->y.length;
   length -= sizeof(uint32_t) + hostKey->y.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an ECDSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEcdsaHostKey(const uint8_t *data, size_t length,
   SshEcdsaHostKey *hostKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp256") &&
      !sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp384") &&
      !sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp521"))
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse elliptic curve domain parameter identifier
   error = sshParseString(data, length, &hostKey->curveName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->curveName.length;
   length -= sizeof(uint32_t) + hostKey->curveName.length;

   //Parse public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an Ed25519 host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEd25519HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-ed25519"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse Ed25519 public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //The public key shall consist of 32 octets
   if(hostKey->q.length != ED25519_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an Ed448 host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEd448HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-ed448"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse Ed448 public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //The public key shall consist of 57 octets
   if(hostKey->q.length != ED448_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse private key header (OpenSSH format)
 * @param[in] data Pointer to the private key structure
 * @param[in] length Length of the private key structure, in bytes
 * @param[out] privateKeyHeader Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshPrivateKeyHeader(const uint8_t *data, size_t length,
   SshPrivateKeyHeader *privateKeyHeader)
{
   error_t error;

   //Malformed private key?
   if(length < SSH_AUTH_MAGIC_SIZE)
      return ERROR_INVALID_SYNTAX;

   //Check magic identifier
   if(osMemcmp(data, "openssh-key-v1", SSH_AUTH_MAGIC_SIZE))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += SSH_AUTH_MAGIC_SIZE;
   length -= SSH_AUTH_MAGIC_SIZE;

   //Parse 'ciphername' field
   error = sshParseString(data, length, &privateKeyHeader->cipherName);
   //Any error to report?
   if(error)
      return error;

   //For unencrypted keys the cipher "none" is used
   if(!sshCompareString(&privateKeyHeader->cipherName, "none"))
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   data += sizeof(uint32_t) + privateKeyHeader->cipherName.length;
   length -= sizeof(uint32_t) + privateKeyHeader->cipherName.length;

   //Parse 'kdfname' field
   error = sshParseString(data, length, &privateKeyHeader->kdfName);
   //Any error to report?
   if(error)
      return error;

   //For unencrypted keys the KDF "none" is used
   if(!sshCompareString(&privateKeyHeader->kdfName, "none"))
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   data += sizeof(uint32_t) + privateKeyHeader->kdfName.length;
   length -= sizeof(uint32_t) + privateKeyHeader->kdfName.length;

   //Parse 'kdfoptions' field
   error = sshParseBinaryString(data, length, &privateKeyHeader->kdfOptions);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKeyHeader->kdfOptions.length;
   length -= sizeof(uint32_t) + privateKeyHeader->kdfOptions.length;

   //Malformed private key?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //Parse 'number of keys' field
   privateKeyHeader->numKeys = LOAD32BE(data);

   //The implementation supports only one public and private key
   if(privateKeyHeader->numKeys != 1)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse 'publickey' field
   error = sshParseBinaryString(data, length, &privateKeyHeader->publicKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKeyHeader->publicKey.length;
   length -= sizeof(uint32_t) + privateKeyHeader->publicKey.length;

   //Parse 'encrypted' field
   error = sshParseBinaryString(data, length, &privateKeyHeader->encrypted);
   //Any error to report?
   if(error)
      return error;

   //The length of the 'encrypted' section must be a multiple of the block size
   if((privateKeyHeader->encrypted.length % 8) != 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + privateKeyHeader->encrypted.length;
   length -= sizeof(uint32_t) + privateKeyHeader->encrypted.length;

   //Malformed private key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RSA private key blob (OpenSSH format)
 * @param[in] data Pointer to the private key blob
 * @param[in] length Length of the private key blob, in bytes
 * @param[out] privateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshRsaPrivateKey(const uint8_t *data, size_t length,
   SshRsaPrivateKey *privateKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Malformed private key blob?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'checkint' fields
   privateKey->checkInt1 = LOAD32BE(data);
   privateKey->checkInt2 = LOAD32BE(data + 4);

   //Before the key is encrypted, a random integer is assigned to both
   //'checkint' fields so successful decryption can be quickly checked
   //by verifying that both checkint fields hold the same value
   if(privateKey->checkInt1 != privateKey->checkInt2)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Decode key format identifier
   error = sshParseString(data, length, &privateKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&privateKey->keyFormatId, "ssh-rsa"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->keyFormatId.length;
   length -= sizeof(uint32_t) + privateKey->keyFormatId.length;

   //Parse RSA modulus
   error = sshParseBinaryString(data, length, &privateKey->n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->n.length;
   length -= sizeof(uint32_t) + privateKey->n.length;

   //Parse RSA public exponent
   error = sshParseBinaryString(data, length, &privateKey->e);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->e.length;
   length -= sizeof(uint32_t) + privateKey->e.length;

   //Parse RSA private exponent
   error = sshParseBinaryString(data, length, &privateKey->d);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->d.length;
   length -= sizeof(uint32_t) + privateKey->d.length;

   //Parse RSA CRT coefficient
   error = sshParseBinaryString(data, length, &privateKey->qinv);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->qinv.length;
   length -= sizeof(uint32_t) + privateKey->qinv.length;

   //Parse RSA first factor
   error = sshParseBinaryString(data, length, &privateKey->p);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->p.length;
   length -= sizeof(uint32_t) + privateKey->p.length;

   //Parse RSA second factor
   error = sshParseBinaryString(data, length, &privateKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->q.length;
   length -= sizeof(uint32_t) + privateKey->q.length;

   //The private key is followed by a comment
   error = sshParseString(data, length, &privateKey->comment);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->comment.length;
   length -= sizeof(uint32_t) + privateKey->comment.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse DSA private key blob (OpenSSH format)
 * @param[in] data Pointer to the private key blob
 * @param[in] length Length of the private key blob, in bytes
 * @param[out] privateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshDsaPrivateKey(const uint8_t *data, size_t length,
   SshDsaPrivateKey *privateKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Malformed private key blob?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'checkint' fields
   privateKey->checkInt1 = LOAD32BE(data);
   privateKey->checkInt2 = LOAD32BE(data + 4);

   //Before the key is encrypted, a random integer is assigned to both
   //'checkint' fields so successful decryption can be quickly checked
   //by verifying that both checkint fields hold the same value
   if(privateKey->checkInt1 != privateKey->checkInt2)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Decode key format identifier
   error = sshParseString(data, length, &privateKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&privateKey->keyFormatId, "ssh-dss"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->keyFormatId.length;
   length -= sizeof(uint32_t) + privateKey->keyFormatId.length;

   //Parse DSA prime modulus
   error = sshParseBinaryString(data, length, &privateKey->p);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->p.length;
   length -= sizeof(uint32_t) + privateKey->p.length;

   //Parse DSA group order
   error = sshParseBinaryString(data, length, &privateKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->q.length;
   length -= sizeof(uint32_t) + privateKey->q.length;

   //Parse DSA group generator
   error = sshParseBinaryString(data, length, &privateKey->g);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->g.length;
   length -= sizeof(uint32_t) + privateKey->g.length;

   //Parse DSA public key value
   error = sshParseBinaryString(data, length, &privateKey->y);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->y.length;
   length -= sizeof(uint32_t) + privateKey->y.length;

   //Parse DSA private key value
   error = sshParseBinaryString(data, length, &privateKey->x);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->x.length;
   length -= sizeof(uint32_t) + privateKey->x.length;

   //The private key is followed by a comment
   error = sshParseString(data, length, &privateKey->comment);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->comment.length;
   length -= sizeof(uint32_t) + privateKey->comment.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse ECDSA private key blob (OpenSSH format)
 * @param[in] data Pointer to the private key blob
 * @param[in] length Length of the private key blob, in bytes
 * @param[out] privateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshEcdsaPrivateKey(const uint8_t *data, size_t length,
   SshEcdsaPrivateKey *privateKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Malformed private key blob?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'checkint' fields
   privateKey->checkInt1 = LOAD32BE(data);
   privateKey->checkInt2 = LOAD32BE(data + 4);

   //Before the key is encrypted, a random integer is assigned to both
   //'checkint' fields so successful decryption can be quickly checked
   //by verifying that both checkint fields hold the same value
   if(privateKey->checkInt1 != privateKey->checkInt2)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Decode key format identifier
   error = sshParseString(data, length, &privateKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&privateKey->keyFormatId, "ecdsa-sha2-nistp256") &&
      !sshCompareString(&privateKey->keyFormatId, "ecdsa-sha2-nistp384") &&
      !sshCompareString(&privateKey->keyFormatId, "ecdsa-sha2-nistp521"))
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->keyFormatId.length;
   length -= sizeof(uint32_t) + privateKey->keyFormatId.length;

   //Parse elliptic curve domain parameter identifier
   error = sshParseString(data, length, &privateKey->curveName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->curveName.length;
   length -= sizeof(uint32_t) + privateKey->curveName.length;

   //Parse public key
   error = sshParseBinaryString(data, length, &privateKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->q.length;
   length -= sizeof(uint32_t) + privateKey->q.length;

   //Parse private key
   error = sshParseBinaryString(data, length, &privateKey->d);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->d.length;
   length -= sizeof(uint32_t) + privateKey->d.length;

   //The private key is followed by a comment
   error = sshParseString(data, length, &privateKey->comment);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->comment.length;
   length -= sizeof(uint32_t) + privateKey->comment.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse Ed25519 private key blob (OpenSSH format)
 * @param[in] data Pointer to the private key blob
 * @param[in] length Length of the private key blob, in bytes
 * @param[out] privateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshEd25519PrivateKey(const uint8_t *data, size_t length,
   SshEddsaPrivateKey *privateKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Malformed private key blob?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'checkint' fields
   privateKey->checkInt1 = LOAD32BE(data);
   privateKey->checkInt2 = LOAD32BE(data + 4);

   //Before the key is encrypted, a random integer is assigned to both
   //'checkint' fields so successful decryption can be quickly checked
   //by verifying that both checkint fields hold the same value
   if(privateKey->checkInt1 != privateKey->checkInt2)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Decode key format identifier
   error = sshParseString(data, length, &privateKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&privateKey->keyFormatId, "ssh-ed25519"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->keyFormatId.length;
   length -= sizeof(uint32_t) + privateKey->keyFormatId.length;

   //Parse Ed25519 public key
   error = sshParseBinaryString(data, length, &privateKey->q);
   //Any error to report?
   if(error)
      return error;

   //The public key shall consist of 32 octets
   if(privateKey->q.length != ED25519_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->q.length;
   length -= sizeof(uint32_t) + privateKey->q.length;

   //Parse Ed25519 private key
   error = sshParseBinaryString(data, length, &privateKey->d);
   //Any error to report?
   if(error)
      return error;

   //The private key shall consist of 64 octets
   if(privateKey->d.length != (ED25519_PRIVATE_KEY_LEN + ED25519_PUBLIC_KEY_LEN))
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->d.length;
   length -= sizeof(uint32_t) + privateKey->d.length;

   //The private key is followed by a comment
   error = sshParseString(data, length, &privateKey->comment);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->comment.length;
   length -= sizeof(uint32_t) + privateKey->comment.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse Ed448 private key blob (OpenSSH format)
 * @param[in] data Pointer to the private key blob
 * @param[in] length Length of the private key blob, in bytes
 * @param[out] privateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseOpenSshEd448PrivateKey(const uint8_t *data, size_t length,
   SshEddsaPrivateKey *privateKey)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Malformed private key blob?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'checkint' fields
   privateKey->checkInt1 = LOAD32BE(data);
   privateKey->checkInt2 = LOAD32BE(data + 4);

   //Before the key is encrypted, a random integer is assigned to both
   //'checkint' fields so successful decryption can be quickly checked
   //by verifying that both checkint fields hold the same value
   if(privateKey->checkInt1 != privateKey->checkInt2)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Decode key format identifier
   error = sshParseString(data, length, &privateKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&privateKey->keyFormatId, "ssh-ed448"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->keyFormatId.length;
   length -= sizeof(uint32_t) + privateKey->keyFormatId.length;

   //Parse Ed448 public key
   error = sshParseBinaryString(data, length, &privateKey->q);
   //Any error to report?
   if(error)
      return error;

   //The public key shall consist of 57 octets
   if(privateKey->q.length != ED448_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->q.length;
   length -= sizeof(uint32_t) + privateKey->q.length;

   //Parse Ed448 private key
   error = sshParseBinaryString(data, length, &privateKey->d);
   //Any error to report?
   if(error)
      return error;

   //The private key shall consist of 114 octets
   if(privateKey->d.length != (ED448_PRIVATE_KEY_LEN + ED448_PUBLIC_KEY_LEN))
      return ERROR_INVALID_SYNTAX;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->d.length;
   length -= sizeof(uint32_t) + privateKey->d.length;

   //The private key is followed by a comment
   error = sshParseString(data, length, &privateKey->comment);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + privateKey->comment.length;
   length -= sizeof(uint32_t) + privateKey->comment.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
