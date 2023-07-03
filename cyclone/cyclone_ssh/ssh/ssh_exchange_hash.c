/**
 * @file ssh_exchange_hash.c
 * @brief Exchange hash calculation
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
#include "ssh/ssh_signature.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Initialize exchange hash
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshInitExchangeHash(SshConnection *connection)
{
   error_t error;
   const char_t *kexAlgo;
   const HashAlgo *hashAlgo;

   //Initialize status code
   error = NO_ERROR;

   //Get the chosen key exchange algorithm
   kexAlgo = connection->kexAlgo;

#if (SSH_SHA1_SUPPORT == ENABLED)
   //Key exchange with SHA-1 as hash?
   if(sshCompareAlgo(kexAlgo, "rsa1024-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group1-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha1"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA224_SUPPORT == ENABLED)
   //Key exchange with SHA-224 as hash?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha224@ssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //Key exchange with SHA-256 as hash?
   if(sshCompareAlgo(kexAlgo, "rsa2048-sha256") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha256") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha256") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp256") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256@libssh.org"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA384_SUPPORT == ENABLED)
   //Key exchange with SHA-384 as hash?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha384@ssh.com") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp384"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //Key exchange with SHA-512 as hash?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group15-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group16-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group17-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group18-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha512@ssh.com") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp521") ||
      sshCompareAlgo(kexAlgo, "curve448-sha512") ||
      sshCompareAlgo(kexAlgo, "sntrup761x25519-sha512@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown key exchange algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      //The hash algorithm for computing the exchange hash is defined by the
      //method name (refer to RFC 4253, section 8)
      connection->hashAlgo = hashAlgo;

      //Initialize exchange hash computation
      hashAlgo->init(&connection->hashContext);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Update exchange hash calculation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] data Pointer to the data block to be hashed
 * @param[in] length Length of the data block, in bytes
 * @return Error code
 **/

error_t sshUpdateExchangeHash(SshConnection *connection, const void *data,
   size_t length)
{
   error_t error;
   uint8_t temp[4];

   //Initialize status code
   error = NO_ERROR;

   //Valid hash algorithm?
   if(connection->hashAlgo != NULL)
   {
      //Encode the length of the data block as a 32-bit big-endian integer
      STORE32BE(length, temp);

      //Digest the length field
      connection->hashAlgo->update(&connection->hashContext, temp, sizeof(temp));
      //Digest the contents of the data block
      connection->hashAlgo->update(&connection->hashContext, data, length);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Update exchange hash calculation (raw data)
 * @param[in] connection Pointer to the SSH connection
 * @param[in] data Pointer to the data block to be hashed
 * @param[in] length Length of the data block, in bytes
 * @return Error code
 **/

error_t sshUpdateExchangeHashRaw(SshConnection *connection, const void *data,
   size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Valid hash algorithm?
   if(connection->hashAlgo != NULL)
   {
      //Digest the contents of the data block
      connection->hashAlgo->update(&connection->hashContext, data, length);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Finalize exchange hash calculation
 * @param[in] connection Pointer to the SSH connection
 * @param[out] digest Buffer where to store the resulting hash value
 * @param[out] digestLen Length of the resulting hash value, in bytes
 * @return Error code
 **/

error_t sshFinalizeExchangeHash(SshConnection *connection, uint8_t *digest,
   size_t *digestLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Valid hash algorithm?
   if(connection->hashAlgo != NULL)
   {
      //Compute H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
      connection->hashAlgo->final(&connection->hashContext, digest);
      //Return the length of the resulting digest
      *digestLen = connection->hashAlgo->digestSize;
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute the signature on the exchange hash
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateExchangeHashSignature(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   error_t error;
   SshHostKey *hostKey;
   SshBinaryString exchangeHash;

   //Compute H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
   error = sshFinalizeExchangeHash(connection, connection->h,
      &connection->hLen);

   //Check status code
   if(!error)
   {
      //First key exchange?
      if(!connection->newKeysSent)
      {
         //The exchange hash H from the first key exchange is used as the session
         //identifier, which is a unique identifier for this connection. Once
         //computed, the session identifier is not changed, even if keys are later
         //re-exchanged (refer to RFC 4253, section 7.2)
         osMemcpy(connection->sessionId, connection->h, connection->hLen);
         connection->sessionIdLen = connection->hLen;
      }

      //Get the currently selected host key
      hostKey = sshGetHostKey(connection);

      //Valid host key?
      if(hostKey != NULL)
      {
         //Get the resulting exchange hash
         exchangeHash.value = connection->h;
         exchangeHash.length = connection->hLen;

         //Compute the signature on the exchange hash
         error = sshGenerateSignature(connection, connection->serverHostKeyAlgo,
            hostKey, NULL, &exchangeHash, p, written);
      }
      else
      {
         //No host key is currently selected
         error = ERROR_INVALID_KEY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify the signature on the exchange hash
 * @param[in] connection Pointer to the SSH connection
 * @param[in] serverHostKey Server's public host key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t sshVerifyExchangeHashSignature(SshConnection *connection,
   const SshBinaryString *serverHostKey, const SshBinaryString *signature)
{
   error_t error;
   SshString serverHostKeyAlgo;
   SshBinaryString exchangeHash;

   //Compute H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
   error = sshFinalizeExchangeHash(connection, connection->h,
      &connection->hLen);

   //Check status code
   if(!error)
   {
      //First key exchange?
      if(!connection->newKeysSent)
      {
         //The exchange hash H from the first key exchange is used as the
         //session identifier, which is a unique identifier for this connection.
         //Once computed, the session identifier is not changed, even if keys
         //are later re-exchanged (refer to RFC 4253, section 7.2)
         osMemcpy(connection->sessionId, connection->h, connection->hLen);
         connection->sessionIdLen = connection->hLen;
      }

      //Get the selected server's host key algorithm
      serverHostKeyAlgo.value = connection->serverHostKeyAlgo;
      serverHostKeyAlgo.length = osStrlen(connection->serverHostKeyAlgo);

      //Get the resulting exchange hash
      exchangeHash.value = connection->h;
      exchangeHash.length = connection->hLen;

      //Verify the signature on the exchange hash
      error = sshVerifySignature(connection, &serverHostKeyAlgo, serverHostKey,
         NULL, &exchangeHash, signature);
   }

   //Return status code
   return error;
}

#endif
