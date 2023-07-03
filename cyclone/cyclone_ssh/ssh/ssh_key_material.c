/**
 * @file ssh_key_material.c
 * @brief Key material generation
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
#include "ssh/ssh_key_material.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Initialize encryption engine
 * @param[in] connection Pointer to the SSH connection
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine to
 *   be initialized
 * @param[in] encAlgo Selected encryption algorithm (NULL-terminated string)
 * @param[in] macAlgo Selected integrity algorithm (NULL-terminated string)
 * @param[in] x A single character used to derive keys
 * @return Error code
 **/

error_t sshInitEncryptionEngine(SshConnection *connection,
   SshEncryptionEngine *encryptionEngine, const char_t *encAlgo,
   const char_t *macAlgo, uint8_t x)
{
   error_t error;

   //Select the relevant cipher algorithm
   error = sshSelectCipherAlgo(encryptionEngine, encAlgo);
   //Any error to report?
   if(error)
      return error;

   //Select the relevant hash algorithm
   error = sshSelectHashAlgo(encryptionEngine, encAlgo, macAlgo);
   //Any error to report?
   if(error)
      return error;

#if (SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   //Stream cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM)
   {
      //Compute encryption key
      error = sshDeriveKey(connection, x + 2, encryptionEngine->encKey,
         encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Compute integrity key
      error = sshDeriveKey(connection, x + 4, encryptionEngine->macKey,
         encryptionEngine->hashAlgo->digestSize);
      //Any error to report?
      if(error)
         return error;

      //Initialize stream cipher context
      error = encryptionEngine->cipherAlgo->init(&encryptionEngine->cipherContext,
         encryptionEngine->encKey, encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Discard the first 1536 bytes of keystream so as to ensure that the
      //cipher's internal state is thoroughly mixed (refer to RFC 4345,
      //section 1)
      encryptionEngine->cipherAlgo->encryptStream(&encryptionEngine->cipherContext,
         NULL, NULL, 1536);

      //Initialize HMAC context
      encryptionEngine->hmacContext = &connection->hmacContext;
   }
   else
#endif
#if (SSH_CBC_CIPHER_SUPPORT == ENABLED || SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //CBC or CTR block cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CBC ||
      encryptionEngine->cipherMode == CIPHER_MODE_CTR)
   {
      //Compute initial IV
      error = sshDeriveKey(connection, x, encryptionEngine->iv,
         encryptionEngine->cipherAlgo->blockSize);
      //Any error to report?
      if(error)
         return error;

      //Compute encryption key
      error = sshDeriveKey(connection, x + 2, encryptionEngine->encKey,
         encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Compute integrity key
      error = sshDeriveKey(connection, x + 4, encryptionEngine->macKey,
         encryptionEngine->hashAlgo->digestSize);
      //Any error to report?
      if(error)
         return error;

      //Initialize block cipher context
      error = encryptionEngine->cipherAlgo->init(&encryptionEngine->cipherContext,
         encryptionEngine->encKey, encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Initialize HMAC context
      encryptionEngine->hmacContext = &connection->hmacContext;
   }
   else
#endif
#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //AES-GCM requires a 12-octet initial IV
      error = sshDeriveKey(connection, x, encryptionEngine->iv, 12);
      //Any error to report?
      if(error)
         return error;

      //AES-GCM requires a encryption key of either 16 or 32 octets
      error = sshDeriveKey(connection, x + 2, encryptionEngine->encKey,
         encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Because an AEAD algorithm such as AES-GCM uses the encryption key to
      //provide both confidentiality and data integrity, the integrity key is
      //not used with AES-GCM (refer to RFC 5647, section 5.1)
      error = encryptionEngine->cipherAlgo->init(&encryptionEngine->cipherContext,
         encryptionEngine->encKey, encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Initialize GCM context
      error = gcmInit(&encryptionEngine->gcmContext, encryptionEngine->cipherAlgo,
         &encryptionEngine->cipherContext);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //The cipher requires 512 bits of key material as output from the SSH
      //key exchange. This forms two 256 bit keys (K_1 and K_2), used by two
      //separate instances of ChaCha20
      error = sshDeriveKey(connection, x + 2, encryptionEngine->encKey,
         encryptionEngine->encKeyLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      return ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release encryption engine
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 **/

void sshFreeEncryptionEngine(SshEncryptionEngine *encryptionEngine)
{
   //Valid cipher context?
   if(encryptionEngine->cipherAlgo != NULL)
   {
      //Erase cipher context
      encryptionEngine->cipherAlgo->deinit(&encryptionEngine->cipherContext);
   }

#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
   //Erase GCM context
   osMemset(&encryptionEngine->gcmContext, 0, sizeof(GcmContext));
#endif

   //Reset encryption parameters
   encryptionEngine->cipherMode = CIPHER_MODE_NULL;
   encryptionEngine->cipherAlgo = NULL;
   encryptionEngine->hashAlgo = NULL;
   encryptionEngine->hmacContext = NULL;
   encryptionEngine->macSize = 0;
   encryptionEngine->etm = FALSE;

   //Erase IV
   osMemset(encryptionEngine->iv, 0, SSH_MAX_CIPHER_BLOCK_SIZE);

   //Erase encryption key
   osMemset(encryptionEngine->encKey, 0, SSH_MAX_ENC_KEY_SIZE);
   encryptionEngine->encKeyLen = 0;

   //Erase integrity key
   osMemset(encryptionEngine->macKey, 0, SSH_MAX_HASH_DIGEST_SIZE);
}


/**
 * @brief Select the relevant cipher algorithm
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine to
 *   be initialized
 * @param[in] encAlgo Encryption algorithm name
 * @return Error code
 **/

error_t sshSelectCipherAlgo(SshEncryptionEngine *encryptionEngine,
   const char_t *encAlgo)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (SSH_RC4_128_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   //RC4 with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "arcfour128"))
   {
      //This cipher uses RC4 with a 128-bit key (refer to RFC 4345, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_STREAM;
      encryptionEngine->cipherAlgo = RC4_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_RC4_256_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   //RC4 with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "arcfour256"))
   {
      //This cipher uses RC4 with a 256-bit key (refer to RFC 4345, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_STREAM;
      encryptionEngine->cipherAlgo = RC4_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_CAST128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //CAST-128-CBC encryption algorithm?
   if(sshCompareAlgo(encAlgo, "cast128-cbc"))
   {
      //This cipher uses CAST-128 in CBC mode with a 128-bit key (refer to
      //RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = CAST128_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_CAST128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //CAST-128-CTR encryption algorithm?
   if(sshCompareAlgo(encAlgo, "cast128-ctr"))
   {
      //This cipher uses CAST-128 in CTR mode with a 128-bit key (refer to
      //RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = CAST128_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //IDEA-CBC encryption algorithm?
   if(sshCompareAlgo(encAlgo, "idea-cbc"))
   {
      //This cipher uses IDEA in CBC mode (refer to RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = IDEA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //IDEA-CTR encryption algorithm?
   if(sshCompareAlgo(encAlgo, "idea-ctr"))
   {
      //This cipher uses IDEA in CTR mode (refer to RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = IDEA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Blowfish-CBC encryption algorithm?
   if(sshCompareAlgo(encAlgo, "blowfish-cbc"))
   {
      //This cipher uses Blowfish in CBC mode with a 128-bit key (refer to
      //RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = BLOWFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Blowfish-CTR encryption algorithm?
   if(sshCompareAlgo(encAlgo, "blowfish-ctr"))
   {
      //This cipher uses Blowfish in CTR mode with a 256-bit key (refer to
      //RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = BLOWFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //3DES-CBC encryption algorithm?
   if(sshCompareAlgo(encAlgo, "3des-cbc"))
   {
      //This cipher uses Triple DES EDE in CBC mode (refer to RFC 4253,
      //section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = DES3_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //3DES-CTR encryption algorithm?
   if(sshCompareAlgo(encAlgo, "3des-ctr"))
   {
      //This cipher uses Triple DES EDE in CTR mode (refer to RFC 4344,
      //section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = DES3_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //AES-CBC with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes128-cbc"))
   {
      //This cipher uses AES in CBC mode with a 128-bit key (refer to
      //RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //AES-CBC with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes192-cbc"))
   {
      //This cipher uses AES in CBC mode with a 192-bit key (refer to
      //RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //AES-CBC with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes256-cbc"))
   {
      //This cipher uses AES in CBC mode with a 256-bit key (refer to
      //RFC 4253, section 6.3)
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //AES-CTR with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes128-ctr"))
   {
      //This cipher uses AES in CTR mode with a 128-bit key (refer to
      //RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //AES-CTR with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes192-ctr"))
   {
      //This cipher uses AES in CTR mode with a 192-bit key (refer to
      //RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //AES-CTR with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes256-ctr"))
   {
      //This cipher uses AES in CTR mode with a 256-bit key (refer to
      //RFC 4344, section 4)
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_TWOFISH_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Twofish-CBC with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish128-cbc"))
   {
      //This cipher uses Twofish in CBC mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_TWOFISH_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Twofish-CBC with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish192-cbc"))
   {
      //This cipher uses Twofish in CBC mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_TWOFISH_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Twofish-CBC with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish256-cbc") ||
      sshCompareAlgo(encAlgo, "twofish-cbc"))
   {
      //This cipher uses Twofish in CBC mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_TWOFISH_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Twofish-CTR with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish128-ctr"))
   {
      //This cipher uses Twofish in CTR mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_TWOFISH_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Twofish-CTR with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish192-ctr"))
   {
      //This cipher uses Twofish in CTR mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_TWOFISH_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Twofish-CTR with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "twofish256-ctr"))
   {
      //This cipher uses Twofish in CTR mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = TWOFISH_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_SERPENT_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Serpent-CBC with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent128-cbc"))
   {
      //This cipher uses Serpent in CBC mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_SERPENT_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Serpent-CBC with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent192-cbc"))
   {
      //This cipher uses Serpent in CBC mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_SERPENT_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Serpent-CBC with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent256-cbc"))
   {
      //This cipher uses Serpent in CBC mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_SERPENT_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Serpent-CTR with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent128-ctr"))
   {
      //This cipher uses Serpent in CTR mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_SERPENT_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Serpent-CTR with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent192-ctr"))
   {
      //This cipher uses Serpent in CTR mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_SERPENT_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Serpent-CTR with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "serpent256-ctr"))
   {
      //This cipher uses Serpent in CTR mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = SERPENT_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Camellia-CBC with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia128-cbc"))
   {
      //This cipher uses Camellia in CBC mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Camellia-CBC with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia192-cbc"))
   {
      //This cipher uses Camellia in CBC mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //Camellia-CBC with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia256-cbc"))
   {
      //This cipher uses Camellia in CBC mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Camellia-CTR with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia128-ctr"))
   {
      //This cipher uses Camellia in CTR mode with a 128-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Camellia-CTR with 192-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia192-ctr"))
   {
      //This cipher uses Camellia in CTR mode with a 192-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 24;
   }
   else
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //Camellia-CTR with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "camellia256-ctr"))
   {
      //This cipher uses Camellia in CTR mode with a 256-bit key
      encryptionEngine->cipherMode = CIPHER_MODE_CTR;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_SEED_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //SEED-CBC encryption algorithm?
   if(sshCompareAlgo(encAlgo, "seed-cbc@ssh.com"))
   {
      //This cipher uses SEED in CBC mode
      encryptionEngine->cipherMode = CIPHER_MODE_CBC;
      encryptionEngine->cipherAlgo = SEED_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes128-gcm@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes256-gcm@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_AES_128_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_AES_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = AES_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //Camellia-GCM with 128-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_128_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 16;
   }
   else
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //Camellia-GCM with 256-bit key encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_GCM;
      encryptionEngine->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      encryptionEngine->encKeyLen = 32;
   }
   else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 encryption algorithm?
   if(sshCompareAlgo(encAlgo, "chacha20-poly1305@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->cipherMode = CIPHER_MODE_CHACHA20_POLY1305;
      encryptionEngine->cipherAlgo = NULL;
      encryptionEngine->encKeyLen = 64;
   }
   else
#endif
   //Unknown encryption algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_CIPHER_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the relevant hash algorithm
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine to
 *   be initialized
 * @param[in] encAlgo Encryption algorithm name
 * @param[in] macAlgo Integrity algorithm name
 * @return Error code
 **/

error_t sshSelectHashAlgo(SshEncryptionEngine *encryptionEngine,
   const char_t *encAlgo, const char_t *macAlgo)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (SSH_AES_128_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes128-gcm@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes256-gcm@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_AES_128_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_AES_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //Camellia-GCM with 128-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_128_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   //Camellia-GCM with 256-bit key authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 authenticated encryption algorithm?
   if(sshCompareAlgo(encAlgo, "chacha20-poly1305@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      encryptionEngine->hashAlgo = NULL;
      encryptionEngine->macSize = 16;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_SUPPORT == ENABLED)
   //HMAC with MD5 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-md5"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = MD5_HASH_ALGO;
      encryptionEngine->macSize = MD5_DIGEST_SIZE;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with MD5 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-md5-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = MD5_HASH_ALGO;
      encryptionEngine->macSize = MD5_DIGEST_SIZE;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_96_SUPPORT == ENABLED)
   //HMAC with MD5/96 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-md5-96"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = MD5_HASH_ALGO;
      encryptionEngine->macSize = 12;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_96_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with MD5/96 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-md5-96-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = MD5_HASH_ALGO;
      encryptionEngine->macSize = 12;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_RIPEMD160_SUPPORT == ENABLED)
   //HMAC with RIPEMD-160 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-ripemd160") ||
      sshCompareAlgo(macAlgo, "hmac-ripemd160@openssh.com"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = RIPEMD160_HASH_ALGO;
      encryptionEngine->macSize = RIPEMD160_DIGEST_SIZE;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_RIPEMD160_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with RIPEMD-160 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-ripemd160-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = RIPEMD160_HASH_ALGO;
      encryptionEngine->macSize = RIPEMD160_DIGEST_SIZE;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED)
   //HMAC with SHA-1 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-sha1"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = SHA1_HASH_ALGO;
      encryptionEngine->macSize = SHA1_DIGEST_SIZE;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with SHA-1 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-sha1-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = SHA1_HASH_ALGO;
      encryptionEngine->macSize = SHA1_DIGEST_SIZE;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_96_SUPPORT == ENABLED)
   //HMAC with SHA-1/96 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-sha1-96"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = SHA1_HASH_ALGO;
      encryptionEngine->macSize = 12;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_96_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with SHA-1/96 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-sha1-96-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = SHA1_HASH_ALGO;
      encryptionEngine->macSize = 12;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //HMAC with SHA-256 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-sha2-256"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = SHA256_HASH_ALGO;
      encryptionEngine->macSize = SHA256_DIGEST_SIZE;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with SHA-256 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-sha2-256-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = SHA256_HASH_ALGO;
      encryptionEngine->macSize = SHA256_DIGEST_SIZE;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //HMAC with SHA-512 integrity algorithm?
   if(sshCompareAlgo(macAlgo, "hmac-sha2-512"))
   {
      //Select MAC-then-encrypt mode
      encryptionEngine->hashAlgo = SHA512_HASH_ALGO;
      encryptionEngine->macSize = SHA512_DIGEST_SIZE;
      encryptionEngine->etm = FALSE;
   }
   else
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   //HMAC with SHA-512 integrity algorithm (EtM mode)?
   if(sshCompareAlgo(macAlgo, "hmac-sha2-512-etm@openssh.com"))
   {
      //Select encrypt-then-MAC mode
      encryptionEngine->hashAlgo = SHA512_HASH_ALGO;
      encryptionEngine->macSize = SHA512_DIGEST_SIZE;
      encryptionEngine->etm = TRUE;
   }
   else
#endif
   //Unknown integrity algorithm?
   {
      //Report an error
      return ERROR_UNSUPPORTED_HASH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Key derivation function
 * @param[in] connection Pointer to the SSH connection
 * @param[in] x A single character
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t sshDeriveKey(SshConnection *connection, uint8_t x, uint8_t *output,
   size_t outputLen)
{
   error_t error;
   size_t i;
   size_t n;
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //Each key exchange method specifies a hash function that is used in the key
   //exchange. The same hash algorithm must be used in key derivation (refer to
   //RFC 4253, section 7.2)
   hashAlgo = connection->hashAlgo;

   //Make sure the hash algorithm is valid
   if(hashAlgo != NULL)
   {
      //Allocate a memory buffer to hold the hash context
      hashContext = sshAllocMem(hashAlgo->contextSize);

      //Successful memory allocation?
      if(hashContext != NULL)
      {
         //Compute K(1) = HASH(K || H || X || session_id)
         hashAlgo->init(hashContext);
         hashAlgo->update(hashContext, connection->k, connection->kLen);
         hashAlgo->update(hashContext, connection->h, connection->hLen);
         hashAlgo->update(hashContext, &x, sizeof(x));
         hashAlgo->update(hashContext, connection->sessionId, connection->sessionIdLen);
         hashAlgo->final(hashContext, NULL);

         //Key data must be taken from the beginning of the hash output
         for(n = 0; n < hashAlgo->digestSize && n < outputLen; n++)
         {
            output[n] = hashContext->digest[n];
         }

         //If the key length needed is longer than the output of the HASH, the key
         //is extended by computing HASH of the concatenation of K and H and the
         //entire key so far, and appending the resulting bytes to the key
         while(n < outputLen)
         {
            //Compute K(n + 1) = HASH(K || H || K(1) || ... || K(n))
            hashAlgo->init(hashContext);
            hashAlgo->update(hashContext, connection->k, connection->kLen);
            hashAlgo->update(hashContext, connection->h, connection->hLen);
            hashAlgo->update(hashContext, output, n);
            hashAlgo->final(hashContext, NULL);

            //This process is repeated until enough key material is available
            for(i = 0; i < hashAlgo->digestSize && n < outputLen; i++, n++)
            {
               output[n] = hashContext->digest[i];
            }
         }

         //Release hash context
         sshFreeMem(hashContext);

         //Successful processing
         error = NO_ERROR;
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The hash algorithm is not valid
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
