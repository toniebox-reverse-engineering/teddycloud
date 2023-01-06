/**
 * @file chacha20_poly1305.c
 * @brief ChaCha20Poly1305 AEAD
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/chacha.h"
#include "mac/poly1305.h"
#include "aead/chacha20_poly1305.h"
#include "debug.h"

//Check crypto library configuration
#if (CHACHA20_POLY1305_SUPPORT == ENABLED)


/**
 * @brief Authenticated encryption using ChaCha20Poly1305
 * @param[in] k key
 * @param[in] kLen Length of the key
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t MAC resulting from the encryption process
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t chacha20Poly1305Encrypt(const uint8_t *k, size_t kLen,
   const uint8_t *n, size_t nLen, const uint8_t *a, size_t aLen,
   const uint8_t *p, uint8_t *c, size_t length, uint8_t *t, size_t tLen)
{
   error_t error;
   size_t paddingLen;
   ChachaContext chachaContext;
   Poly1305Context poly1305Context;
   uint8_t temp[32];

   //Check the length of the message-authentication code
   if(tLen != 16)
      return ERROR_INVALID_LENGTH;

   //Initialize ChaCha20 context
   error = chachaInit(&chachaContext, 20, k, kLen, n, nLen);
   //Any error to report?
   if(error)
      return error;

   //First, a Poly1305 one-time key is generated from the 256-bit key
   //and nonce
   chachaCipher(&chachaContext, NULL, temp, 32);

   //The other 256 bits of the ChaCha20 block are discarded
   chachaCipher(&chachaContext, NULL, NULL, 32);

   //Next, the ChaCha20 encryption function is called to encrypt the
   //plaintext, using the same key and nonce
   chachaCipher(&chachaContext, p, c, length);

   //Initialize the Poly1305 function with the key calculated above
   poly1305Init(&poly1305Context, temp);

   //Compute MAC over the AAD
   poly1305Update(&poly1305Context, a, aLen);

   //If the length of the AAD is not an integral multiple of 16 bytes,
   //then padding is required
   if((aLen % 16) != 0)
   {
      //Compute the number of padding bytes
      paddingLen = 16 - (aLen % 16);

      //The padding is up to 15 zero bytes, and it brings the total length
      //so far to an integral multiple of 16
      osMemset(temp, 0, paddingLen);

      //Compute MAC over the padding
      poly1305Update(&poly1305Context, temp, paddingLen);
   }

   //Compute MAC over the ciphertext
   poly1305Update(&poly1305Context, c, length);

   //If the length of the ciphertext is not an integral multiple of 16 bytes,
   //then padding is required
   if((length % 16) != 0)
   {
      //Compute the number of padding bytes
      paddingLen = 16 - (length % 16);

      //The padding is up to 15 zero bytes, and it brings the total length
      //so far to an integral multiple of 16
      osMemset(temp, 0, paddingLen);

      //Compute MAC over the padding
      poly1305Update(&poly1305Context, temp, paddingLen);
   }

   //Encode the length of the AAD as a 64-bit little-endian integer
   STORE64LE(aLen, temp);
   //Compute MAC over the length field
   poly1305Update(&poly1305Context, temp, sizeof(uint64_t));

   //Encode the length of the ciphertext as a 64-bit little-endian integer
   STORE64LE(length, temp);
   //Compute MAC over the length field
   poly1305Update(&poly1305Context, temp, sizeof(uint64_t));

   //Compute message-authentication code
   poly1305Final(&poly1305Context, t);

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using ChaCha20Poly1305
 * @param[in] k key
 * @param[in] kLen Length of the key
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t MAC to be verified
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t chacha20Poly1305Decrypt(const uint8_t *k, size_t kLen,
   const uint8_t *n, size_t nLen, const uint8_t *a, size_t aLen,
   const uint8_t *c, uint8_t *p, size_t length, const uint8_t *t, size_t tLen)
{
   error_t error;
   uint8_t mask;
   size_t i;
   size_t paddingLen;
   ChachaContext chachaContext;
   Poly1305Context poly1305Context;
   uint8_t temp[32];

   //Check the length of the message-authentication code
   if(tLen != 16)
      return ERROR_INVALID_LENGTH;

   //Initialize ChaCha20 context
   error = chachaInit(&chachaContext, 20, k, kLen, n, nLen);
   //Any error to report?
   if(error)
      return error;

   //First, a Poly1305 one-time key is generated from the 256-bit key
   //and nonce
   chachaCipher(&chachaContext, NULL, temp, 32);

   //The other 256 bits of the ChaCha20 block are discarded
   chachaCipher(&chachaContext, NULL, NULL, 32);

   //Initialize the Poly1305 function with the key calculated above
   poly1305Init(&poly1305Context, temp);

   //Compute MAC over the AAD
   poly1305Update(&poly1305Context, a, aLen);

   //If the length of the AAD is not an integral multiple of 16 bytes,
   //then padding is required
   if((aLen % 16) != 0)
   {
      //Compute the number of padding bytes
      paddingLen = 16 - (aLen % 16);

      //The padding is up to 15 zero bytes, and it brings the total length
      //so far to an integral multiple of 16
      osMemset(temp, 0, paddingLen);

      //Compute MAC over the padding
      poly1305Update(&poly1305Context, temp, paddingLen);
   }

   //Compute MAC over the ciphertext
   poly1305Update(&poly1305Context, c, length);

   //If the length of the ciphertext is not an integral multiple of 16 bytes,
   //then padding is required
   if((length % 16) != 0)
   {
      //Compute the number of padding bytes
      paddingLen = 16 - (length % 16);

      //The padding is up to 15 zero bytes, and it brings the total length
      //so far to an integral multiple of 16
      osMemset(temp, 0, paddingLen);

      //Compute MAC over the padding
      poly1305Update(&poly1305Context, temp, paddingLen);
   }

   //Encode the length of the AAD as a 64-bit little-endian integer
   STORE64LE(aLen, temp);
   //Compute MAC over the length field
   poly1305Update(&poly1305Context, temp, sizeof(uint64_t));

   //Encode the length of the ciphertext as a 64-bit little-endian integer
   STORE64LE(length, temp);
   //Compute MAC over the length field
   poly1305Update(&poly1305Context, temp, sizeof(uint64_t));

   //Compute message-authentication code
   poly1305Final(&poly1305Context, temp);

   //Finally, we decrypt the ciphertext
   chachaCipher(&chachaContext, c, p, length);

   //The calculated tag is bitwise compared to the received tag. The message
   //is authenticated if and only if the tags match
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= temp[i] ^ t[i];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
