/**
 * @file ccm.c
 * @brief Cipher Block Chaining-Message Authentication Code (CCM)
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
 * @section Description
 *
 * CCM mode (Cipher Block Chaining-Message Authentication Code) is a mode of
 * operation for cryptographic block ciphers. It is an authenticated encryption
 * algorithm designed to provide both authentication and confidentiality. CCM
 * mode is only defined for block ciphers with a block length of 128 bits.
 * Refer to SP 800-38D for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "aead/ccm.h"
#include "debug.h"

//Check crypto library configuration
#if (CCM_SUPPORT == ENABLED)


/**
 * @brief Authenticated encryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
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

__weak_func error_t ccmEncrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen)
{
   size_t m;
   size_t q;
   size_t qLen;
   uint8_t b[16];
   uint8_t y[16];
   uint8_t s[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //CCM supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the nonce
   if(nLen < 7 || nLen > 13)
      return ERROR_INVALID_LENGTH;

   //Check the length of the MAC
   if(tLen < 4 || tLen > 16 || (tLen % 2) != 0)
      return ERROR_INVALID_LENGTH;

   //Q is the bit string representation of the octet length of P
   q = length;
   //Compute the octet length of Q
   qLen = 15 - nLen;

   //Format the leading octet of the first block
   b[0] = (aLen > 0) ? 0x40 : 0x00;
   //Encode the octet length of T
   b[0] |= ((tLen - 2) / 2) << 3;
   //Encode the octet length of Q
   b[0] |= qLen - 1;

   //Copy the nonce
   osMemcpy(b + 1, n, nLen);

   //Encode the length field Q
   for(m = 0; m < qLen; m++, q >>= 8)
   {
      b[15 - m] = q & 0xFF;
   }

   //Invalid length?
   if(q != 0)
      return ERROR_INVALID_LENGTH;

   //Set Y(0) = CIPH(B(0))
   cipher->encryptBlock(context, b, y);

   //Any additional data?
   if(aLen > 0)
   {
      //Format the associated data
      osMemset(b, 0, 16);

      //Check the length of the associated data string
      if(aLen < 0xFF00)
      {
         //The length is encoded as 2 octets
         STORE16BE(aLen, b);

         //Number of bytes to copy
         m = MIN(aLen, 16 - 2);
         //Concatenate the associated data A
         osMemcpy(b + 2, a, m);
      }
      else
      {
         //The length is encoded as 6 octets
         b[0] = 0xFF;
         b[1] = 0xFE;

         //MSB is stored first
         STORE32BE(aLen, b + 2);

         //Number of bytes to copy
         m = MIN(aLen, 16 - 6);
         //Concatenate the associated data A
         osMemcpy(b + 6, a, m);
      }

      //XOR B(1) with Y(0)
      ccmXorBlock(y, b, y, 16);
      //Compute Y(1) = CIPH(B(1) ^ Y(0))
      cipher->encryptBlock(context, y, y);

      //Number of remaining data bytes
      aLen -= m;
      a += m;

      //Process the remaining data bytes
      while(aLen > 0)
      {
         //Associated data are processed in a block-by-block fashion
         m = MIN(aLen, 16);

         //XOR B(i) with Y(i-1)
         ccmXorBlock(y, a, y, m);
         //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
         cipher->encryptBlock(context, y, y);

         //Next block
         aLen -= m;
         a += m;
      }
   }

   //Format CTR(0)
   b[0] = (uint8_t) (qLen - 1);
   //Copy the nonce
   osMemcpy(b + 1, n, nLen);
   //Initialize counter value
   osMemset(b + 1 + nLen, 0, qLen);

   //Compute S(0) = CIPH(CTR(0))
   cipher->encryptBlock(context, b, s);
   //Save MSB(S(0))
   osMemcpy(t, s, tLen);

   //Encrypt plaintext
   while(length > 0)
   {
      //The encryption operates in a block-by-block fashion
      m = MIN(length, 16);

      //XOR B(i) with Y(i-1)
      ccmXorBlock(y, p, y, m);
      //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
      cipher->encryptBlock(context, y, y);

      //Increment counter
      ccmIncCounter(b, qLen);
      //Compute S(i) = CIPH(CTR(i))
      cipher->encryptBlock(context, b, s);
      //Compute C(i) = B(i) XOR S(i)
      ccmXorBlock(c, p, s, m);

      //Next block
      length -= m;
      p += m;
      c += m;
   }

   //Compute MAC
   ccmXorBlock(t, t, y, tLen);

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
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

__weak_func error_t ccmDecrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen)
{
   uint8_t mask;
   size_t m;
   size_t q;
   size_t qLen;
   uint8_t b[16];
   uint8_t y[16];
   uint8_t r[16];
   uint8_t s[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //CCM supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the nonce
   if(nLen < 7 || nLen > 13)
      return ERROR_INVALID_LENGTH;

   //Check the length of the MAC
   if(tLen < 4 || tLen > 16 || (tLen % 2) != 0)
      return ERROR_INVALID_LENGTH;

   //Q is the bit string representation of the octet length of C
   q = length;
   //Compute the octet length of Q
   qLen = 15 - nLen;

   //Format the leading octet of the first block
   b[0] = (aLen > 0) ? 0x40 : 0x00;
   //Encode the octet length of T
   b[0] |= ((tLen - 2) / 2) << 3;
   //Encode the octet length of Q
   b[0] |= qLen - 1;

   //Copy the nonce
   osMemcpy(b + 1, n, nLen);

   //Encode the length field Q
   for(m = 0; m < qLen; m++, q >>= 8)
   {
      b[15 - m] = q & 0xFF;
   }

   //Invalid length?
   if(q != 0)
      return ERROR_INVALID_LENGTH;

   //Set Y(0) = CIPH(B(0))
   cipher->encryptBlock(context, b, y);

   //Any additional data?
   if(aLen > 0)
   {
      //Format the associated data
      osMemset(b, 0, 16);

      //Check the length of the associated data string
      if(aLen < 0xFF00)
      {
         //The length is encoded as 2 octets
         STORE16BE(aLen, b);

         //Number of bytes to copy
         m = MIN(aLen, 16 - 2);
         //Concatenate the associated data A
         osMemcpy(b + 2, a, m);
      }
      else
      {
         //The length is encoded as 6 octets
         b[0] = 0xFF;
         b[1] = 0xFE;

         //MSB is stored first
         STORE32BE(aLen, b + 2);

         //Number of bytes to copy
         m = MIN(aLen, 16 - 6);
         //Concatenate the associated data A
         osMemcpy(b + 6, a, m);
      }

      //XOR B(1) with Y(0)
      ccmXorBlock(y, b, y, 16);
      //Compute Y(1) = CIPH(B(1) ^ Y(0))
      cipher->encryptBlock(context, y, y);

      //Number of remaining data bytes
      aLen -= m;
      a += m;

      //Process the remaining data bytes
      while(aLen > 0)
      {
         //Associated data are processed in a block-by-block fashion
         m = MIN(aLen, 16);

         //XOR B(i) with Y(i-1)
         ccmXorBlock(y, a, y, m);
         //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
         cipher->encryptBlock(context, y, y);

         //Next block
         aLen -= m;
         a += m;
      }
   }

   //Format CTR(0)
   b[0] = (uint8_t) (qLen - 1);
   //Copy the nonce
   osMemcpy(b + 1, n, nLen);
   //Initialize counter value
   osMemset(b + 1 + nLen, 0, qLen);

   //Compute S(0) = CIPH(CTR(0))
   cipher->encryptBlock(context, b, s);
   //Save MSB(S(0))
   osMemcpy(r, s, tLen);

   //Decrypt ciphertext
   while(length > 0)
   {
      //The decryption operates in a block-by-block fashion
      m = MIN(length, 16);

      //Increment counter
      ccmIncCounter(b, qLen);
      //Compute S(i) = CIPH(CTR(i))
      cipher->encryptBlock(context, b, s);
      //Compute B(i) = C(i) XOR S(i)
      ccmXorBlock(p, c, s, m);

      //XOR B(i) with Y(i-1)
      ccmXorBlock(y, p, y, m);
      //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
      cipher->encryptBlock(context, y, y);

      //Next block
      length -= m;
      c += m;
      p += m;
   }

   //Compute MAC
   ccmXorBlock(r, r, y, tLen);

   //The calculated tag is bitwise compared to the received tag. The message
   //is authenticated if and only if the tags match
   for(mask = 0, m = 0; m < tLen; m++)
   {
      mask |= r[m] ^ t[m];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First block
 * @param[in] b Second block
 * @param[in] n Size of the block
 **/

void ccmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}


/**
 * @brief Increment counter block
 * @param[in,out] x Pointer to the counter block
 * @param[in] n Size in bytes of the specific part of the block to be incremented
 **/

void ccmIncCounter(uint8_t *x, size_t n)
{
   size_t i;
   uint16_t temp;

   //The function increments the right-most bytes of the block. The remaining
   //left-most bytes remain unchanged
   for(temp = 1, i = 0; i < n; i++)
   {
      //Increment the current byte and propagate the carry
      temp += x[15 - i];
      x[15 - i] = temp & 0xFF;
      temp >>= 8;
   }
}

#endif
