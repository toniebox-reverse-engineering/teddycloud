/**
 * @file cmac.c
 * @brief CMAC (Cipher-based Message Authentication Code)
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
 * CMAC is a block cipher-based MAC algorithm specified in NIST SP 800-38B
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/cmac.h"

//Check crypto library configuration
#if (CMAC_SUPPORT == ENABLED)


/**
 * @brief Compute CMAC using the specified cipher algorithm
 * @param[in] cipher Cipher algorithm used to compute CMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @param[in] data Pointer to the input message
 * @param[in] dataLen Length of the input data
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t cmacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *mac, size_t macLen)
{
   error_t error;
   CmacContext *context;

   //Allocate a memory buffer to hold the CMAC context
   context = cryptoAllocMem(sizeof(CmacContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the CMAC context
      error = cmacInit(context, cipher, key, keyLen);

      //Check status code
      if(!error)
      {
         //Digest the message
         cmacUpdate(context, data, dataLen);
         //Finalize the CMAC computation
         error = cmacFinal(context, mac, macLen);
      }

      //Free previously allocated memory
      cryptoFreeMem(context);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize CMAC calculation
 * @param[in] context Pointer to the CMAC context to initialize
 * @param[in] cipher Cipher algorithm used to compute CMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @return Error code
 **/

error_t cmacInit(CmacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen)
{
   error_t error;
   uint8_t rb;

   //Check parameters
   if(context == NULL || cipher == NULL)
      return ERROR_INVALID_PARAMETER;

   //CMAC supports only block ciphers whose block size is 64 or 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK)
      return ERROR_INVALID_PARAMETER;

   //Rb is completely determined by the number of bits in a block
   if(cipher->blockSize == 8)
   {
      //If b = 64, then Rb = 11011
      rb = 0x1B;
   }
   else if(cipher->blockSize == 16)
   {
      //If b = 128, then Rb = 10000111
      rb = 0x87;
   }
   else
   {
      //Invalid block size
      return ERROR_INVALID_PARAMETER;
   }

   //Cipher algorithm used to compute CMAC
   context->cipher = cipher;

   //Initialize cipher context
   error = cipher->init(&context->cipherContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Let L = 0
   osMemset(context->buffer, 0, cipher->blockSize);

   //Compute L = CIPH(L)
   cipher->encryptBlock(&context->cipherContext, context->buffer,
      context->buffer);

   //The subkey K1 is obtained by multiplying L by x in GF(2^b)
   cmacMul(context->k1, context->buffer, cipher->blockSize, rb);
   //The subkey K2 is obtained by multiplying L by x^2 in GF(2^b)
   cmacMul(context->k2, context->k1, cipher->blockSize, rb);

   //Reset CMAC context
   cmacReset(context);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Reset CMAC context
 * @param[in] context Pointer to the CMAC context
 **/

void cmacReset(CmacContext *context)
{
   //Clear input buffer
   osMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;

   //Initialize MAC value
   osMemset(context->mac, 0, context->cipher->blockSize);
}


/**
 * @brief Update the CMAC context with a portion of the message being hashed
 * @param[in] context Pointer to the CMAC context
 * @param[in] data Pointer to the input data
 * @param[in] dataLen Length of the buffer
 **/

void cmacUpdate(CmacContext *context, const void *data, size_t dataLen)
{
   size_t n;

   //Process the incoming data
   while(dataLen > 0)
   {
      //Process message block by block
      if(context->bufferLength == context->cipher->blockSize)
      {
         //XOR M(i) with C(i-1)
         cmacXorBlock(context->buffer, context->buffer, context->mac,
            context->cipher->blockSize);

         //Compute C(i) = CIPH(M(i) ^ C(i-1))
         context->cipher->encryptBlock(&context->cipherContext, context->buffer,
            context->mac);

         //Empty the buffer
         context->bufferLength = 0;
      }

      //The message is partitioned into complete blocks
      n = MIN(dataLen, context->cipher->blockSize - context->bufferLength);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->bufferLength, data, n);
      //Update the length of the buffer
      context->bufferLength += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      dataLen -= n;
   }
}


/**
 * @brief Finish the CMAC calculation
 * @param[in] context Pointer to the CMAC context
 * @param[out] mac Calculated MAC value (optional parameter)
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t cmacFinal(CmacContext *context, uint8_t *mac, size_t macLen)
{
   //Make sure the CMAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the MAC
   if(macLen < 1 || macLen > context->cipher->blockSize)
      return ERROR_INVALID_PARAMETER;

   //Check whether the last block Mn is complete
   if(context->bufferLength >= context->cipher->blockSize)
   {
      //The final block M(n) is XOR-ed with the first subkey K1
      cmacXorBlock(context->buffer, context->buffer, context->k1,
         context->cipher->blockSize);
   }
   else
   {
      //Append padding string
      context->buffer[context->bufferLength++] = 0x80;

      //Append the minimum number of zeroes to form a complete block
      while(context->bufferLength < context->cipher->blockSize)
      {
         context->buffer[context->bufferLength++] = 0x00;
      }

      //The final block M(n) is XOR-ed with the second subkey K2
      cmacXorBlock(context->buffer, context->buffer, context->k2,
         context->cipher->blockSize);
   }

   //XOR M(n) with C(n-1)
   cmacXorBlock(context->buffer, context->buffer, context->mac,
      context->cipher->blockSize);

   //Compute T = CIPH(M(n) ^ C(n-1))
   context->cipher->encryptBlock(&context->cipherContext, context->buffer,
      context->mac);

   //Copy the resulting MAC value
   if(mac != NULL)
   {
      //It is possible to truncate the MAC. The result of the truncation
      //should be taken in most significant bits first order
      osMemcpy(mac, context->mac, macLen);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Multiplication by x in GF(2^128)
 * @param[out] x Pointer to the output block
 * @param[out] a Pointer to the input block
 * @param[in] n Size of the block, in bytes
 * @param[in] rb Representation of the irreducible binary polynomial
 **/

void cmacMul(uint8_t *x, const uint8_t *a, size_t n, uint8_t rb)
{
   size_t i;
   uint8_t c;

   //Save the value of the most significant bit
   c = a[0] >> 7;

   //The multiplication of a polynomial by x in GF(2^128) corresponds to a
   //shift of indices
   for(i = 0; i < (n - 1); i++)
   {
      x[i] = (a[i] << 1) | (a[i + 1] >> 7);
   }

   //Shift the last byte of the block to the left
   x[i] = a[i] << 1;

   //If the highest term of the result is equal to one, then perform reduction
   x[i] ^= rb & ~(c - 1);
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First input block
 * @param[in] b Second input block
 * @param[in] n Size of the block, in bytes
 **/

void cmacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}

#endif
