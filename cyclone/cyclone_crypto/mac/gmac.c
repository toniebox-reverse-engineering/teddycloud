/**
 * @file gmac.c
 * @brief GMAC (Galois Message Authentication Code)
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
 * GMAC is a message authentication code (MAC) based on GCM. Refer to
 * SP 800-38D for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/gmac.h"

//Check crypto library configuration
#if (GMAC_SUPPORT == ENABLED)

//Reduction table
static const uint32_t r[GMAC_TABLE_N] =
{
#if (GMAC_TABLE_W == 4)
   0x00000000, 0x1C200000, 0x38400000, 0x24600000, 0x70800000, 0x6CA00000, 0x48C00000, 0x54E00000,
   0xE1000000, 0xFD200000, 0xD9400000, 0xC5600000, 0x91800000, 0x8DA00000, 0xA9C00000, 0xB5E00000
#else
   0x00000000, 0x01C20000, 0x03840000, 0x02460000, 0x07080000, 0x06CA0000, 0x048C0000, 0x054E0000,
   0x0E100000, 0x0FD20000, 0x0D940000, 0x0C560000, 0x09180000, 0x08DA0000, 0x0A9C0000, 0x0B5E0000,
   0x1C200000, 0x1DE20000, 0x1FA40000, 0x1E660000, 0x1B280000, 0x1AEA0000, 0x18AC0000, 0x196E0000,
   0x12300000, 0x13F20000, 0x11B40000, 0x10760000, 0x15380000, 0x14FA0000, 0x16BC0000, 0x177E0000,
   0x38400000, 0x39820000, 0x3BC40000, 0x3A060000, 0x3F480000, 0x3E8A0000, 0x3CCC0000, 0x3D0E0000,
   0x36500000, 0x37920000, 0x35D40000, 0x34160000, 0x31580000, 0x309A0000, 0x32DC0000, 0x331E0000,
   0x24600000, 0x25A20000, 0x27E40000, 0x26260000, 0x23680000, 0x22AA0000, 0x20EC0000, 0x212E0000,
   0x2A700000, 0x2BB20000, 0x29F40000, 0x28360000, 0x2D780000, 0x2CBA0000, 0x2EFC0000, 0x2F3E0000,
   0x70800000, 0x71420000, 0x73040000, 0x72C60000, 0x77880000, 0x764A0000, 0x740C0000, 0x75CE0000,
   0x7E900000, 0x7F520000, 0x7D140000, 0x7CD60000, 0x79980000, 0x785A0000, 0x7A1C0000, 0x7BDE0000,
   0x6CA00000, 0x6D620000, 0x6F240000, 0x6EE60000, 0x6BA80000, 0x6A6A0000, 0x682C0000, 0x69EE0000,
   0x62B00000, 0x63720000, 0x61340000, 0x60F60000, 0x65B80000, 0x647A0000, 0x663C0000, 0x67FE0000,
   0x48C00000, 0x49020000, 0x4B440000, 0x4A860000, 0x4FC80000, 0x4E0A0000, 0x4C4C0000, 0x4D8E0000,
   0x46D00000, 0x47120000, 0x45540000, 0x44960000, 0x41D80000, 0x401A0000, 0x425C0000, 0x439E0000,
   0x54E00000, 0x55220000, 0x57640000, 0x56A60000, 0x53E80000, 0x522A0000, 0x506C0000, 0x51AE0000,
   0x5AF00000, 0x5B320000, 0x59740000, 0x58B60000, 0x5DF80000, 0x5C3A0000, 0x5E7C0000, 0x5FBE0000,
   0xE1000000, 0xE0C20000, 0xE2840000, 0xE3460000, 0xE6080000, 0xE7CA0000, 0xE58C0000, 0xE44E0000,
   0xEF100000, 0xEED20000, 0xEC940000, 0xED560000, 0xE8180000, 0xE9DA0000, 0xEB9C0000, 0xEA5E0000,
   0xFD200000, 0xFCE20000, 0xFEA40000, 0xFF660000, 0xFA280000, 0xFBEA0000, 0xF9AC0000, 0xF86E0000,
   0xF3300000, 0xF2F20000, 0xF0B40000, 0xF1760000, 0xF4380000, 0xF5FA0000, 0xF7BC0000, 0xF67E0000,
   0xD9400000, 0xD8820000, 0xDAC40000, 0xDB060000, 0xDE480000, 0xDF8A0000, 0xDDCC0000, 0xDC0E0000,
   0xD7500000, 0xD6920000, 0xD4D40000, 0xD5160000, 0xD0580000, 0xD19A0000, 0xD3DC0000, 0xD21E0000,
   0xC5600000, 0xC4A20000, 0xC6E40000, 0xC7260000, 0xC2680000, 0xC3AA0000, 0xC1EC0000, 0xC02E0000,
   0xCB700000, 0xCAB20000, 0xC8F40000, 0xC9360000, 0xCC780000, 0xCDBA0000, 0xCFFC0000, 0xCE3E0000,
   0x91800000, 0x90420000, 0x92040000, 0x93C60000, 0x96880000, 0x974A0000, 0x950C0000, 0x94CE0000,
   0x9F900000, 0x9E520000, 0x9C140000, 0x9DD60000, 0x98980000, 0x995A0000, 0x9B1C0000, 0x9ADE0000,
   0x8DA00000, 0x8C620000, 0x8E240000, 0x8FE60000, 0x8AA80000, 0x8B6A0000, 0x892C0000, 0x88EE0000,
   0x83B00000, 0x82720000, 0x80340000, 0x81F60000, 0x84B80000, 0x857A0000, 0x873C0000, 0x86FE0000,
   0xA9C00000, 0xA8020000, 0xAA440000, 0xAB860000, 0xAEC80000, 0xAF0A0000, 0xAD4C0000, 0xAC8E0000,
   0xA7D00000, 0xA6120000, 0xA4540000, 0xA5960000, 0xA0D80000, 0xA11A0000, 0xA35C0000, 0xA29E0000,
   0xB5E00000, 0xB4220000, 0xB6640000, 0xB7A60000, 0xB2E80000, 0xB32A0000, 0xB16C0000, 0xB0AE0000,
   0xBBF00000, 0xBA320000, 0xB8740000, 0xB9B60000, 0xBCF80000, 0xBD3A0000, 0xBF7C0000, 0xBEBE0000
#endif
};


/**
 * @brief Compute GMAC using the specified cipher algorithm
 * @param[in] cipher Cipher algorithm used to compute GMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] data Pointer to the input message
 * @param[in] dataLen Length of the input data
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t gmacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const uint8_t *iv, size_t ivLen, const void *data, size_t dataLen,
   uint8_t *mac, size_t macLen)
{
   error_t error;
   GmacContext *context;

   //Allocate a memory buffer to hold the GMAC context
   context = cryptoAllocMem(sizeof(GmacContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the GMAC context
      error = gmacInit(context, cipher, key, keyLen);

      //Check status code
      if(!error)
      {
         //Reset GMAC context
         error = gmacReset(context, iv, ivLen);
      }

      //Check status code
      if(!error)
      {
         //Digest the message
         gmacUpdate(context, data, dataLen);
         //Finalize the GMAC computation
         error = gmacFinal(context, mac, macLen);
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
 * @brief Initialize GMAC calculation
 * @param[in] context Pointer to the GMAC context to initialize
 * @param[in] cipher Cipher algorithm used to compute GMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @return Error code
 **/

error_t gmacInit(GmacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint32_t c;
   uint32_t h[4];

   //Check parameters
   if(context == NULL || cipher == NULL)
      return ERROR_INVALID_PARAMETER;

   //GMAC supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Cipher algorithm used to compute GMAC
   context->cipher = cipher;

   //Initialize cipher context
   error = cipher->init(&context->cipherContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Let H = 0
   h[0] = 0;
   h[1] = 0;
   h[2] = 0;
   h[3] = 0;

   //Generate the hash subkey H
   context->cipher->encryptBlock(&context->cipherContext, (uint8_t *) h,
      (uint8_t *) h);

   //Pre-compute M(0) = H * 0
   j = GMAC_REVERSE_BITS(0);
   context->m[j][0] = 0;
   context->m[j][1] = 0;
   context->m[j][2] = 0;
   context->m[j][3] = 0;

   //Pre-compute M(1) = H * 1
   j = GMAC_REVERSE_BITS(1);
   context->m[j][0] = betoh32(h[3]);
   context->m[j][1] = betoh32(h[2]);
   context->m[j][2] = betoh32(h[1]);
   context->m[j][3] = betoh32(h[0]);

   //Pre-compute all multiples of H (Shoup's method)
   for(i = 2; i < GMAC_TABLE_N; i++)
   {
      //Odd value?
      if((i & 1) != 0)
      {
         //Compute M(i) = M(i - 1) + H
         j = GMAC_REVERSE_BITS(i - 1);
         h[0] = context->m[j][0];
         h[1] = context->m[j][1];
         h[2] = context->m[j][2];
         h[3] = context->m[j][3];

         //An addition in GF(2^128) is identical to a bitwise exclusive-OR
         //operation
         j = GMAC_REVERSE_BITS(1);
         h[0] ^= context->m[j][0];
         h[1] ^= context->m[j][1];
         h[2] ^= context->m[j][2];
         h[3] ^= context->m[j][3];
      }
      else
      {
         //Compute M(i) = M(i / 2) * x
         j = GMAC_REVERSE_BITS(i / 2);
         h[0] = context->m[j][0];
         h[1] = context->m[j][1];
         h[2] = context->m[j][2];
         h[3] = context->m[j][3];

         //The multiplication of a polynomial by x in GF(2^128) corresponds
         //to a shift of indices
         c = h[0] & 0x01;
         h[0] = (h[0] >> 1) | (h[1] << 31);
         h[1] = (h[1] >> 1) | (h[2] << 31);
         h[2] = (h[2] >> 1) | (h[3] << 31);
         h[3] >>= 1;

         //If the highest term of the result is equal to one, then perform
         //reduction
         h[3] ^= r[GMAC_REVERSE_BITS(1)] & ~(c - 1);
      }

      //Save M(i)
      j = GMAC_REVERSE_BITS(i);
      context->m[j][0] = h[0];
      context->m[j][1] = h[1];
      context->m[j][2] = h[2];
      context->m[j][3] = h[3];
   }

   //Clear input buffer
   osMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;
   //Total number of bytes
   context->totalLength = 0;

   //Initialize MAC value
   osMemset(context->mac, 0, context->cipher->blockSize);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Reset GMAC context
 * @param[in] context Pointer to the GMAC context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @return Error code
 **/

error_t gmacReset(GmacContext *context, const uint8_t *iv, size_t ivLen)
{
   size_t k;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is
      //appended to the IV to form the pre-counter block
      osMemcpy(j, iv, 12);
      STORE32BE(1, j + 12);
   }
   else
   {
      //Initialize GHASH calculation
      osMemset(j, 0, 16);

      //Length of the IV
      n = ivLen;

      //Process the initialization vector
      while(n > 0)
      {
         //The IV processed in a block-by-block fashion
         k = MIN(n, 16);

         //Apply GHASH function
         gmacXorBlock(j, j, iv, k);
         gmacMul(context, j);

         //Next block
         iv += k;
         n -= k;
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      osMemset(b, 0, 8);
      STORE64BE(ivLen * 8, b + 8);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      gmacXorBlock(j, j, b, 16);
      gmacMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipher->encryptBlock(&context->cipherContext, j, b);
   osMemcpy(context->mac, b, 16);

   //Initialize GHASH calculation
   osMemset(context->s, 0, 16);

   //Clear input buffer
   osMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Update the GMAC context with a portion of the message being hashed
 * @param[in] context Pointer to the GMAC context
 * @param[in] data Pointer to the input data
 * @param[in] dataLen Length of the buffer
 **/

void gmacUpdate(GmacContext *context, const void *data, size_t dataLen)
{
   size_t n;

   //Process the incoming data
   while(dataLen > 0)
   {
      //The message is partitioned into complete blocks
      n = MIN(dataLen, 16 - context->bufferLength);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->bufferLength, data, n);
      //Update the length of the buffer
      context->bufferLength += n;
      //Update the total number of bytes
      context->totalLength += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      dataLen -= n;

      //Process message block by block
      if(context->bufferLength == 16)
      {
         //Apply GHASH function
         gmacXorBlock(context->s, context->s, context->buffer, 16);
         gmacMul(context, context->s);

         //Empty the buffer
         context->bufferLength = 0;
      }
   }
}


/**
 * @brief Finish the GMAC calculation
 * @param[in] context Pointer to the GMAC context
 * @param[out] mac Calculated MAC value (optional parameter)
 * @param[in] macLen Expected length of the MAC
 **/

error_t gmacFinal(GmacContext *context, uint8_t *mac, size_t macLen)
{
   //Make sure the GMAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the MAC
   if(macLen < 4 || macLen > 16)
      return ERROR_INVALID_PARAMETER;

   //Process the last block of the message
   if(context->bufferLength > 0)
   {
      //Apply GHASH function
      gmacXorBlock(context->s, context->s, context->buffer, context->bufferLength);
      gmacMul(context, context->s);
   }

   //Append the 64-bit representation of the length of the message followed
   //by 64 additional 0 bits
   STORE64BE(context->totalLength * 8, context->buffer);
   osMemset(context->buffer + 8, 0, 8);

   //The GHASH function is applied to the result to produce a single output block S
   gmacXorBlock(context->s, context->s, context->buffer, 16);
   gmacMul(context, context->s);

   //Let T = GCTR(J(0), S)
   gmacXorBlock(context->mac, context->mac, context->s, 16);

   //Copy the resulting MAC value
   if(mac != NULL)
   {
      //Output MSB(T)
      osMemcpy(mac, context->mac, macLen);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Multiplication operation in GF(2^128)
 * @param[in] context Pointer to the GMAC context
 * @param[in, out] x 16-byte block to be multiplied by H
 **/

void gmacMul(GmacContext *context, uint8_t *x)
{
   int_t i;
   uint8_t b;
   uint8_t c;
   uint32_t z[4];

   //Let Z = 0
   z[0] = 0;
   z[1] = 0;
   z[2] = 0;
   z[3] = 0;

   //Fast table-driven implementation (Shoup's method)
   for(i = 15; i >= 0; i--)
   {
#if (GMAC_TABLE_W == 4)
      //Get the lower nibble
      b = x[i] & 0x0F;

      //Multiply 4 bits at a time
      c = z[0] & 0x0F;
      z[0] = (z[0] >> 4) | (z[1] << 28);
      z[1] = (z[1] >> 4) | (z[2] << 28);
      z[2] = (z[2] >> 4) | (z[3] << 28);
      z[3] >>= 4;

      z[0] ^= context->m[b][0];
      z[1] ^= context->m[b][1];
      z[2] ^= context->m[b][2];
      z[3] ^= context->m[b][3];

      //Perform reduction
      z[3] ^= r[c];

      //Get the upper nibble
      b = (x[i] >> 4) & 0x0F;

      //Multiply 4 bits at a time
      c = z[0] & 0x0F;
      z[0] = (z[0] >> 4) | (z[1] << 28);
      z[1] = (z[1] >> 4) | (z[2] << 28);
      z[2] = (z[2] >> 4) | (z[3] << 28);
      z[3] >>= 4;

      z[0] ^= context->m[b][0];
      z[1] ^= context->m[b][1];
      z[2] ^= context->m[b][2];
      z[3] ^= context->m[b][3];

      //Perform reduction
      z[3] ^= r[c];
#else
      //Get current byte
      b = x[i];

      //Multiply 8 bits at a time
      c = z[0] & 0xFF;
      z[0] = (z[0] >> 8) | (z[1] << 24);
      z[1] = (z[1] >> 8) | (z[2] << 24);
      z[2] = (z[2] >> 8) | (z[3] << 24);
      z[3] >>= 8;

      z[0] ^= context->m[b][0];
      z[1] ^= context->m[b][1];
      z[2] ^= context->m[b][2];
      z[3] ^= context->m[b][3];

      //Perform reduction
      z[3] ^= r[c];
#endif
   }

   //Save the result
   STORE32BE(z[3], x);
   STORE32BE(z[2], x + 4);
   STORE32BE(z[1], x + 8);
   STORE32BE(z[0], x + 12);
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First block
 * @param[in] b Second block
 * @param[in] n Size of the block
 **/

void gmacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
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
 **/

void gmacIncCounter(uint8_t *x)
{
   uint16_t temp;

   //The function increments the right-most 32 bits of the block. The remaining
   //left-most 96 bits remain unchanged
   temp = x[15] + 1;
   x[15] = temp & 0xFF;
   temp = (temp >> 8) + x[14];
   x[14] = temp & 0xFF;
   temp = (temp >> 8) + x[13];
   x[13] = temp & 0xFF;
   temp = (temp >> 8) + x[12];
   x[12] = temp & 0xFF;
}

#endif
