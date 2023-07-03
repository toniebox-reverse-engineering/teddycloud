/**
 * @file rc2.c
 * @brief RC2 block cipher
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
 * RC2 is a block encryption algorithm, which may be considered as a proposal
 * for a DES replacement. The input and output block sizes are 64 bits each.
 * The key size is variable, from one byte up to 128 bytes. Refer to RFC 2268
 * for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/rc2.h"
#include "debug.h"

//Check crypto library configuration
#if (RC2_SUPPORT == ENABLED)

//PITABLE array
static uint8_t piTable[256] =
{
   0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
   0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
   0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
   0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
   0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
   0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
   0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
   0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
   0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
   0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
   0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
   0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
   0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
   0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
   0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
   0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD
};

//Common interface for encryption algorithms
const CipherAlgo rc2CipherAlgo =
{
   "RC2",
   sizeof(Rc2Context),
   CIPHER_ALGO_TYPE_BLOCK,
   RC2_BLOCK_SIZE,
   (CipherAlgoInit) rc2Init,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) rc2EncryptBlock,
   (CipherAlgoDecryptBlock) rc2DecryptBlock,
   (CipherAlgoDeinit) rc2Deinit
};


/**
 * @brief Initialize a RC2 context using the supplied key
 * @param[in] context Pointer to the RC2 context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t rc2Init(Rc2Context *context, const uint8_t *key, size_t keyLen)
{
   //Initialize a RC2 context
   return rc2InitEx(context, key, keyLen, keyLen * 8);
}


/**
 * @brief Initialize a RC2 context using the supplied key
 * @param[in] context Pointer to the RC2 context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (T)
 * @param[in] effectiveKeyLen Maximum effective key length, in bits (T1)
 * @return Error code
 **/

error_t rc2InitEx(Rc2Context *context, const uint8_t *key, size_t keyLen,
   uint_t effectiveKeyLen)
{
   uint_t i;
   uint_t t8;
   uint8_t tm;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the key length is acceptable
   if(keyLen < 1 || keyLen > 128)
      return ERROR_INVALID_KEY_LENGTH;

   //Make sure the maximum effective key length is acceptable
   if(effectiveKeyLen < 1 || effectiveKeyLen > 1024)
      return ERROR_INVALID_KEY_LENGTH;

   //The key expansion algorithm begins by placing the supplied T-byte key
   //into bytes L[0], ..., L[T-1] of the key buffer
   osMemcpy(context->l, key, keyLen);

   //The key expansion algorithm then computes the effective key length in
   //bytes T8
   t8 = (effectiveKeyLen + 7) / 8;

   //The mask TM has its 8 - (8*T8 - T1) least significant bits set
   tm = 0xFF >> (8 * t8 - effectiveKeyLen);

   //First loop of the key expansion operation
   for(i = keyLen; i < 128; i++)
   {
      context->l[i] = piTable[(context->l[i - 1] + context->l[i - keyLen]) & 0xFF];
   }

   //The intermediate step's bitwise AND operation reduces the search space
   //for L[128-T8] so that the effective number of key bits is T1
   context->l[128 - t8] = piTable[context->l[128 - t8] & tm];

   //Second loop of the key expansion operation
   for(i = 128 - t8; i > 0; i--)
   {
      context->l[i - 1] = piTable[context->l[i] ^ context->l[i + t8 - 1]];
   }

   //The low-order byte of each K word is given before the high-order byte
   for(i = 0; i < 64; i++)
   {
      context->k[i] = letoh16(context->k[i]);
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using RC2 algorithm
 * @param[in] context Pointer to the RC2 context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void rc2EncryptBlock(Rc2Context *context, const uint8_t *input,
   uint8_t *output)
{
   int_t i;
   uint16_t r0;
   uint16_t r1;
   uint16_t r2;
   uint16_t r3;

   //The plaintext is divided into four 16-bit registers
   r0 = LOAD16LE(input + 0);
   r1 = LOAD16LE(input + 2);
   r2 = LOAD16LE(input + 4);
   r3 = LOAD16LE(input + 6);

   //Apply 16 rounds
   for(i = 0; i < 16; i++)
   {
      //Perform mixing round
      r0 += (r1 & ~r3) + (r2 & r3) + context->k[i * 4];
      r0 = ROL16(r0, 1);
      r1 += (r2 & ~r0) + (r3 & r0) + context->k[i * 4 + 1];
      r1 = ROL16(r1, 2);
      r2 += (r3 & ~r1) + (r0 & r1) + context->k[i * 4 + 2];
      r2 = ROL16(r2, 3);
      r3 += (r0 & ~r2) + (r1 & r2) + context->k[i * 4 + 3];
      r3 = ROL16(r3, 5);

      //5th and 11th rounds require special processing
      if(i == 4 || i == 10)
      {
         //Perform mashing round
         r0 += context->k[r3 % 64];
         r1 += context->k[r0 % 64];
         r2 += context->k[r1 % 64];
         r3 += context->k[r2 % 64];
      }
   }

   //The resulting value is the ciphertext
   STORE16LE(r0, output + 0);
   STORE16LE(r1, output + 2);
   STORE16LE(r2, output + 4);
   STORE16LE(r3, output + 6);
}


/**
 * @brief Decrypt a 8-byte block using RC2 algorithm
 * @param[in] context Pointer to the RC2 context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void rc2DecryptBlock(Rc2Context *context, const uint8_t *input,
   uint8_t *output)
{
   int_t i;
   uint16_t r0;
   uint16_t r1;
   uint16_t r2;
   uint16_t r3;

   //The ciphertext is divided into four 16-bit registers
   r0 = LOAD16LE(input + 0);
   r1 = LOAD16LE(input + 2);
   r2 = LOAD16LE(input + 4);
   r3 = LOAD16LE(input + 6);

   //Apply 16 rounds
   for(i = 15; i >= 0; i--)
   {
      //Perform r-mixing round
      r3 = ROR16(r3, 5);
      r3 -= (r0 & ~r2) + (r1 & r2) + context->k[i * 4 + 3];
      r2 = ROR16(r2, 3);
      r2 -= (r3 & ~r1) + (r0 & r1) + context->k[i * 4 + 2];
      r1 = ROR16(r1, 2);
      r1 -= (r2 & ~r0) + (r3 & r0) + context->k[i * 4 + 1];
      r0 = ROR16(r0, 1);
      r0 -= (r1 & ~r3) + (r2 & r3) + context->k[i * 4];

      //5th and 11th rounds require special processing
      if(i == 5 || i == 11)
      {
         //Perform r-mashing round
         r3 -= context->k[r2 % 64];
         r2 -= context->k[r1 % 64];
         r1 -= context->k[r0 % 64];
         r0 -= context->k[r3 % 64];
      }
   }

   //The resulting value is the plaintext
   STORE16LE(r0, output + 0);
   STORE16LE(r1, output + 2);
   STORE16LE(r2, output + 4);
   STORE16LE(r3, output + 6);
}


/**
 * @brief Release RC2 context
 * @param[in] context Pointer to the RC2 context
 **/

void rc2Deinit(Rc2Context *context)
{
   //Clear RC2 context
   osMemset(context, 0, sizeof(Rc2Context));
}

#endif
