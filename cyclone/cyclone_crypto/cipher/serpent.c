/**
 * @file serpent.c
 * @brief Serpent encryption algorithm
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
 * Serpent is a block cipher algorithm which supports a key size of 128, 192
 * or 256 bits. S-box functions are implemented as per Dag Arne Osvik's
 * paper "Speeding up Serpent"
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/serpent.h"

//Check crypto library configuration
#if (SERPENT_SUPPORT == ENABLED)

//Golden ration
#define PHI 0x9E3779B9

//S-box 0
#define SBOX0(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r3 ^= r0; r4 = r1; \
   r1 &= r3; r4 ^= r2; \
   r1 ^= r0; r0 |= r3; \
   r0 ^= r4; r4 ^= r3; \
   r3 ^= r2; r2 |= r1; \
   r2 ^= r4; r4 = ~r4; \
   r4 |= r1; r1 ^= r3; \
   r1 ^= r4; r3 |= r0; \
   r1 ^= r3; r4 ^= r3; \
   r3 = r0; r0 = r1; r1 = r4; \
}

//Inverse S-box 0
#define SBOX0_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r2 = ~r2; r4 = r1; \
   r1 |= r0; r4 = ~r4; \
   r1 ^= r2; r2 |= r4; \
   r1 ^= r3; r0 ^= r4; \
   r2 ^= r0; r0 &= r3; \
   r4 ^= r0; r0 |= r1; \
   r0 ^= r2; r3 ^= r4; \
   r2 ^= r1; r3 ^= r0; \
   r3 ^= r1; \
   r2 &= r3; \
   r4 ^= r2; \
   r2 = r1; r1 = r4; \
}

//S-box 1
#define SBOX1(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r0 = ~r0; r2 = ~r2; \
   r4 = r0; r0 &= r1; \
   r2 ^= r0; r0 |= r3; \
   r3 ^= r2; r1 ^= r0; \
   r0 ^= r4; r4 |= r1; \
   r1 ^= r3; r2 |= r0; \
   r2 &= r4; r0 ^= r1; \
   r1 &= r2; \
   r1 ^= r0; r0 &= r2; \
   r0 ^= r4; \
   r4 = r0; r0 = r2; r2 = r3; r3 = r1; r1 = r4; \
}

//Inverse S-box 1
#define SBOX1_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r1; r1 ^= r3; \
   r3 &= r1; r4 ^= r2; \
   r3 ^= r0; r0 |= r1; \
   r2 ^= r3; r0 ^= r4; \
   r0 |= r2; r1 ^= r3; \
   r0 ^= r1; r1 |= r3; \
   r1 ^= r0; r4 = ~r4; \
   r4 ^= r1; r1 |= r0; \
   r1 ^= r0; \
   r1 |= r4; \
   r3 ^= r1; \
   r1 = r0; r0 = r4; r4 = r2; r2 = r3; r3 = r4; \
}

//S-box 2
#define SBOX2(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r0; r0 &= r2; \
   r0 ^= r3; r2 ^= r1; \
   r2 ^= r0; r3 |= r4; \
   r3 ^= r1; r4 ^= r2; \
   r1 = r3; r3 |= r4; \
   r3 ^= r0; r0 &= r1; \
   r4 ^= r0; r1 ^= r3; \
   r1 ^= r4; r4 = ~r4; \
   r0 = r2; r2 = r1; r1 = r3; r3 = r4; \
}

//Inverse S-box 2
#define SBOX2_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r2 ^= r3; r3 ^= r0; \
   r4 = r3; r3 &= r2; \
   r3 ^= r1; r1 |= r2; \
   r1 ^= r4; r4 &= r3; \
   r2 ^= r3; r4 &= r0; \
   r4 ^= r2; r2 &= r1; \
   r2 |= r0; r3 = ~r3; \
   r2 ^= r3; r0 ^= r3; \
   r0 &= r1; r3 ^= r4; \
   r3 ^= r0; \
   r0 = r1; r1 = r4; \
}

//S-box 3
#define SBOX3(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r0; r0 |= r3; \
   r3 ^= r1; r1 &= r4; \
   r4 ^= r2; r2 ^= r3; \
   r3 &= r0; r4 |= r1; \
   r3 ^= r4; r0 ^= r1; \
   r4 &= r0; r1 ^= r3; \
   r4 ^= r2; r1 |= r0; \
   r1 ^= r2; r0 ^= r3; \
   r2 = r1; r1 |= r3; \
   r1 ^= r0; \
   r0 = r1; r1 = r2; r2 = r3; r3 = r4; \
}

//Inverse S-box 3
#define SBOX3_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r2; r2 ^= r1; \
   r0 ^= r2; r4 &= r2; \
   r4 ^= r0; r0 &= r1; \
   r1 ^= r3; r3 |= r4; \
   r2 ^= r3; r0 ^= r3; \
   r1 ^= r4; r3 &= r2; \
   r3 ^= r1; r1 ^= r0; \
   r1 |= r2; r0 ^= r3; \
   r1 ^= r4; \
   r0 ^= r1; \
   r4 = r0; r0 = r2; r2 = r3; r3 = r4; \
}

//S-box 4
#define SBOX4(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r1 ^= r3; r3 = ~r3; \
   r2 ^= r3; r3 ^= r0; \
   r4 = r1; r1 &= r3; \
   r1 ^= r2; r4 ^= r3; \
   r0 ^= r4; r2 &= r4; \
   r2 ^= r0; r0 &= r1; \
   r3 ^= r0; r4 |= r1; \
   r4 ^= r0; r0 |= r3; \
   r0 ^= r2; r2 &= r3; \
   r0 = ~r0; r4 ^= r2; \
   r2 = r0; r0 = r1; r1 = r4; \
}


//Inverse S-box 4
#define SBOX4_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r2; r2 &= r3; \
   r2 ^= r1; r1 |= r3; \
   r1 &= r0; r4 ^= r2; \
   r4 ^= r1; r1 &= r2; \
   r0 = ~r0; r3 ^= r4; \
   r1 ^= r3; r3 &= r0; \
   r3 ^= r2; r0 ^= r1; \
   r2 &= r0; r3 ^= r0; \
   r2 ^= r4; \
   r2 |= r3; r3 ^= r0; \
   r2 ^= r1; \
   r1 = r3; r3 = r4; \
}

//S-box 5
#define SBOX5(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r0 ^= r1; r1 ^= r3; \
   r3 = ~r3; r4 = r1; \
   r1 &= r0; r2 ^= r3; \
   r1 ^= r2; r2 |= r4; \
   r4 ^= r3; r3 &= r1; \
   r3 ^= r0; r4 ^= r1; \
   r4 ^= r2; r2 ^= r0; \
   r0 &= r3; r2 = ~r2; \
   r0 ^= r4; r4 |= r3; \
   r2 ^= r4; \
   r4 = r0; r0 = r1; r1 = r3; r3 = r2; r2 = r4; \
}

//Inverse S-box 5
#define SBOX5_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r1 = ~r1; r4 = r3; \
   r2 ^= r1; r3 |= r0; \
   r3 ^= r2; r2 |= r1; \
   r2 &= r0; r4 ^= r3; \
   r2 ^= r4; r4 |= r0; \
   r4 ^= r1; r1 &= r2; \
   r1 ^= r3; r4 ^= r2; \
   r3 &= r4; r4 ^= r1; \
   r3 ^= r4; r4 = ~r4; \
   r3 ^= r0; \
   r0 = r1; r1 = r4; r4 = r2; r2 = r3; r3 = r4; \
}

//S-box 6
#define SBOX6(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r2 = ~r2; r4 = r3; \
   r3 &= r0; r0 ^= r4; \
   r3 ^= r2; r2 |= r4; \
   r1 ^= r3; r2 ^= r0; \
   r0 |= r1; r2 ^= r1; \
   r4 ^= r0; r0 |= r3; \
   r0 ^= r2; r4 ^= r3; \
   r4 ^= r0; r3 = ~r3; \
   r2 &= r4; \
   r2 ^= r3; \
   r3 = r2; r2 = r4; \
}

//Inverse S-box 6
#define SBOX6_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r0 ^= r2; r4 = r2; \
   r2 &= r0; r4 ^= r3; \
   r2 = ~r2; r3 ^= r1; \
   r2 ^= r3; r4 |= r0; \
   r0 ^= r2; r3 ^= r4; \
   r4 ^= r1; r1 &= r3; \
   r1 ^= r0; r0 ^= r3; \
   r0 |= r2; r3 ^= r1; \
   r4 ^= r0; \
   r0 = r1; r1 = r2; r2 = r4; \
}

//S-box 7
#define SBOX7(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r1; r1 |= r2; \
   r1 ^= r3; r4 ^= r2; \
   r2 ^= r1; r3 |= r4; \
   r3 &= r0; r4 ^= r2; \
   r3 ^= r1; r1 |= r4; \
   r1 ^= r0; r0 |= r4; \
   r0 ^= r2; r1 ^= r4; \
   r2 ^= r1; r1 &= r0; \
   r1 ^= r4; r2 = ~r2; \
   r2 |= r0; \
   r4 ^= r2; \
   r2 = r1; r1 = r3; r3 = r0; r0 = r4; \
}

//Inverse S-box 7
#define SBOX7_INV(r0, r1, r2, r3) \
{ \
   uint32_t r4; \
   r4 = r2; r2 ^= r0; \
   r0 &= r3; r4 |= r3; \
   r2 = ~r2; r3 ^= r1; \
   r1 |= r0; r0 ^= r2; \
   r2 &= r4; r3 &= r4; \
   r1 ^= r2; r2 ^= r0; \
   r0 |= r2; r4 ^= r1; \
   r0 ^= r3; r3 ^= r4; \
   r4 |= r0; r3 ^= r2; \
   r4 ^= r2; \
   r2 = r1; r1 = r0; r0 = r3; r3 = r4; \
}

//Linear transformation
#define LT(x0, x1, x2, x3) \
{ \
   x0 = ROL32(x0, 13); \
   x2 = ROL32(x2, 3); \
   x1 ^= x0 ^ x2; \
   x3 ^= x2 ^ (x0 << 3); \
   x1 = ROL32(x1, 1); \
   x3 = ROL32(x3, 7); \
   x0 ^= x1 ^ x3; \
   x2 ^= x3 ^ (x1 << 7); \
   x0 = ROL32(x0, 5); \
   x2 = ROL32(x2, 22); \
}

//Inverse linear transformation
#define LT_INV(x0, x1, x2, x3) \
{ \
   x2 = ROR32(x2, 22); \
   x0 = ROR32(x0, 5); \
   x2 ^= x3 ^ (x1 << 7); \
   x0 ^= x1 ^ x3; \
   x3 = ROR32(x3, 7); \
   x1 = ROR32(x1, 1); \
   x3 ^= x2 ^ (x0 << 3); \
   x1 ^= x0 ^ x2; \
   x2 = ROR32(x2, 3); \
   x0 = ROR32(x0, 13); \
}

//XOR operation
#define XOR(x0, x1, x2, x3, k) \
{ \
   x0 ^= k[0]; \
   x1 ^= k[1]; \
   x2 ^= k[2]; \
   x3 ^= k[3]; \
}

//Encryption round
#define ROUND(n, x0, x1, x2, x3, k) \
{ \
   XOR(x0, x1, x2, x3, k); \
   SBOX##n(x0, x1, x2, x3); \
   LT(x0, x1, x2, x3); \
}

//Decryption round
#define ROUND_INV(n, x0, x1, x2, x3, k) \
{ \
   LT_INV(x0, x1, x2, x3); \
   SBOX##n##_INV(x0, x1, x2, x3); \
   XOR(x0, x1, x2, x3, k); \
}

//Common interface for encryption algorithms
const CipherAlgo serpentCipherAlgo =
{
   "Serpent",
   sizeof(SerpentContext),
   CIPHER_ALGO_TYPE_BLOCK,
   SERPENT_BLOCK_SIZE,
   (CipherAlgoInit) serpentInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) serpentEncryptBlock,
   (CipherAlgoDecryptBlock) serpentDecryptBlock,
   (CipherAlgoDeinit) serpentDeinit
};


/**
 * @brief Key expansion
 * @param[in] context Pointer to the Serpent context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t serpentInit(SerpentContext *context, const uint8_t *key, size_t keyLen)
{
   uint_t i;
   uint32_t t;
   uint32_t *w;
   uint32_t p[8];

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen != 16 && keyLen != 24 && keyLen != 32)
      return ERROR_INVALID_KEY_LENGTH;

   //Determine the number of 32-bit words in the key
   keyLen /= 4;

   //Copy the original key
   for(i = 0; i < keyLen; i++)
   {
      p[i] = LOAD32LE(key + 4 * i);
   }

   //Short keys with less than 256 bits are mapped to full-length keys of 256
   //bits by appending one '1' bit to the MSB end
   if(i < 8)
   {
      p[i++] = 0x00000001;
   }

   //Append as many '0' bits as required to make up 256 bits
   while(i < 8)
   {
      p[i++] = 0;
   }

   //Point to the intermediate prekey
   w = (uint32_t *) context->k;

   //Generate the first 8 words of the prekey
   t = p[0] ^ p[3] ^ p[5] ^ p[7] ^ PHI ^ 0;
   w[0] = ROL32(t, 11);
   t = p[1] ^ p[4] ^ p[6] ^ w[0] ^ PHI ^ 1;
   w[1] = ROL32(t, 11);
   t = p[2] ^ p[5] ^ p[7] ^ w[1] ^ PHI ^ 2;
   w[2] = ROL32(t, 11);
   t = p[3] ^ p[6] ^ w[0] ^ w[2] ^ PHI ^ 3;
   w[3] = ROL32(t, 11);
   t = p[4] ^ p[7] ^ w[1] ^ w[3] ^ PHI ^ 4;
   w[4] = ROL32(t, 11);
   t = p[5] ^ w[0] ^ w[2] ^ w[4] ^ PHI ^ 5;
   w[5] = ROL32(t, 11);
   t = p[6] ^ w[1] ^ w[3] ^ w[5] ^ PHI ^ 6;
   w[6] = ROL32(t, 11);
   t = p[7] ^ w[2] ^ w[4] ^ w[6] ^ PHI ^ 7;
   w[7] = ROL32(t, 11);

   //Expand the prekey using affine recurrence
   for(i = 8; i < 132; i++)
   {
      t = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i;
      w[i] = ROL32(t, 11);
   }

   //The round keys are now calculated from the prekeys using the S-boxes
   for(i = 0; i < 128; i += 32)
   {
      SBOX3(w[i + 0], w[i + 1], w[i + 2], w[i + 3]);
      SBOX2(w[i + 4], w[i + 5], w[i + 6], w[i + 7]);
      SBOX1(w[i + 8], w[i + 9], w[i + 10], w[i + 11]);
      SBOX0(w[i + 12], w[i + 13], w[i + 14], w[i + 15]);
      SBOX7(w[i + 16], w[i + 17], w[i + 18], w[i + 19]);
      SBOX6(w[i + 20], w[i + 21], w[i + 22], w[i + 23]);
      SBOX5(w[i + 24], w[i + 25], w[i + 26], w[i + 27]);
      SBOX4(w[i + 28], w[i + 29], w[i + 30], w[i + 31]);
   }

   //Calculate the last round key
   SBOX3(w[128], w[129], w[130], w[131]);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using Serpent algorithm
 * @param[in] context Pointer to the Serpent context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void serpentEncryptBlock(SerpentContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t r0;
   uint32_t r1;
   uint32_t r2;
   uint32_t r3;

   //The 16 bytes of plaintext are split into 4 words
   r0 = LOAD32LE(input + 0);
   r1 = LOAD32LE(input + 4);
   r2 = LOAD32LE(input + 8);
   r3 = LOAD32LE(input + 12);

   //The 32 rounds use 8 different S-boxes
   for(i = 0; i < 32; i += 8)
   {
      ROUND(0, r0, r1, r2, r3, context->k[i]);
      ROUND(1, r0, r1, r2, r3, context->k[i + 1]);
      ROUND(2, r0, r1, r2, r3, context->k[i + 2]);
      ROUND(3, r0, r1, r2, r3, context->k[i + 3]);
      ROUND(4, r0, r1, r2, r3, context->k[i + 4]);
      ROUND(5, r0, r1, r2, r3, context->k[i + 5]);
      ROUND(6, r0, r1, r2, r3, context->k[i + 6]);
      ROUND(7, r0, r1, r2, r3, context->k[i + 7]);
   }

   //In the last round, the linear transformation is replaced by an additional
   //key mixing
   LT_INV(r0, r1, r2, r3);
   XOR(r0, r1, r2, r3, context->k[32]);

   //The 4 words of ciphertext are then written as 16 bytes
   STORE32LE(r0, output + 0);
   STORE32LE(r1, output + 4);
   STORE32LE(r2, output + 8);
   STORE32LE(r3, output + 12);
}


/**
 * @brief Decrypt a 16-byte block using Serpent algorithm
 * @param[in] context Pointer to the Serpent context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void serpentDecryptBlock(SerpentContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t r0;
   uint32_t r1;
   uint32_t r2;
   uint32_t r3;

   //The 16 bytes of ciphertext are split into 4 words
   r0 = LOAD32LE(input + 0);
   r1 = LOAD32LE(input + 4);
   r2 = LOAD32LE(input + 8);
   r3 = LOAD32LE(input + 12);

   //In the first decryption round, the inverse linear transformation is
   //replaced by an additional key mixing
   XOR(r0, r1, r2, r3, context->k[32]);
   LT(r0, r1, r2, r3);

   //Decryption is different from encryption in that the inverse of the
   //S-boxes must be used in the reverse order, as well as the inverse linear
   //transformation and reverse order of the subkeys
   for(i = 0; i < 32; i += 8)
   {
      ROUND_INV(7, r0, r1, r2, r3, context->k[31 - i]);
      ROUND_INV(6, r0, r1, r2, r3, context->k[30 - i]);
      ROUND_INV(5, r0, r1, r2, r3, context->k[29 - i]);
      ROUND_INV(4, r0, r1, r2, r3, context->k[28 - i]);
      ROUND_INV(3, r0, r1, r2, r3, context->k[27 - i]);
      ROUND_INV(2, r0, r1, r2, r3, context->k[26 - i]);
      ROUND_INV(1, r0, r1, r2, r3, context->k[25 - i]);
      ROUND_INV(0, r0, r1, r2, r3, context->k[24 - i]);
   }

   //The 4 words of plaintext are then written as 16 bytes
   STORE32LE(r0, output + 0);
   STORE32LE(r1, output + 4);
   STORE32LE(r2, output + 8);
   STORE32LE(r3, output + 12);
}


/**
 * @brief Release Serpent context
 * @param[in] context Pointer to the Serpent context
 **/

void serpentDeinit(SerpentContext *context)
{
   //Clear Serpent context
   osMemset(context, 0, sizeof(SerpentContext));
}

#endif
