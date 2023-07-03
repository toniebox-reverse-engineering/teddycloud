/**
 * @file twofish.c
 * @brief Twofish encryption algorithm
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
#include "cipher/twofish.h"

//Check crypto library configuration
#if (TWOFISH_SUPPORT == ENABLED)

//MDS matrix
static const uint8_t mds[4][4] =
{
   {0x01, 0xEF, 0x5B, 0x5B},
   {0x5B, 0xEF, 0xEF, 0x01},
   {0xEF, 0x5B, 0x01, 0xEF},
   {0xEF, 0x01, 0xEF, 0x5B}
};

//RS matrix
static const uint8_t rs[4][8] =
{
   {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
   {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
   {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
   {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
};

//Permutation table q0
static const uint8_t q0[256] =
{
   0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
   0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
   0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
   0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
   0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
   0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
   0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
   0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
   0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
   0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
   0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
   0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
   0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
   0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
   0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
   0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
};

//Permutation table q1
static const uint8_t q1[256] =
{
   0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
   0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
   0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
   0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
   0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
   0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
   0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
   0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
   0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
   0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
   0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
   0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
   0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
   0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
   0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
   0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
};

//Common interface for encryption algorithms
const CipherAlgo twofishCipherAlgo =
{
   "Twofish",
   sizeof(TwofishContext),
   CIPHER_ALGO_TYPE_BLOCK,
   TWOFISH_BLOCK_SIZE,
   (CipherAlgoInit) twofishInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) twofishEncryptBlock,
   (CipherAlgoDecryptBlock) twofishDecryptBlock,
   (CipherAlgoDeinit) twofishDeinit
};


/**
 * @brief Multiplication in GF(2^8)
 * @param[in] a First operand
 * @param[in] b Second operand
 * @param[in] p Primitive polynomial of degree 8 over GF(2)
 * @return Resulting value
 **/

static uint32_t GF_MUL(uint8_t a, uint8_t b, uint8_t p)
{
   uint_t i;
   uint8_t r;

   //Initialize result
   r = 0;

   //The operand is processed bit by bit
   for(i = 0; i < 8; i++)
   {
      //Check the value of the current bit
      if((b & 0x01) != 0)
      {
         //An addition in GF(2^8) is identical to a bitwise XOR operation
         r ^= a;
      }

      //The multiplication of a polynomial by x in GF(2^8) corresponds
      //to a shift of indices
      if((a & 0x80) != 0)
      {
         a = (a << 1) ^ p;
      }
      else
      {
         a = a << 1;
      }

      //Process next bit
      b = b >> 1;
   }

   //Return the resulting value
   return r;
}


/**
 * @brief Helper subroutine for implementing function h
 * @param[in] x Input value X
 * @param[in] l List L of 32-bit words of length k
 * @param[in] k Length of the list L
 * @param[in] i Index in range 0 to 3
 * @return Output value Z
 **/

static uint32_t H_SUB(uint8_t x, const uint32_t *l, uint_t k, uint_t i)
{
   uint32_t z;

   //This stage is optional
   if(k == 4)
   {
      //The byte is passed through a fixed S-box
      x = (i == 1 || i == 2) ? q0[x] : q1[x];
      //Then resulting value is XORed with a byte derived from the list
      x ^= (l[3] >> (8 * i)) & 0xFF;
   }

   //This stage is optional
   if(k >= 3)
   {
      //The byte is passed through a fixed S-box
      x = (i == 2 || i == 3) ? q0[x] : q1[x];
      //Then resulting value is XORed with a byte derived from the list
      x ^= (l[2] >> (8 * i)) & 0xFF;
   }

   //The following 2 stages are always required
   x = (i == 0 || i == 2) ? q0[x] : q1[x];
   x ^= (l[1] >> (8 * i)) & 0xFF;
   x = (i == 0 || i == 1) ? q0[x] : q1[x];
   x ^= (l[0] >> (8 * i)) & 0xFF;

   //Finally, the byte is once again passed through a fixed S-box
   x = (i == 1 || i == 3) ? q0[x] : q1[x];

   //The resulting value is multiplied by the MDS matrix
   z = GF_MUL(mds[0][i], x, 0x69);
   z |= GF_MUL(mds[1][i], x, 0x69) << 8;
   z |= GF_MUL(mds[2][i], x, 0x69) << 16;
   z |= GF_MUL(mds[3][i], x, 0x69) << 24;

   //Return the resulting value
   return z;
}


/**
 * @brief Function h
 * @param[in] x Input value X
 * @param[in] l List L of 32-bit words of length k
 * @param[in] k Length of the list L
 * @return Output value Z
 **/

static uint32_t H(uint8_t x, const uint32_t *l, uint_t k)
{
   uint_t i;
   uint32_t z;

   //Initialize result
   z = 0;

   //Process each byte of the 32-bit word
   for(i = 0; i < 4; i++)
   {
      z ^= H_SUB(x, l, k, i);
   }

   //Return the resulting value
   return z;
}


/**
 * @brief Key expansion
 * @param[in] context Pointer to the Twofish context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t twofishInit(TwofishContext *context, const uint8_t *key, size_t keyLen)
{
   uint_t i;
   uint_t j;
   uint_t k;
   uint_t n;
   uint32_t a;
   uint32_t b;
   uint32_t me[4];
   uint32_t mo[4];
   uint32_t s[4];

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen != 16 && keyLen != 24 && keyLen != 32)
      return ERROR_INVALID_KEY_LENGTH;

   //Let k = N / 64 where N is the length of the key, in bits
   k = keyLen / 8;

   //The bytes are first converted into 2*k words of 32 bits each and then
   //into two word vectors Me and Mo of length k
   for(i = 0; i < k; i++)
   {
      me[i] = LOAD32LE(key + 8 * i);
      mo[i] = LOAD32LE(key + 8 * i + 4);
   }

   //A third word vector S of length k is derived from the key
   for(i = 0; i < k; i++)
   {
      //Note that S lists the words in reverse order
      s[k - i - 1] = 0;

      //Each result of 4 bytes is interpreted as a 32-bit word
      for(j = 0; j < 4; j++)
      {
         //Take the key bytes in groups of 8, interpreting them as a vector
         //over GF(2^8), and multiplying them by the RS matrix
         for(a = 0, n = 0; n < 8; n++)
         {
            a ^= GF_MUL(rs[j][n], key[8 * i + n], 0x4D);
         }

         //Update current word
         s[k - i - 1] |= a << (8 * j);
      }
   }

   //Generate the key-dependent S-boxes
   for(i = 0; i < 256; i++)
   {
      context->s1[i] = H_SUB(i, s, k, 0);
      context->s2[i] = H_SUB(i, s, k, 1);
      context->s3[i] = H_SUB(i, s, k, 2);
      context->s4[i] = H_SUB(i, s, k, 3);
   }

   //Generate the expanded key words K
   for(i = 0; i < 20; i++)
   {
      //The words of the expanded key are defined using the h function
      a = H(2 * i, me, k);
      b = H(2 * i + 1, mo, k);
      b = ROL32(b, 8);
      a += b;
      context->k[2 * i] = a;
      a += b;
      context->k[2 * i + 1] = ROL32(a, 9);
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using Twofish algorithm
 * @param[in] context Pointer to the Twofish context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void twofishEncryptBlock(TwofishContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t r0;
   uint32_t r1;
   uint32_t r2;
   uint32_t r3;
   uint32_t t0;
   uint32_t t1;

   //The 16 bytes of plaintext are split into 4 words
   r0 = LOAD32LE(input + 0);
   r1 = LOAD32LE(input + 4);
   r2 = LOAD32LE(input + 8);
   r3 = LOAD32LE(input + 12);

   //In the input whitening step, the data words are XORed with 4 words of
   //the expanded key
   r0 ^= context->k[0];
   r1 ^= context->k[1];
   r2 ^= context->k[2];
   r3 ^= context->k[3];

   //16 rounds of computation are needed
   for(i = 0; i < 32; i += 4)
   {
      //Apply odd round function
      t0 = context->s1[r0 & 0xFF];
      t0 ^= context->s2[(r0 >> 8) & 0xFF];
      t0 ^= context->s3[(r0 >> 16) & 0xFF];
      t0 ^= context->s4[(r0 >> 24) & 0xFF];

      t1 = context->s2[r1 & 0xFF];
      t1 ^= context->s3[(r1 >> 8) & 0xFF];
      t1 ^= context->s4[(r1 >> 16) & 0xFF];
      t1 ^= context->s1[(r1 >> 24) & 0xFF];

      r2 ^= t0 + t1 + context->k[8 + i];
      r2 = ROR32(r2, 1);
      r3 = ROL32(r3, 1);
      r3 ^= (t0 + t1 + t1 + context->k[9 + i]);

      //Apply even round function
      t0 = context->s1[r2 & 0xFF];
      t0 ^= context->s2[(r2 >> 8) & 0xFF];
      t0 ^= context->s3[(r2 >> 16) & 0xFF];
      t0 ^= context->s4[(r2 >> 24) & 0xFF];

      t1 = context->s2[r3 & 0xFF];
      t1 ^= context->s3[(r3 >> 8) & 0xFF];
      t1 ^= context->s4[(r3 >> 16) & 0xFF];
      t1 ^= context->s1[(r3 >> 24) & 0xFF];

      r0 ^= t0 + t1 + context->k[10 + i];
      r0 = ROR32(r0, 1);
      r1 = ROL32(r1, 1);
      r1 ^= (t0 + t1 + t1 + context->k[11 + i]);
   }

   //The output whitening step undoes the swap of the last round, and XORs
   //the data words with 4 words of the expanded key
   r2 ^= context->k[4];
   r3 ^= context->k[5];
   r0 ^= context->k[6];
   r1 ^= context->k[7];

   //The 4 words of ciphertext are then written as 16 bytes
   STORE32LE(r2, output + 0);
   STORE32LE(r3, output + 4);
   STORE32LE(r0, output + 8);
   STORE32LE(r1, output + 12);
}


/**
 * @brief Decrypt a 16-byte block using Twofish algorithm
 * @param[in] context Pointer to the Twofish context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void twofishDecryptBlock(TwofishContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t r0;
   uint32_t r1;
   uint32_t r2;
   uint32_t r3;
   uint32_t t0;
   uint32_t t1;

   //The 16 bytes of ciphertext are split into 4 words
   r2 = LOAD32LE(input + 0);
   r3 = LOAD32LE(input + 4);
   r0 = LOAD32LE(input + 8);
   r1 = LOAD32LE(input + 12);

   //The input whitening step undoes the swap of the last round, and XORs
   //the data words with 4 words of the expanded key
   r2 ^= context->k[4];
   r3 ^= context->k[5];
   r0 ^= context->k[6];
   r1 ^= context->k[7];

   //16 rounds of computation are needed
   for(i = 0; i < 32; i += 4)
   {
      //Apply even round function
      t0 = context->s1[r2 & 0xFF];
      t0 ^= context->s2[(r2 >> 8) & 0xFF];
      t0 ^= context->s3[(r2 >> 16) & 0xFF];
      t0 ^= context->s4[(r2 >> 24) & 0xFF];

      t1 = context->s2[r3 & 0xFF];
      t1 ^= context->s3[(r3 >> 8) & 0xFF];
      t1 ^= context->s4[(r3 >> 16) & 0xFF];
      t1 ^= context->s1[(r3 >> 24) & 0xFF];

      r0 = ROL32(r0, 1);
      r0 ^= t0 + t1 + context->k[38 - i];
      r1 ^= (t0 + t1 + t1 + context->k[39 - i]);
      r1 = ROR32(r1, 1);

      //Apply odd round function
      t0 = context->s1[r0 & 0xFF];
      t0 ^= context->s2[(r0 >> 8) & 0xFF];
      t0 ^= context->s3[(r0 >> 16) & 0xFF];
      t0 ^= context->s4[(r0 >> 24) & 0xFF];

      t1 = context->s2[r1 & 0xFF];
      t1 ^= context->s3[(r1 >> 8) & 0xFF];
      t1 ^= context->s4[(r1 >> 16) & 0xFF];
      t1 ^= context->s1[(r1 >> 24) & 0xFF];

      r2 = ROL32(r2, 1);
      r2 ^= t0 + t1 + context->k[36 - i];
      r3 ^= (t0 + t1 + t1 + context->k[37 - i]);
      r3 = ROR32(r3, 1);
   }

   //In the output whitening step, the data words are XORed with 4 words of
   //the expanded key
   r0 ^= context->k[0];
   r1 ^= context->k[1];
   r2 ^= context->k[2];
   r3 ^= context->k[3];

   //The 4 words of plaintext are then written as 16 bytes
   STORE32LE(r0, output + 0);
   STORE32LE(r1, output + 4);
   STORE32LE(r2, output + 8);
   STORE32LE(r3, output + 12);
}


/**
 * @brief Release Twofish context
 * @param[in] context Pointer to the Twofish context
 **/

void twofishDeinit(TwofishContext *context)
{
   //Clear Twofish context
   osMemset(context, 0, sizeof(TwofishContext));
}

#endif
