/**
 * @file des.c
 * @brief DES (Data Encryption Standard)
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
 * DES is an encryption algorithm designed to encipher and decipher blocks of
 * 64 bits under control of a 64-bit key. Refer to FIPS 46-3 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/des.h"

//Check crypto library configuration
#if (DES_SUPPORT == ENABLED || DES3_SUPPORT == ENABLED)

//Rotate left operation
#define ROL28(a, n) ((((a) << (n)) | ((a) >> (28 - (n)))) & 0x0FFFFFFF)

//Permutation of bit fields between words (Eric Young's technique)
#define SWAPMOVE(a, b, n, m) \
{ \
   t = ((a >> n) ^ b) & m; \
   b ^= t; \
   a ^= t << n; \
}

//Initial permutation
#define IP(l, r) \
{ \
   SWAPMOVE(l, r, 4, 0x0F0F0F0F); \
   SWAPMOVE(l, r, 16, 0x0000FFFF); \
   SWAPMOVE(r, l, 2, 0x33333333); \
   SWAPMOVE(r, l, 8, 0x00FF00FF); \
   SWAPMOVE(l, r, 1, 0x55555555); \
   l = ROL32(l, 1); \
   r = ROL32(r, 1); \
}

//Inverse of initial permutation
#define IP_INV(l, r) \
{ \
   l = ROR32(l, 1); \
   r = ROR32(r, 1); \
   SWAPMOVE(l, r, 1, 0x55555555); \
   SWAPMOVE(r, l, 8, 0x00FF00FF); \
   SWAPMOVE(r, l, 2, 0x33333333); \
   SWAPMOVE(l, r, 16, 0x0000FFFF); \
   SWAPMOVE(l, r, 4, 0x0F0F0F0F); \
}

//Permuted choice 1
#define PC1(c, d) \
{ \
   SWAPMOVE(c, d, 4, 0x0F0F0F0F); \
   SWAPMOVE(c, d, 16, 0x0000FFFF); \
   SWAPMOVE(d, c, 2, 0x33333333); \
   SWAPMOVE(d, c, 8, 0x00FF00FF); \
   SWAPMOVE(c, d, 1, 0x55555555); \
   SWAPMOVE(d, c, 8, 0x00FF00FF); \
   SWAPMOVE(c, d, 16, 0x0000FFFF); \
   t = (c << 4) & 0x0FFFFFF0; \
   t |= (d >> 24) & 0x0000000F; \
   c = (d << 20) & 0x0FF00000; \
   c |= (d << 4) & 0x000FF000; \
   c |= (d >> 12) & 0x00000FF0; \
   c |= (d >> 28) & 0x0000000F; \
   d = t; \
}

//Permuted choice 2 (first half)
#define PC2_L(c, d) \
   (((c << 4) & 0x24000000) | \
   ((c << 28) & 0x10000000) | \
   ((c << 14) & 0x08000000) | \
   ((c << 18) & 0x02080000) | \
   ((c << 6) & 0x01000000) | \
   ((c << 9) & 0x00200000) | \
   ((c >> 1) & 0x00100000) | \
   ((c << 10) & 0x00040000) | \
   ((c << 2) & 0x00020000) | \
   ((c >> 10) & 0x00010000) | \
   ((d >> 13) & 0x00002000) | \
   ((d >> 4) & 0x00001000) | \
   ((d << 6) & 0x00000800) | \
   ((d >> 1) & 0x00000400) | \
   ((d >> 14) & 0x00000200) | \
   ((d >> 0) & 0x00000100) | \
   ((d >> 5) & 0x00000020) | \
   ((d >> 10) & 0x00000010) | \
   ((d >> 3) & 0x00000008) | \
   ((d >> 18) & 0x00000004) | \
   ((d >> 26) & 0x00000002) | \
   ((d >> 24) & 0x00000001))

//Permuted choice 2 (second half)
#define PC2_R(c, d) \
   (((c << 15) & 0x20000000) | \
   ((c << 17) & 0x10000000) | \
   ((c << 10) & 0x08000000) | \
   ((c << 22) & 0x04000000) | \
   ((c >> 2) & 0x02000000) | \
   ((c << 1) & 0x01000000) | \
   ((c << 16) & 0x00200000) | \
   ((c << 11) & 0x00100000) | \
   ((c << 3) & 0x00080000) | \
   ((c >> 6) & 0x00040000) | \
   ((c << 15) & 0x00020000) | \
   ((c >> 4) & 0x00010000) | \
   ((d >> 2) & 0x00002000) | \
   ((d << 8) & 0x00001000) | \
   ((d >> 14) & 0x00000808) | \
   ((d >> 9) & 0x00000400) | \
   ((d >> 0) & 0x00000200) | \
   ((d << 7) & 0x00000100) | \
   ((d >> 7) & 0x00000020) | \
   ((d >> 3) & 0x00000011) | \
   ((d << 2) & 0x00000004) | \
   ((d >> 21) & 0x00000002))

//Round function
#define ROUND(l, r, k1, k2) \
{ \
   t = r ^ k1; \
   l ^= sp2[(t >> 24) & 0x3F]; \
   l ^= sp4[(t >> 16) & 0x3F]; \
   l ^= sp6[(t >> 8) & 0x3F]; \
   l ^= sp8[t & 0x3F]; \
   t = ROR32(r, 4) ^ k2; \
   l ^= sp1[(t >> 24) & 0x3F]; \
   l ^= sp3[(t >> 16) & 0x3F]; \
   l ^= sp5[(t >> 8) & 0x3F]; \
   l ^= sp7[t & 0x3F]; \
}

//Selection function 1
static const uint32_t sp1[64] =
{
   0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
   0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
   0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
   0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
   0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
   0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
   0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
   0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004
};

//Selection function 2
static const uint32_t sp2[64] =
{
   0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
   0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
   0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
   0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
   0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
   0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
   0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
   0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000
};

//Selection function 3
static const uint32_t sp3[64] =
{
   0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
   0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
   0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
   0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
   0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
   0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
   0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
   0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200
};

//Selection function 4
static const uint32_t sp4[64] =
{
   0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
   0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
   0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
   0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
   0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
   0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
   0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
   0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080
};

//Selection function 5
static const uint32_t sp5[64] =
{
   0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
   0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
   0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
   0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
   0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
   0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
   0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
   0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100
};

//Selection function 6
static const uint32_t sp6[64] =
{
   0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
   0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
   0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
   0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
   0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
   0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
   0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
   0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010
};

//Selection function 7
static const uint32_t sp7[64] =
{
   0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
   0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
   0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
   0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
   0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
   0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
   0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
   0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002
};

//Selection function 8
static const uint32_t sp8[64] =
{
   0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
   0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
   0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
   0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
   0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
   0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
   0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
   0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000
};

//Common interface for encryption algorithms
const CipherAlgo desCipherAlgo =
{
   "DES",
   sizeof(DesContext),
   CIPHER_ALGO_TYPE_BLOCK,
   DES_BLOCK_SIZE,
   (CipherAlgoInit) desInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) desEncryptBlock,
   (CipherAlgoDecryptBlock) desDecryptBlock,
   (CipherAlgoDeinit) desDeinit
};


/**
 * @brief Initialize a DES context using the supplied key
 * @param[in] context Pointer to the DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (must be set to 8)
 * @return Error code
 **/

__weak_func error_t desInit(DesContext *context, const uint8_t *key,
   size_t keyLen)
{
   uint_t i;
   uint32_t c;
   uint32_t d;
   uint32_t t;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 8)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the key
   c = LOAD32BE(key + 0);
   d = LOAD32BE(key + 4);

   //Permuted choice 1
   PC1(c, d);

   //Generate the key schedule
   for(i = 0; i < 16; i++)
   {
      //Individual blocks are shifted left
      if(i == 0 || i == 1 || i == 8 || i == 15)
      {
         c = ROL28(c, 1);
         d = ROL28(d, 1);
      }
      else
      {
         c = ROL28(c, 2);
         d = ROL28(d, 2);
      }

      //Permuted choice 2
      context->ks[2 * i] = PC2_L(c, d);
      context->ks[2 * i + 1] = PC2_R(c, d);
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

__weak_func void desEncryptBlock(DesContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t l;
   uint32_t r;
   uint32_t t;

   //Copy the plaintext from the input buffer
   l = LOAD32BE(input + 0);
   r = LOAD32BE(input + 4);

   //Initial permutation
   IP(l, r);

   //16 rounds of computation are needed
   for(i = 0; i < 32; i += 4)
   {
      //Apply odd round function
      ROUND(l, r, context->ks[i], context->ks[i + 1]);
      //Apply even round function
      ROUND(r, l, context->ks[i + 2], context->ks[i + 3]);
   }

   //Inverse of initial permutation
   IP_INV(r, l);

   //Copy the resulting ciphertext
   STORE32BE(r, output + 0);
   STORE32BE(l, output + 4);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

__weak_func void desDecryptBlock(DesContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t l;
   uint32_t r;
   uint32_t t;

   //Copy the ciphertext from the input buffer
   r = LOAD32BE(input + 0);
   l = LOAD32BE(input + 4);

   //Initial permutation
   IP(r, l);

   //For decryption, keys in the key schedule must be applied in reverse order
   for(i = 32; i > 0; i -= 4)
   {
      //Apply even round function
      ROUND(r, l, context->ks[i - 2], context->ks[i - 1]);
      //Apply odd round function
      ROUND(l, r, context->ks[i - 4], context->ks[i - 3]);
   }

   //Inverse of initial permutation
   IP_INV(l, r);

   //Copy the resulting plaintext
   STORE32BE(l, output + 0);
   STORE32BE(r, output + 4);
}


/**
 * @brief Release DES context
 * @param[in] context Pointer to the DES context
 **/

__weak_func void desDeinit(DesContext *context)
{
   //Clear DES context
   osMemset(context, 0, sizeof(DesContext));
}

#endif
