/**
 * @file present.c
 * @brief PRESENT encryption algorithm
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
 * PRESENT is an ultra-lightweight block cipher
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/present.h"

//Check crypto library configuration
#if (PRESENT_SUPPORT == ENABLED)

//S-box
static const uint8_t sbox[16] =
{
   0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02
};

//Inverse S-box
static const uint8_t isbox[256] =
{
   0x55, 0x5E, 0x5F, 0x58, 0x5C, 0x51, 0x52, 0x5D, 0x5B, 0x54, 0x56, 0x53, 0x50, 0x57, 0x59, 0x5A,
   0xE5, 0xEE, 0xEF, 0xE8, 0xEC, 0xE1, 0xE2, 0xED, 0xEB, 0xE4, 0xE6, 0xE3, 0xE0, 0xE7, 0xE9, 0xEA,
   0xF5, 0xFE, 0xFF, 0xF8, 0xFC, 0xF1, 0xF2, 0xFD, 0xFB, 0xF4, 0xF6, 0xF3, 0xF0, 0xF7, 0xF9, 0xFA,
   0x85, 0x8E, 0x8F, 0x88, 0x8C, 0x81, 0x82, 0x8D, 0x8B, 0x84, 0x86, 0x83, 0x80, 0x87, 0x89, 0x8A,
   0xC5, 0xCE, 0xCF, 0xC8, 0xCC, 0xC1, 0xC2, 0xCD, 0xCB, 0xC4, 0xC6, 0xC3, 0xC0, 0xC7, 0xC9, 0xCA,
   0x15, 0x1E, 0x1F, 0x18, 0x1C, 0x11, 0x12, 0x1D, 0x1B, 0x14, 0x16, 0x13, 0x10, 0x17, 0x19, 0x1A,
   0x25, 0x2E, 0x2F, 0x28, 0x2C, 0x21, 0x22, 0x2D, 0x2B, 0x24, 0x26, 0x23, 0x20, 0x27, 0x29, 0x2A,
   0xD5, 0xDE, 0xDF, 0xD8, 0xDC, 0xD1, 0xD2, 0xDD, 0xDB, 0xD4, 0xD6, 0xD3, 0xD0, 0xD7, 0xD9, 0xDA,
   0xB5, 0xBE, 0xBF, 0xB8, 0xBC, 0xB1, 0xB2, 0xBD, 0xBB, 0xB4, 0xB6, 0xB3, 0xB0, 0xB7, 0xB9, 0xBA,
   0x45, 0x4E, 0x4F, 0x48, 0x4C, 0x41, 0x42, 0x4D, 0x4B, 0x44, 0x46, 0x43, 0x40, 0x47, 0x49, 0x4A,
   0x65, 0x6E, 0x6F, 0x68, 0x6C, 0x61, 0x62, 0x6D, 0x6B, 0x64, 0x66, 0x63, 0x60, 0x67, 0x69, 0x6A,
   0x35, 0x3E, 0x3F, 0x38, 0x3C, 0x31, 0x32, 0x3D, 0x3B, 0x34, 0x36, 0x33, 0x30, 0x37, 0x39, 0x3A,
   0x05, 0x0E, 0x0F, 0x08, 0x0C, 0x01, 0x02, 0x0D, 0x0B, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0A,
   0x75, 0x7E, 0x7F, 0x78, 0x7C, 0x71, 0x72, 0x7D, 0x7B, 0x74, 0x76, 0x73, 0x70, 0x77, 0x79, 0x7A,
   0x95, 0x9E, 0x9F, 0x98, 0x9C, 0x91, 0x92, 0x9D, 0x9B, 0x94, 0x96, 0x93, 0x90, 0x97, 0x99, 0x9A,
   0xA5, 0xAE, 0xAF, 0xA8, 0xAC, 0xA1, 0xA2, 0xAD, 0xAB, 0xA4, 0xA6, 0xA3, 0xA0, 0xA7, 0xA9, 0xAA,
};

//Inverse bit permutation
static const uint32_t ipbox[256] =
{
   0x00000000, 0x00000001, 0x00000010, 0x00000011, 0x00000100, 0x00000101, 0x00000110, 0x00000111,
   0x00001000, 0x00001001, 0x00001010, 0x00001011, 0x00001100, 0x00001101, 0x00001110, 0x00001111,
   0x00010000, 0x00010001, 0x00010010, 0x00010011, 0x00010100, 0x00010101, 0x00010110, 0x00010111,
   0x00011000, 0x00011001, 0x00011010, 0x00011011, 0x00011100, 0x00011101, 0x00011110, 0x00011111,
   0x00100000, 0x00100001, 0x00100010, 0x00100011, 0x00100100, 0x00100101, 0x00100110, 0x00100111,
   0x00101000, 0x00101001, 0x00101010, 0x00101011, 0x00101100, 0x00101101, 0x00101110, 0x00101111,
   0x00110000, 0x00110001, 0x00110010, 0x00110011, 0x00110100, 0x00110101, 0x00110110, 0x00110111,
   0x00111000, 0x00111001, 0x00111010, 0x00111011, 0x00111100, 0x00111101, 0x00111110, 0x00111111,
   0x01000000, 0x01000001, 0x01000010, 0x01000011, 0x01000100, 0x01000101, 0x01000110, 0x01000111,
   0x01001000, 0x01001001, 0x01001010, 0x01001011, 0x01001100, 0x01001101, 0x01001110, 0x01001111,
   0x01010000, 0x01010001, 0x01010010, 0x01010011, 0x01010100, 0x01010101, 0x01010110, 0x01010111,
   0x01011000, 0x01011001, 0x01011010, 0x01011011, 0x01011100, 0x01011101, 0x01011110, 0x01011111,
   0x01100000, 0x01100001, 0x01100010, 0x01100011, 0x01100100, 0x01100101, 0x01100110, 0x01100111,
   0x01101000, 0x01101001, 0x01101010, 0x01101011, 0x01101100, 0x01101101, 0x01101110, 0x01101111,
   0x01110000, 0x01110001, 0x01110010, 0x01110011, 0x01110100, 0x01110101, 0x01110110, 0x01110111,
   0x01111000, 0x01111001, 0x01111010, 0x01111011, 0x01111100, 0x01111101, 0x01111110, 0x01111111,
   0x10000000, 0x10000001, 0x10000010, 0x10000011, 0x10000100, 0x10000101, 0x10000110, 0x10000111,
   0x10001000, 0x10001001, 0x10001010, 0x10001011, 0x10001100, 0x10001101, 0x10001110, 0x10001111,
   0x10010000, 0x10010001, 0x10010010, 0x10010011, 0x10010100, 0x10010101, 0x10010110, 0x10010111,
   0x10011000, 0x10011001, 0x10011010, 0x10011011, 0x10011100, 0x10011101, 0x10011110, 0x10011111,
   0x10100000, 0x10100001, 0x10100010, 0x10100011, 0x10100100, 0x10100101, 0x10100110, 0x10100111,
   0x10101000, 0x10101001, 0x10101010, 0x10101011, 0x10101100, 0x10101101, 0x10101110, 0x10101111,
   0x10110000, 0x10110001, 0x10110010, 0x10110011, 0x10110100, 0x10110101, 0x10110110, 0x10110111,
   0x10111000, 0x10111001, 0x10111010, 0x10111011, 0x10111100, 0x10111101, 0x10111110, 0x10111111,
   0x11000000, 0x11000001, 0x11000010, 0x11000011, 0x11000100, 0x11000101, 0x11000110, 0x11000111,
   0x11001000, 0x11001001, 0x11001010, 0x11001011, 0x11001100, 0x11001101, 0x11001110, 0x11001111,
   0x11010000, 0x11010001, 0x11010010, 0x11010011, 0x11010100, 0x11010101, 0x11010110, 0x11010111,
   0x11011000, 0x11011001, 0x11011010, 0x11011011, 0x11011100, 0x11011101, 0x11011110, 0x11011111,
   0x11100000, 0x11100001, 0x11100010, 0x11100011, 0x11100100, 0x11100101, 0x11100110, 0x11100111,
   0x11101000, 0x11101001, 0x11101010, 0x11101011, 0x11101100, 0x11101101, 0x11101110, 0x11101111,
   0x11110000, 0x11110001, 0x11110010, 0x11110011, 0x11110100, 0x11110101, 0x11110110, 0x11110111,
   0x11111000, 0x11111001, 0x11111010, 0x11111011, 0x11111100, 0x11111101, 0x11111110, 0x11111111
};

//Combined S-box and bit permutation
static const uint64_t spbox[256] =
{
   0x0003000300000000, 0x0002000300000001, 0x0002000300010000, 0x0003000200010001,
   0x0003000200000001, 0x0002000200000000, 0x0003000200010000, 0x0003000300000001,
   0x0002000200010001, 0x0003000300010000, 0x0003000300010001, 0x0003000200000000,
   0x0002000300000000, 0x0002000300010001, 0x0002000200000001, 0x0002000200010000,
   0x0001000300000002, 0x0000000300000003, 0x0000000300010002, 0x0001000200010003,
   0x0001000200000003, 0x0000000200000002, 0x0001000200010002, 0x0001000300000003,
   0x0000000200010003, 0x0001000300010002, 0x0001000300010003, 0x0001000200000002,
   0x0000000300000002, 0x0000000300010003, 0x0000000200000003, 0x0000000200010002,
   0x0001000300020000, 0x0000000300020001, 0x0000000300030000, 0x0001000200030001,
   0x0001000200020001, 0x0000000200020000, 0x0001000200030000, 0x0001000300020001,
   0x0000000200030001, 0x0001000300030000, 0x0001000300030001, 0x0001000200020000,
   0x0000000300020000, 0x0000000300030001, 0x0000000200020001, 0x0000000200030000,
   0x0003000100020002, 0x0002000100020003, 0x0002000100030002, 0x0003000000030003,
   0x0003000000020003, 0x0002000000020002, 0x0003000000030002, 0x0003000100020003,
   0x0002000000030003, 0x0003000100030002, 0x0003000100030003, 0x0003000000020002,
   0x0002000100020002, 0x0002000100030003, 0x0002000000020003, 0x0002000000030002,
   0x0003000100000002, 0x0002000100000003, 0x0002000100010002, 0x0003000000010003,
   0x0003000000000003, 0x0002000000000002, 0x0003000000010002, 0x0003000100000003,
   0x0002000000010003, 0x0003000100010002, 0x0003000100010003, 0x0003000000000002,
   0x0002000100000002, 0x0002000100010003, 0x0002000000000003, 0x0002000000010002,
   0x0001000100000000, 0x0000000100000001, 0x0000000100010000, 0x0001000000010001,
   0x0001000000000001, 0x0000000000000000, 0x0001000000010000, 0x0001000100000001,
   0x0000000000010001, 0x0001000100010000, 0x0001000100010001, 0x0001000000000000,
   0x0000000100000000, 0x0000000100010001, 0x0000000000000001, 0x0000000000010000,
   0x0003000100020000, 0x0002000100020001, 0x0002000100030000, 0x0003000000030001,
   0x0003000000020001, 0x0002000000020000, 0x0003000000030000, 0x0003000100020001,
   0x0002000000030001, 0x0003000100030000, 0x0003000100030001, 0x0003000000020000,
   0x0002000100020000, 0x0002000100030001, 0x0002000000020001, 0x0002000000030000,
   0x0003000300000002, 0x0002000300000003, 0x0002000300010002, 0x0003000200010003,
   0x0003000200000003, 0x0002000200000002, 0x0003000200010002, 0x0003000300000003,
   0x0002000200010003, 0x0003000300010002, 0x0003000300010003, 0x0003000200000002,
   0x0002000300000002, 0x0002000300010003, 0x0002000200000003, 0x0002000200010002,
   0x0001000100020002, 0x0000000100020003, 0x0000000100030002, 0x0001000000030003,
   0x0001000000020003, 0x0000000000020002, 0x0001000000030002, 0x0001000100020003,
   0x0000000000030003, 0x0001000100030002, 0x0001000100030003, 0x0001000000020002,
   0x0000000100020002, 0x0000000100030003, 0x0000000000020003, 0x0000000000030002,
   0x0003000300020000, 0x0002000300020001, 0x0002000300030000, 0x0003000200030001,
   0x0003000200020001, 0x0002000200020000, 0x0003000200030000, 0x0003000300020001,
   0x0002000200030001, 0x0003000300030000, 0x0003000300030001, 0x0003000200020000,
   0x0002000300020000, 0x0002000300030001, 0x0002000200020001, 0x0002000200030000,
   0x0003000300020002, 0x0002000300020003, 0x0002000300030002, 0x0003000200030003,
   0x0003000200020003, 0x0002000200020002, 0x0003000200030002, 0x0003000300020003,
   0x0002000200030003, 0x0003000300030002, 0x0003000300030003, 0x0003000200020002,
   0x0002000300020002, 0x0002000300030003, 0x0002000200020003, 0x0002000200030002,
   0x0003000100000000, 0x0002000100000001, 0x0002000100010000, 0x0003000000010001,
   0x0003000000000001, 0x0002000000000000, 0x0003000000010000, 0x0003000100000001,
   0x0002000000010001, 0x0003000100010000, 0x0003000100010001, 0x0003000000000000,
   0x0002000100000000, 0x0002000100010001, 0x0002000000000001, 0x0002000000010000,
   0x0001000300000000, 0x0000000300000001, 0x0000000300010000, 0x0001000200010001,
   0x0001000200000001, 0x0000000200000000, 0x0001000200010000, 0x0001000300000001,
   0x0000000200010001, 0x0001000300010000, 0x0001000300010001, 0x0001000200000000,
   0x0000000300000000, 0x0000000300010001, 0x0000000200000001, 0x0000000200010000,
   0x0001000300020002, 0x0000000300020003, 0x0000000300030002, 0x0001000200030003,
   0x0001000200020003, 0x0000000200020002, 0x0001000200030002, 0x0001000300020003,
   0x0000000200030003, 0x0001000300030002, 0x0001000300030003, 0x0001000200020002,
   0x0000000300020002, 0x0000000300030003, 0x0000000200020003, 0x0000000200030002,
   0x0001000100000002, 0x0000000100000003, 0x0000000100010002, 0x0001000000010003,
   0x0001000000000003, 0x0000000000000002, 0x0001000000010002, 0x0001000100000003,
   0x0000000000010003, 0x0001000100010002, 0x0001000100010003, 0x0001000000000002,
   0x0000000100000002, 0x0000000100010003, 0x0000000000000003, 0x0000000000010002,
   0x0001000100020000, 0x0000000100020001, 0x0000000100030000, 0x0001000000030001,
   0x0001000000020001, 0x0000000000020000, 0x0001000000030000, 0x0001000100020001,
   0x0000000000030001, 0x0001000100030000, 0x0001000100030001, 0x0001000000020000,
   0x0000000100020000, 0x0000000100030001, 0x0000000000020001, 0x0000000000030000
};

//Common interface for encryption algorithms
const CipherAlgo presentCipherAlgo =
{
   "PRESENT",
   sizeof(PresentContext),
   CIPHER_ALGO_TYPE_BLOCK,
   PRESENT_BLOCK_SIZE,
   (CipherAlgoInit) presentInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) presentEncryptBlock,
   (CipherAlgoDecryptBlock) presentDecryptBlock,
   (CipherAlgoDeinit) presentDeinit
};


/**
 * @brief Key expansion
 * @param[in] context Pointer to the PRESENT context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t presentInit(PresentContext *context, const uint8_t *key,
   size_t keyLen)
{
   uint_t i;
   uint64_t t;
   uint64_t kl;
   uint64_t kh;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check key length
   if(keyLen != 10 && keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //PRESENT can take keys of either 80 or 128 bits
   if(keyLen == 10)
   {
      //Copy the 80-bit key
      kh = LOAD16BE(key);
      kl = LOAD64BE(key + 2);

      //Save the 64 leftmost bits of K
      context->ks[0] = (kh << 48) | (kl >> 16);

      //Generate round keys
      for(i = 1; i <= 31; i++)
      {
         //The key register is rotated by 61 bit positions to the left
         t = kh & 0xFFFF;
         kh = (kl >> 3) & 0xFFFF;
         kl = (kl << 61) | (t << 45) | (kl >> 19);

         //The left-most four bits are passed through the S-box
         t = sbox[(kh >> 12) & 0x0F];
         kh = (kh & 0x0FFF) | (t << 12);

         //The round counter value i is XOR-ed with bits 19, 18, 17, 16, 15 of K
         kl ^= (uint64_t) i << 15;

         //Save the 64 leftmost bits of K
         context->ks[i] = (kh << 48) | (kl >> 16);
      }
   }
   else
   {
      //Copy the 128-bit key
      kh = LOAD64BE(key);
      kl = LOAD64BE(key + 8);

      //Save the 64 leftmost bits of K
      context->ks[0] = kh;

      //Generate round keys
      for(i = 1; i <= 31; i++)
      {
         //The key register is rotated by 61 bit positions to the left
         t = kh;
         kh = (t << 61) | (kl >> 3);
         kl = (kl << 61) | (t >> 3);

         //The left-most eight bits are passed through two S-boxes
         t = sbox[(kh >> 56) & 0x0F];
         kh = (kh & 0xF0FFFFFFFFFFFFFF) | (t << 56);
         t = sbox[(kh >> 60) & 0x0F];
         kh = (kh & 0x0FFFFFFFFFFFFFFF) | (t << 60);

         //The round counter value i is XOR-ed with bits 66, 65, 64, 63, 62 of K
         kh ^= (uint64_t) i >> 2;
         kl ^= (uint64_t) i << 62;

         //Save the 64 leftmost bits of K
         context->ks[i] = kh;
      }
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using PRESENT algorithm
 * @param[in] context Pointer to the PRESENT context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void presentEncryptBlock(PresentContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint64_t s;
   uint64_t t;
   uint64_t state;

   //Copy the plaintext to the 64-bit state
   state = LOAD64BE(input);

   //Initial round key addition
   state ^= context->ks[0];

   //The encryption consists of 31 rounds
   for(i = 1; i <= 31; i++)
   {
      //Apply S-box and bit permutation
      s = spbox[state & 0xFF];
      t = spbox[(state >> 8) & 0xFF];
      s |= ROL64(t, 2);
      t = spbox[(state >> 16) & 0xFF];
      s |= ROL64(t, 4);
      t = spbox[(state >> 24) & 0xFF];
      s |= ROL64(t, 6);
      t = spbox[(state >> 32) & 0xFF];
      s |= ROL64(t, 8);
      t = spbox[(state >> 40) & 0xFF];
      s |= ROL64(t, 10);
      t = spbox[(state >> 48) & 0xFF];
      s |= ROL64(t, 12);
      t = spbox[(state >> 56) & 0xFF];
      s |= ROL64(t, 14);

      //Add round key
      state = s ^ context->ks[i];
   }

   //The final state is then copied to the output
   STORE64BE(state, output);
}


/**
 * @brief Decrypt a 8-byte block using PRESENT algorithm
 * @param[in] context Pointer to the PRESENT context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void presentDecryptBlock(PresentContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint64_t s;
   uint64_t t;
   uint64_t state;

   //Copy the ciphertext to the 64-bit state
   state = LOAD64BE(input);

   //The decryption consists of 31 rounds
   for(i = 31; i > 0; i--)
   {
      //Add round key
      state ^= context->ks[i];

      //Apply inverse bit permutation
      s = ipbox[state & 0xFF];
      t = ipbox[(state >> 8) & 0xFF];
      s |= ROL64(t, 32);
      t = ipbox[(state >> 16) & 0xFF];
      s |= ROL64(t, 1);
      t = ipbox[(state >> 24) & 0xFF];
      s |= ROL64(t, 33);
      t = ipbox[(state >> 32) & 0xFF];
      s |= ROL64(t, 2);
      t = ipbox[(state >> 40) & 0xFF];
      s |= ROL64(t, 34);
      t = ipbox[(state >> 48) & 0xFF];
      s |= ROL64(t, 3);
      t = ipbox[(state >> 56) & 0xFF];
      s |= ROL64(t, 35);

      //Apply inverse S-box
      state = isbox[s & 0xFF];
      t = isbox[(s >> 8) & 0xFF];
      state |= ROL64(t, 8);
      t = isbox[(s >> 16) & 0xFF];
      state |= ROL64(t, 16);
      t = isbox[(s >> 24) & 0xFF];
      state |= ROL64(t, 24);
      t = isbox[(s >> 32) & 0xFF];
      state |= ROL64(t, 32);
      t = isbox[(s >> 40) & 0xFF];
      state |= ROL64(t, 40);
      t = isbox[(s >> 48) & 0xFF];
      state |= ROL64(t, 48);
      t = isbox[(s >> 56) & 0xFF];
      state |= ROL64(t, 56);
   }

   //Final round key addition
   state ^= context->ks[0];

   //The final state is then copied to the output
   STORE64BE(state, output);
}


/**
 * @brief Release PRESENT context
 * @param[in] context Pointer to the PRESENT context
 **/

void presentDeinit(PresentContext *context)
{
   //Clear PRESENT context
   osMemset(context, 0, sizeof(PresentContext));
}

#endif
