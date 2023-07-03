/**
 * @file pic32mz_crypto_cipher.c
 * @brief PIC32MZ cipher hardware accelerator
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
#include <p32xxxx.h>
#include <sys/kmem.h>
#include "core/crypto.h"
#include "hardware/pic32mz/pic32mz_crypto.h"
#include "hardware/pic32mz/pic32mz_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32MZ_CRYPTO_CIPHER_SUPPORT == ENABLED)

//Buffer descriptor
volatile Pic32mzCryptoBufferDesc cipherBufferDesc
   __attribute__((coherent, aligned(8)));

//Security association
volatile Pic32mzCryptoSecurityAssoc cipherSecurityAssoc
   __attribute__((coherent, aligned(8)));

//Input buffer
uint8_t cipherInput[PIC32MZ_CRYPTO_BUFFER_SIZE]
   __attribute__((coherent, aligned(4)));

//Output buffer
uint8_t cipherOutput[PIC32MZ_CRYPTO_BUFFER_SIZE]
   __attribute__((coherent, aligned(4)));

//GCM authentication tag
uint8_t gcmAuthTag[16] __attribute__((coherent, aligned(4)));


#if (DES_SUPPORT == ENABLED)

/**
 * @brief Perform DES encryption or decryption
 * @param[in] context DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void desProcessData(DesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   size_t i;
   size_t n;
   uint32_t *p;

   //Acquire exclusive access to the crypto engine
   osAcquireMutex(&pic32mzCryptoMutex);

   //Reset the crypto engine
   CECON |= _CECON_SWRST_MASK;
   //Wait for the reset to complete
   while((CECON & _CECON_SWRST_MASK) != 0)
   {
   }

   //Clear descriptors
   memset((void *) &cipherBufferDesc, 0, sizeof(Pic32mzCryptoBufferDesc));
   memset((void *) &cipherSecurityAssoc, 0, sizeof(Pic32mzCryptoSecurityAssoc));

   //Set up buffer descriptor
   cipherBufferDesc.SA_ADDR = KVA_TO_PA(&cipherSecurityAssoc);
   cipherBufferDesc.SRCADDR = KVA_TO_PA(cipherInput);
   cipherBufferDesc.DSTADDR = KVA_TO_PA(cipherOutput);
   cipherBufferDesc.NXTPTR = KVA_TO_PA(&cipherBufferDesc);
   cipherBufferDesc.MSG_LEN = (length + 7) & ~7UL;

   //Set up security association
   cipherSecurityAssoc.SA_CTRL = SA_CTRL_LNC | SA_CTRL_LOADIV | SA_CTRL_FB |
      SA_CTRL_ALGO_DES | mode;

   //Set encryption key
   cipherSecurityAssoc.SA_ENCKEY[6] = htobe32(context->ks[0]);
   cipherSecurityAssoc.SA_ENCKEY[7] = htobe32(context->ks[1]);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      cipherSecurityAssoc.SA_ENCIV[2] = LOAD32BE(iv);
      cipherSecurityAssoc.SA_ENCIV[3] = LOAD32BE(iv + 4);
   }

   //Set the number of cycles that the DMA would wait before refetching the
   //descriptor control word if the previous descriptor fetched was disabled
   CEPOLLCON = 10;

   //Set the address from which the DMA will start fetching buffer descriptors
   CEBDPADDR = KVA_TO_PA(&cipherBufferDesc);

   //Enable DMA engine
   CECON = _CECON_SWAPOEN_MASK | _CECON_SWAPEN_MASK | _CECON_BDPCHST_MASK |
      _CECON_BDPPLEN_MASK | _CECON_DMAEN_MASK;

   //Process data
   for(i = 0; i < length; i += n)
   {
      //Limit the number of data to process at a time
      n = MIN(length - i, sizeof(cipherInput));
      //Copy input data
      osMemcpy(cipherInput, input, n);

      //Padding must be added to ensure the size of the incoming data to
      //be processed is a multiple of 8 bytes
      cipherBufferDesc.BD_CTRL = (n + 7) & ~7UL;

      //First buffer descriptor?
      if(i == 0)
      {
         //Fetch security association from the SA pointer
         cipherBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
      }

      //Last buffer descriptor?
      if((i + n) == length)
      {
         //This BD is the last in the frame
         cipherBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
      }

      //Give the ownership of the descriptor to the hardware
      cipherBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

      //Wait for the encryption/decryption to complete
      while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
      {
      }

      //Copy output data
      osMemcpy(output, cipherOutput, n);

      //Advance data pointer
      input += n;
      output += n;
   }

   //Release exclusive access to the crypto engine
   osReleaseMutex(&pic32mzCryptoMutex);
}


/**
 * @brief Initialize a DES context using the supplied key
 * @param[in] context Pointer to the DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (must be set to 8)
 * @return Error code
 **/

error_t desInit(DesContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 8)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the key
   osMemcpy(context->ks, key, keyLen);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void desEncryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform DES encryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE, SA_CTRL_ENC |
      SA_CTRL_CRYPTOALGO_ECB);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform DES decryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE,
      SA_CTRL_CRYPTOALGO_ECB);
}

#endif
#if (DES3_SUPPORT == ENABLED)

/**
 * @brief Perform Triple DES encryption or decryption
 * @param[in] context Triple DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void des3ProcessData(Des3Context *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   size_t i;
   size_t n;
   uint32_t *p;

   //Acquire exclusive access to the crypto engine
   osAcquireMutex(&pic32mzCryptoMutex);

   //Reset the crypto engine
   CECON |= _CECON_SWRST_MASK;
   //Wait for the reset to complete
   while((CECON & _CECON_SWRST_MASK) != 0)
   {
   }

   //Clear descriptors
   memset((void *) &cipherBufferDesc, 0, sizeof(Pic32mzCryptoBufferDesc));
   memset((void *) &cipherSecurityAssoc, 0, sizeof(Pic32mzCryptoSecurityAssoc));

   //Set up buffer descriptor
   cipherBufferDesc.SA_ADDR = KVA_TO_PA(&cipherSecurityAssoc);
   cipherBufferDesc.SRCADDR = KVA_TO_PA(cipherInput);
   cipherBufferDesc.DSTADDR = KVA_TO_PA(cipherOutput);
   cipherBufferDesc.NXTPTR = KVA_TO_PA(&cipherBufferDesc);
   cipherBufferDesc.MSG_LEN = (length + 7) & ~7UL;

   //Set up security association
   cipherSecurityAssoc.SA_CTRL = SA_CTRL_LNC | SA_CTRL_LOADIV | SA_CTRL_FB |
      SA_CTRL_ALGO_TDES | mode;

   //Set encryption key
   cipherSecurityAssoc.SA_ENCKEY[2] = htobe32(context->k1.ks[0]);
   cipherSecurityAssoc.SA_ENCKEY[3] = htobe32(context->k1.ks[1]);
   cipherSecurityAssoc.SA_ENCKEY[4] = htobe32(context->k2.ks[0]);
   cipherSecurityAssoc.SA_ENCKEY[5] = htobe32(context->k2.ks[1]);
   cipherSecurityAssoc.SA_ENCKEY[6] = htobe32(context->k3.ks[0]);
   cipherSecurityAssoc.SA_ENCKEY[7] = htobe32(context->k3.ks[1]);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      cipherSecurityAssoc.SA_ENCIV[2] = LOAD32BE(iv);
      cipherSecurityAssoc.SA_ENCIV[3] = LOAD32BE(iv + 4);
   }

   //Set the number of cycles that the DMA would wait before refetching the
   //descriptor control word if the previous descriptor fetched was disabled
   CEPOLLCON = 10;

   //Set the address from which the DMA will start fetching buffer descriptors
   CEBDPADDR = KVA_TO_PA(&cipherBufferDesc);

   //Enable DMA engine
   CECON = _CECON_SWAPOEN_MASK | _CECON_SWAPEN_MASK | _CECON_BDPCHST_MASK |
      _CECON_BDPPLEN_MASK | _CECON_DMAEN_MASK;

   //Process data
   for(i = 0; i < length; i += n)
   {
      //Limit the number of data to process at a time
      n = MIN(length - i, sizeof(cipherInput));
      //Copy input data
      osMemcpy(cipherInput, input, n);

      //Padding must be added to ensure the size of the incoming data to
      //be processed is a multiple of 8 bytes
      cipherBufferDesc.BD_CTRL = (n + 7) & ~7UL;

      //First buffer descriptor?
      if(i == 0)
      {
         //Fetch security association from the SA pointer
         cipherBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
      }

      //Last buffer descriptor?
      if((i + n) == length)
      {
         //This BD is the last in the frame
         cipherBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
      }

      //Give the ownership of the descriptor to the hardware
      cipherBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

      //Wait for the encryption/decryption to complete
      while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
      {
      }

      //Copy output data
      osMemcpy(output, cipherOutput, n);

      //Advance data pointer
      input += n;
      output += n;
   }

   //Release exclusive access to the crypto engine
   osReleaseMutex(&pic32mzCryptoMutex);
}


/**
 * @brief Initialize a Triple DES context using the supplied key
 * @param[in] context Pointer to the Triple DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t des3Init(Des3Context *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check key length
   if(keyLen == 8)
   {
      //This option provides backward compatibility with DES, because the
      //first and second DES operations cancel out
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key, 8);
      osMemcpy(context->k3.ks, key, 8);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key + 8, 8);
      osMemcpy(context->k3.ks, key, 8);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key + 8, 8);
      osMemcpy(context->k3.ks, key + 16, 8);
   }
   else
   {
      //The length of the key is not valid
      return ERROR_INVALID_KEY_LENGTH;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void des3EncryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Perform Triple DES encryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE, SA_CTRL_ENC |
      SA_CTRL_CRYPTOALGO_TECB);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Perform Triple DES decryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE,
      SA_CTRL_CRYPTOALGO_TECB);
}

#endif
#if (AES_SUPPORT == ENABLED)

/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read SA_CTRL value
   temp = cipherSecurityAssoc.SA_CTRL & ~SA_CTRL_KEYSIZE;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      cipherSecurityAssoc.SA_CTRL = temp | SA_CTRL_KEYSIZE_128;

      //Set the 128-bit encryption key
      cipherSecurityAssoc.SA_ENCKEY[4] = htobe32(context->ek[0]);
      cipherSecurityAssoc.SA_ENCKEY[5] = htobe32(context->ek[1]);
      cipherSecurityAssoc.SA_ENCKEY[6] = htobe32(context->ek[2]);
      cipherSecurityAssoc.SA_ENCKEY[7] = htobe32(context->ek[3]);
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      cipherSecurityAssoc.SA_CTRL = temp | SA_CTRL_KEYSIZE_192;

      //Set the 192-bit encryption key
      cipherSecurityAssoc.SA_ENCKEY[2] = htobe32(context->ek[0]);
      cipherSecurityAssoc.SA_ENCKEY[3] = htobe32(context->ek[1]);
      cipherSecurityAssoc.SA_ENCKEY[4] = htobe32(context->ek[2]);
      cipherSecurityAssoc.SA_ENCKEY[5] = htobe32(context->ek[3]);
      cipherSecurityAssoc.SA_ENCKEY[6] = htobe32(context->ek[4]);
      cipherSecurityAssoc.SA_ENCKEY[7] = htobe32(context->ek[5]);
   }
   else
   {
      //14 rounds are required for 256-bit key
      cipherSecurityAssoc.SA_CTRL = temp | SA_CTRL_KEYSIZE_256;

      //Set the 256-bit encryption key
      cipherSecurityAssoc.SA_ENCKEY[0] = htobe32(context->ek[0]);
      cipherSecurityAssoc.SA_ENCKEY[1] = htobe32(context->ek[1]);
      cipherSecurityAssoc.SA_ENCKEY[2] = htobe32(context->ek[2]);
      cipherSecurityAssoc.SA_ENCKEY[3] = htobe32(context->ek[3]);
      cipherSecurityAssoc.SA_ENCKEY[4] = htobe32(context->ek[4]);
      cipherSecurityAssoc.SA_ENCKEY[5] = htobe32(context->ek[5]);
      cipherSecurityAssoc.SA_ENCKEY[6] = htobe32(context->ek[6]);
      cipherSecurityAssoc.SA_ENCKEY[7] = htobe32(context->ek[7]);
   }
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   size_t i;
   size_t n;
   uint32_t *p;

   //Acquire exclusive access to the crypto engine
   osAcquireMutex(&pic32mzCryptoMutex);

   //Reset the crypto engine
   CECON |= _CECON_SWRST_MASK;
   //Wait for the reset to complete
   while((CECON & _CECON_SWRST_MASK) != 0)
   {
   }

   //Clear descriptors
   memset((void *) &cipherBufferDesc, 0, sizeof(Pic32mzCryptoBufferDesc));
   memset((void *) &cipherSecurityAssoc, 0, sizeof(Pic32mzCryptoSecurityAssoc));

   //Set up buffer descriptor
   cipherBufferDesc.SA_ADDR = KVA_TO_PA(&cipherSecurityAssoc);
   cipherBufferDesc.SRCADDR = KVA_TO_PA(cipherInput);
   cipherBufferDesc.DSTADDR = KVA_TO_PA(cipherOutput);
   cipherBufferDesc.NXTPTR = KVA_TO_PA(&cipherBufferDesc);
   cipherBufferDesc.MSG_LEN = (length + 15) & ~15UL;

   //Set up security association
   cipherSecurityAssoc.SA_CTRL = SA_CTRL_LNC | SA_CTRL_LOADIV | SA_CTRL_FB |
      SA_CTRL_ALGO_AES | mode;

   //Set encryption key
   aesLoadKey(context);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      cipherSecurityAssoc.SA_ENCIV[0] = LOAD32BE(iv);
      cipherSecurityAssoc.SA_ENCIV[1] = LOAD32BE(iv + 4);
      cipherSecurityAssoc.SA_ENCIV[2] = LOAD32BE(iv + 8);
      cipherSecurityAssoc.SA_ENCIV[3] = LOAD32BE(iv + 12);
   }

   //Set the number of cycles that the DMA would wait before refetching the
   //descriptor control word if the previous descriptor fetched was disabled
   CEPOLLCON = 10;

   //Set the address from which the DMA will start fetching buffer descriptors
   CEBDPADDR = KVA_TO_PA(&cipherBufferDesc);

   //Enable DMA engine
   CECON = _CECON_SWAPOEN_MASK | _CECON_SWAPEN_MASK | _CECON_BDPCHST_MASK |
      _CECON_BDPPLEN_MASK | _CECON_DMAEN_MASK;

   //Process data
   for(i = 0; i < length; i += n)
   {
      //Limit the number of data to process at a time
      n = MIN(length - i, sizeof(cipherInput));
      //Copy input data
      osMemcpy(cipherInput, input, n);

      //Padding must be added to ensure the size of the incoming data to
      //be processed is a multiple of 16 bytes
      cipherBufferDesc.BD_CTRL = (n + 15) & ~15UL;

      //First buffer descriptor?
      if(i == 0)
      {
         //Fetch security association from the SA pointer
         cipherBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
      }

      //Last buffer descriptor?
      if((i + n) == length)
      {
         //This BD is the last in the frame
         cipherBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
      }

      //Give the ownership of the descriptor to the hardware
      cipherBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

      //Wait for the encryption/decryption to complete
      while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
      {
      }

      //Copy output data
      osMemcpy(output, cipherOutput, n);

      //Advance data pointer
      input += n;
      output += n;
   }

   //Release exclusive access to the crypto engine
   osReleaseMutex(&pic32mzCryptoMutex);
}


/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
   }
   else if(keyLen == 24)
   {
      //12 rounds are required for 192-bit key
      context->nr = 12;
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //Report an error
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Copy the original key
   osMemcpy(context->ek, key, keyLen);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform AES encryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE, SA_CTRL_ENC |
      SA_CTRL_CRYPTOALGO_RECB);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform AES decryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      SA_CTRL_CRYPTOALGO_RECB);
}

#endif
#if (ECB_SUPPORT == ENABLED)

/**
 * @brief ECB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ecbEncrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         desProcessData(context, NULL, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         des3ProcessData(context, NULL, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_TECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         aesProcessData(context, NULL, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_RECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Encrypt current block
         cipher->encryptBlock(context, p, c);

         //Next block
         p += cipher->blockSize;
         c += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief ECB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t ecbDecrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Decrypt payload data
         desProcessData(context, NULL, c, p, length, SA_CTRL_CRYPTOALGO_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Decrypt payload data
         des3ProcessData(context, NULL, c, p, length, SA_CTRL_CRYPTOALGO_TECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Decrypt payload data
         aesProcessData(context, NULL, c, p, length, SA_CTRL_CRYPTOALGO_RECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Decrypt current block
         cipher->decryptBlock(context, c, p);

         //Next block
         c += cipher->blockSize;
         p += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}

#endif
#if (CBC_SUPPORT == ENABLED)

/**
 * @brief CBC encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t cbcEncrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         desProcessData(context, iv, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_CBC);

         //Update the value of the initialization vector
         osMemcpy(iv, c + length - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         des3ProcessData(context, iv, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_TCBC);

         //Update the value of the initialization vector
         osMemcpy(iv, c + length - DES3_BLOCK_SIZE, DES3_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Encrypt payload data
         aesProcessData(context, iv, p, c, length, SA_CTRL_ENC |
            SA_CTRL_CRYPTOALGO_RCBC);

         //Update the value of the initialization vector
         osMemcpy(iv, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      size_t i;

      //CBC mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //XOR input block with IV contents
         for(i = 0; i < cipher->blockSize; i++)
         {
            c[i] = p[i] ^ iv[i];
         }

         //Encrypt the current block based upon the output of the previous
         //encryption
         cipher->encryptBlock(context, c, c);

         //Update IV with output block contents
         osMemcpy(iv, c, cipher->blockSize);

         //Next block
         p += cipher->blockSize;
         c += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CBC decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t cbcDecrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         uint8_t block[DES_BLOCK_SIZE];

         //Save the last input block
         osMemcpy(block, c + length - DES_BLOCK_SIZE, DES_BLOCK_SIZE);

         //Decrypt payload data
         desProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_CBC);

         //Update the value of the initialization vector
         osMemcpy(iv, block, DES_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         uint8_t block[DES3_BLOCK_SIZE];

         //Save the last input block
         osMemcpy(block, c + length - DES3_BLOCK_SIZE, DES3_BLOCK_SIZE);

         //Decrypt payload data
         des3ProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_TCBC);

         //Update the value of the initialization vector
         osMemcpy(iv, block, DES3_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         uint8_t block[AES_BLOCK_SIZE];

         //Save the last input block
         osMemcpy(block, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

         //Decrypt payload data
         aesProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_RCBC);

         //Update the value of the initialization vector
         osMemcpy(iv, block, AES_BLOCK_SIZE);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      size_t i;
      uint8_t t[16];

      //CBC mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Save input block
         osMemcpy(t, c, cipher->blockSize);

         //Decrypt the current block
         cipher->decryptBlock(context, c, p);

         //XOR output block with IV contents
         for(i = 0; i < cipher->blockSize; i++)
         {
            p[i] ^= iv[i];
         }

         //Update IV with input block contents
         osMemcpy(iv, t, cipher->blockSize);

         //Next block
         c += cipher->blockSize;
         p += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}

#endif
#if (CFB_SUPPORT == ENABLED)

/**
 * @brief CFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t cfbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            desProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_CFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            des3ProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_TCFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_RCFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CFB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t cfbDecrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            desProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_CFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            des3ProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_TCFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            aesProcessData(context, iv, c, p, length, SA_CTRL_CRYPTOALGO_RCFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each ciphertext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

            //Compute P(j) = C(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               p[i] = c[i] ^ o[i];
            }

            //Next block
            c += n;
            p += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}

#endif
#if (OFB_SUPPORT == ENABLED)

/**
 * @brief OFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ofbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            desProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_OFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            des3ProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_TOFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, SA_CTRL_ENC |
               SA_CTRL_CRYPTOALGO_ROFB);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | O(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, o, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}

#endif
#if (GCM_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

/**
 * @brief Perform AES-GCM encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode
 **/

void gcmProcessData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, uint32_t mode)
{
   size_t i;
   size_t n;
   size_t padLen;
   uint32_t *p;

   //Acquire exclusive access to the crypto engine
   osAcquireMutex(&pic32mzCryptoMutex);

   //Reset the crypto engine
   CECON |= _CECON_SWRST_MASK;
   //Wait for the reset to complete
   while((CECON & _CECON_SWRST_MASK) != 0)
   {
   }

   //Clear descriptors
   memset((void *) &cipherBufferDesc, 0, sizeof(Pic32mzCryptoBufferDesc));
   memset((void *) &cipherSecurityAssoc, 0, sizeof(Pic32mzCryptoSecurityAssoc));

   //Set up buffer descriptor
   cipherBufferDesc.SA_ADDR = KVA_TO_PA(&cipherSecurityAssoc);
   cipherBufferDesc.SRCADDR = KVA_TO_PA(cipherInput);
   cipherBufferDesc.DSTADDR = KVA_TO_PA(cipherOutput);
   cipherBufferDesc.NXTPTR = KVA_TO_PA(&cipherBufferDesc);
   cipherBufferDesc.UPDPTR = KVA_TO_PA(gcmAuthTag);

   //Set up security association
   cipherSecurityAssoc.SA_CTRL = SA_CTRL_LNC | SA_CTRL_LOADIV | SA_CTRL_FB |
      SA_CTRL_ALGO_AES | mode;

   //Set encryption key
   aesLoadKey(context);

   //The fourth word of encryption IV for AES GCM shall be 1
   cipherSecurityAssoc.SA_ENCIV[0] = LOAD32BE(iv);
   cipherSecurityAssoc.SA_ENCIV[1] = LOAD32BE(iv + 4);
   cipherSecurityAssoc.SA_ENCIV[2] = LOAD32BE(iv + 8);
   cipherSecurityAssoc.SA_ENCIV[3] = 1;

   //Set the number of cycles that the DMA would wait before refetching the
   //descriptor control word if the previous descriptor fetched was disabled
   CEPOLLCON = 10;

   //Set the address from which the DMA will start fetching buffer descriptors
   CEBDPADDR = KVA_TO_PA(&cipherBufferDesc);

   //Enable DMA engine
   CECON = _CECON_SWAPOEN_MASK | _CECON_SWAPEN_MASK | _CECON_BDPCHST_MASK |
      _CECON_BDPPLEN_MASK | _CECON_DMAEN_MASK;

   //Check parameters
   if(aLen > 0 || length > 0)
   {
      //Select GCM operation mode
      cipherSecurityAssoc.SA_CTRL |= SA_CTRL_CRYPTOALGO_AES_GCM;

      //Specify the length of the payload data and AAD
      cipherBufferDesc.MSG_LEN = length;
      cipherBufferDesc.ENC_OFF = aLen;

      //Process additional authenticated data
      for(i = 0; i < aLen; i += n)
      {
         //Limit the number of data to process at a time
         n = MIN(aLen - i, sizeof(cipherInput));
         //Copy additional authenticated data
         osMemcpy(cipherInput, a, n);

         //Check the length of the incoming data
         if((n % 16) != 0)
         {
            //Padding must be added to ensure the size of the incoming data to
            //be processed is a multiple of 16 bytes
            padLen = 16 - (n % 16);

            //The padding string shall consist of zeroes
            osMemset(cipherInput + n, 0, padLen);
         }
         else
         {
            //No padding needed
            padLen = 0;
         }

         //Set buffer length
         cipherBufferDesc.BD_CTRL = n + padLen;

         //First buffer descriptor?
         if(i == 0)
         {
            //Fetch security association from the SA pointer
            cipherBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
         }

         //Last buffer descriptor?
         if((i + n) == aLen && length == 0)
         {
            //This BD is the last in the frame
            cipherBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
         }

         //Give the ownership of the descriptor to the hardware
         cipherBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

         //Wait for the process to complete
         while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
         {
         }

         //Advance data pointer
         a += n;
      }

      //Process data
      for(i = 0; i < length; i += n)
      {
         //Limit the number of data to process at a time
         n = MIN(length - i, sizeof(cipherInput));
         //Copy input data
         osMemcpy(cipherInput, input, n);

         //Padding must be added to ensure the size of the incoming data to
         //be processed is a multiple of 16 bytes
         cipherBufferDesc.BD_CTRL = (n + 15) & ~15UL;

         //First buffer descriptor?
         if(i == 0 && aLen == 0)
         {
            //Fetch security association from the SA pointer
            cipherBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
         }

         //Last buffer descriptor?
         if((i + n) == length)
         {
            //This BD is the last in the frame
            cipherBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
         }

         //Give the ownership of the descriptor to the hardware
         cipherBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

         //Wait for the encryption/decryption to complete
         while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
         {
         }

         //Copy output data
         osMemcpy(output, cipherOutput, n);

         //Advance data pointer
         input += n;
         output += n;
      }

      //Copy the resulting authentication tag
      osMemcpy(t, gcmAuthTag, 16);
   }
   else
   {
      //Select CTR operation mode
      cipherSecurityAssoc.SA_CTRL |= SA_CTRL_CRYPTOALGO_RCTR | SA_CTRL_ENC;

      //Clear input data block
      osMemset(cipherInput, 0, AES_BLOCK_SIZE);

      //Specify the length of the data block
      cipherBufferDesc.MSG_LEN = AES_BLOCK_SIZE;

      //Give the ownership of the descriptor to the hardware
      cipherBufferDesc.BD_CTRL = BD_CTRL_DESC_EN | BD_CTRL_SA_FETCH_EN |
         BD_CTRL_LIFM | AES_BLOCK_SIZE;

      //Wait for the encryption to complete
      while((cipherBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
      {
      }

      //Copy the resulting authentication tag
      osMemcpy(t, cipherOutput, AES_BLOCK_SIZE);
   }

   //Release exclusive access to the crypto engine
   osReleaseMutex(&pic32mzCryptoMutex);
}


/**
 * @brief Initialize GCM context
 * @param[in] context Pointer to the GCM context
 * @param[in] cipherAlgo Cipher algorithm
 * @param[in] cipherContext Pointer to the cipher algorithm context
 * @return Error code
 **/

error_t gcmInit(GcmContext *context, const CipherAlgo *cipherAlgo,
   void *cipherContext)
{
   //The CRYP module only supports AES cipher algorithm
   if(cipherAlgo != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Save cipher algorithm context
   context->cipherAlgo = cipherAlgo;
   context->cipherContext = cipherContext;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Authenticated encryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p,
   uint8_t *c, size_t length, uint8_t *t, size_t tLen)
{
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Perform AES-GCM encryption
   gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length,
      authTag, SA_CTRL_ENC);

   //Copy the resulting authentication tag
   osMemcpy(t, authTag, tLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c,
   uint8_t *p, size_t length, const uint8_t *t, size_t tLen)
{
   size_t i;
   uint8_t mask;
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Perform AES-GCM decryption
   gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length,
      authTag, 0);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
