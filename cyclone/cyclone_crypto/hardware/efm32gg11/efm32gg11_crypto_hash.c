/**
 * @file efm32gg11_crypto_hash.c
 * @brief EFM32 Giant Gecko 11 hash hardware accelerator
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
#include "em_device.h"
#include "em_crypto.h"
#include "core/crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (EFM32GG11_CRYPTO_HASH_SUPPORT == ENABLED)
#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Digest the message
   CRYPTO_SHA_1(CRYPTO0, data, length, digest);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-1 context
 **/

void sha1ProcessBlock(Sha1Context *context)
{
   uint32_t temp[8];

   //Initialize the 8 working registers
   temp[0] = context->h[0];
   temp[1] = context->h[1];
   temp[2] = context->h[2];
   temp[3] = context->h[3];
   temp[4] = context->h[4];
   temp[5] = 0;
   temp[6] = 0;
   temp[7] = 0;

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Configure the CRYPTO module for SHA-1 operation
   CRYPTO0->CTRL = CRYPTO_CTRL_SHA_SHA1;
   CRYPTO0->SEQCTRL = 0;
   CRYPTO0->SEQCTRLB = 0;

   //Set the result width for MADD32 operation
   CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

   //Write the state to DDATA1
   CRYPTO_DDataWrite(&CRYPTO0->DDATA1, temp);

   //Copy data to DDATA0 and select DDATA0 and DDATA1 for SHA operation
   CRYPTO_EXECUTE_2(CRYPTO0,
      CRYPTO_CMD_INSTR_DDATA1TODDATA0,
      CRYPTO_CMD_INSTR_SELDDATA0DDATA1);

   //Write the 16-word block to QDATA1BIG
   CRYPTO_QDataWrite(&CRYPTO0->QDATA1BIG, context->w);

   //Accelerate SHA-1 inner compression loop
   CRYPTO_EXECUTE_3(CRYPTO0,
      CRYPTO_CMD_INSTR_SHA,
      CRYPTO_CMD_INSTR_MADD32,
      CRYPTO_CMD_INSTR_DDATA0TODDATA1);

   //Read the resulting digest from DDATA0BIG
   CRYPTO_DDataRead(&CRYPTO0->DDATA0BIG, temp);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Convert from big-endian byte order to host byte order
   context->h[0] = betoh32(temp[0]);
   context->h[1] = betoh32(temp[1]);
   context->h[2] = betoh32(temp[2]);
   context->h[3] = betoh32(temp[3]);
   context->h[4] = betoh32(temp[4]);
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Digest the message
   CRYPTO_SHA_256(CRYPTO0, data, length, digest);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-256 context
 **/

void sha256ProcessBlock(Sha256Context *context)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Configure the CRYPTO module for SHA-256 operation
   CRYPTO0->CTRL = CRYPTO_CTRL_SHA_SHA2;
   CRYPTO0->SEQCTRL = 0;
   CRYPTO0->SEQCTRLB = 0;

   //Set the result width for MADD32 operation
   CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

   //Write the state to DDATA1
   CRYPTO_DDataWrite(&CRYPTO0->DDATA1, context->h);

   //Copy data to DDATA0 and select DDATA0 and DDATA1 for SHA operation
   CRYPTO_EXECUTE_2(CRYPTO0,
      CRYPTO_CMD_INSTR_DDATA1TODDATA0,
      CRYPTO_CMD_INSTR_SELDDATA0DDATA1);

   //Write the 16-word block to QDATA1BIG
   CRYPTO_QDataWrite(&CRYPTO0->QDATA1BIG, context->w);

   //Accelerate SHA-256 inner compression loop
   CRYPTO_EXECUTE_3(CRYPTO0,
      CRYPTO_CMD_INSTR_SHA,
      CRYPTO_CMD_INSTR_MADD32,
      CRYPTO_CMD_INSTR_DDATA0TODDATA1);

   //Read the resulting digest from DDATA0BIG
   CRYPTO_DDataRead(&CRYPTO0->DDATA0BIG, context->h);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Convert from big-endian byte order to host byte order
   context->h[0] = betoh32(context->h[0]);
   context->h[1] = betoh32(context->h[1]);
   context->h[2] = betoh32(context->h[2]);
   context->h[3] = betoh32(context->h[3]);
   context->h[4] = betoh32(context->h[4]);
   context->h[5] = betoh32(context->h[5]);
   context->h[6] = betoh32(context->h[6]);
   context->h[7] = betoh32(context->h[7]);
}

#endif
#endif
