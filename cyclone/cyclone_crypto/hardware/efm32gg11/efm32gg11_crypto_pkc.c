/**
 * @file efm32gg11_crypto_pkc.c
 * @brief EFM32 Giant Gecko 11 public-key hardware accelerator
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
#include "hardware/efm32gg11/efm32gg11_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/curve25519.h"
#include "debug.h"

//Check crypto library configuration
#if (EFM32GG11_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief Fast modular multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 * @return Error code
 **/

error_t ecMulMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b)
{
   error_t error;
   uint_t i;
   uint32_t temp[8];

   //Check elliptic curve
   if(!osStrcmp(params->name, "secp256r1"))
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the first operand
      for(i = 0; i < a->size && i < 8; i++)
      {
         temp[i] = a->data[i];
      }

      while(i < 8)
      {
         temp[i++] = 0;
      }

      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, temp);

      //Copy the second operand
      for(i = 0; i < b->size && i < 8; i++)
      {
         temp[i] = b->data[i];
      }

      while(i < 8)
      {
         temp[i++] = 0;
      }

      CRYPTO_DDataWrite(&CRYPTO0->DDATA2, temp);

      //Compute R = (A * B) mod p
      CRYPTO_EXECUTE_2(CRYPTO0,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, temp);

      //Adjust the size of the integer
      error = mpiGrow(r, 8);

      //Copy the result
      for(i = 0; i < 8; i++)
      {
         r->data[i] = temp[i];
      }

      while(i < r->size)
      {
         r->data[i++] = 0;
      }

      //Set the sign of the result
      r->sign = 1;

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      //Compute R = A * B
      error = mpiMul(r, a, b);

      //Check status code
      if(!error)
      {
         //Compute R = (A * B) mod p
         if(params->mod != NULL)
         {
            error = params->mod(r, &params->p);
         }
         else
         {
            error = mpiMod(r, r, &params->p);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Fast modular squaring
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @return Error code
 **/

error_t ecSqrMod(const EcDomainParameters *params, Mpi *r, const Mpi *a)
{
   error_t error;
   uint_t i;
   uint32_t temp[8];

   //Check elliptic curve
   if(!osStrcmp(params->name, "secp256r1"))
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the operand
      for(i = 0; i < a->size && i < 8; i++)
      {
         temp[i] = a->data[i];
      }

      while(i < 8)
      {
         temp[i++] = 0;
      }

      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, temp);

      //Compute R = (A ^ 2) mod p
      CRYPTO_EXECUTE_3(CRYPTO0,
         CRYPTO_CMD_INSTR_DDATA1TODDATA2,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, temp);

      //Adjust the size of the integer
      error = mpiGrow(r, 8);

      //Copy the result
      for(i = 0; i < 8; i++)
      {
         r->data[i] = temp[i];
      }

      while(i < r->size)
      {
         r->data[i++] = 0;
      }

      //Set the sign of the result
      r->sign = 1;

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      //Compute R = A ^ 2
      error = mpiMul(r, a, a);

      //Check status code
      if(!error)
      {
         //Compute R = (A ^ 2) mod p
         if(params->mod != NULL)
         {
            error = params->mod(r, &params->p);
         }
         else
         {
            error = mpiMod(r, r, &params->p);
         }
      }
   }

   //Return status code
   return error;
}


#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint64_t temp;
   uint32_t u[16];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Set wide arithmetic configuration
   CRYPTO0->WAC = 0;
   CRYPTO0->CTRL = 0;

   //Set CRYPTO module parameters
   CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperand256Bits);
   CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

   //Copy the first operand
   CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);
   //Copy the second operand
   CRYPTO_DDataWrite(&CRYPTO0->DDATA2, b);

   //Compute R = A * B
   CRYPTO_EXECUTE_2(CRYPTO0,
      CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
      CRYPTO_CMD_INSTR_LMUL);

   //Wait for the instruction sequence to complete
   CRYPTO_InstructionSequenceWait(CRYPTO0);

   //Copy the resulting value
   CRYPTO_DDataRead(&CRYPTO0->DDATA0, u);
   CRYPTO_DDataRead(&CRYPTO0->DDATA1, u + 8);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Reduce bit 255 (2^255 = 19 mod p)
   temp = (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (first pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      temp += (uint64_t) u[i + 8] * 38;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce bit 256 (2^256 = 38 mod p)
   temp *= 38;
   //Reduce bit 255 (2^255 = 19 mod p)
   temp += (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (second pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve25519Red(r, u);
}


/**
 * @brief Modular squaring
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve25519Sqr(uint32_t *r, const uint32_t *a)
{
   uint_t i;
   uint64_t temp;
   uint32_t u[16];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Set wide arithmetic configuration
   CRYPTO0->WAC = 0;
   CRYPTO0->CTRL = 0;

   //Set CRYPTO module parameters
   CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperand256Bits);
   CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

   //Copy the operand
   CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);

   //Compute R = A ^ 2
   CRYPTO_EXECUTE_3(CRYPTO0,
      CRYPTO_CMD_INSTR_DDATA1TODDATA2,
      CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
      CRYPTO_CMD_INSTR_LMUL);

   //Wait for the instruction sequence to complete
   CRYPTO_InstructionSequenceWait(CRYPTO0);

   //Copy the resulting value
   CRYPTO_DDataRead(&CRYPTO0->DDATA0, u);
   CRYPTO_DDataRead(&CRYPTO0->DDATA1, u + 8);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);

   //Reduce bit 255 (2^255 = 19 mod p)
   temp = (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (first pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      temp += (uint64_t) u[i + 8] * 38;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce bit 256 (2^256 = 38 mod p)
   temp *= 38;
   //Reduce bit 255 (2^255 = 19 mod p)
   temp += (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (second pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve25519Red(r, u);
}

#endif
#endif
