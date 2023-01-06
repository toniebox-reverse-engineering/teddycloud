/**
 * @file esp32_crypto_pkc.c
 * @brief ESP32 public-key hardware accelerator
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
#include "soc/hwcrypto_reg.h"
#include "soc/dport_access.h"
#include "driver/periph_ctrl.h"
#include "hardware/esp32/esp32_crypto.h"
#include "hardware/esp32/esp32_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/curve25519.h"
#include "ecc/curve448.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief RSA module initialization
 **/

void esp32RsaInit(void)
{
   //Enable RSA module
   periph_module_enable(PERIPH_RSA_MODULE);

   //Software should query RSA_CLEAN_REG after being released from reset, and
   //before writing to any RSA Accelerator memory blocks or registers for the
   //first time
   while(DPORT_REG_READ(RSA_CLEAN_REG) == 0)
   {
   }
}


/**
 * @brief Multiple precision multiplication
 * @param[out] r Resulting integer R = A * B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiMul(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   size_t i;
   size_t n;
   size_t aLen;
   size_t bLen;

   //Retrieve the length of the first operand, in 32-bit words
   aLen = mpiGetLength(a);
   //Retrieve the length of the second operand, in 32-bit words
   bLen = mpiGetLength(b);

   //The accelerator supports large-number multiplication up to 2048 bits
   if(aLen <= 64 && bLen <= 64)
   {
      //All numbers in calculation must be of the same length
      n = 1;
      n = MAX(n, aLen);
      n = MAX(n, bLen);
      n = (n + 7) & ~7U;

      //Acquire exclusive access to the RSA module
      osAcquireMutex(&esp32CryptoMutex);

      //Clear the interrupt flag
      DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
      //Set mode register
      DPORT_REG_WRITE(RSA_MULT_MODE_REG, (n / 8) - 1 + 8);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         if(i < a->size)
         {
            DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a->data[i]);
         }
         else
         {
            DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
         }
      }

      //The second operand will not be written to the base address of the
      //RSA_Z_MEM memory. This area must be filled with zeroes
      for(i = 0; i < n; i++)
      {
         DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
      }

      //The second operand must be written to the base address of the
      //RSA_Z_MEM memory plus the address offset 4 * n
      for(i = 0; i < n; i++)
      {
         if(i < b->size)
         {
            DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, b->data[i]);
         }
         else
         {
            DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, 0);
         }
      }

      //Start large-number multiplication
      DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
      {
      }

      //Set the sign of the result
      r->sign = (a->sign == b->sign) ? 1 : -1;

      //The length of the result is 2 x N bits
      error = mpiGrow(r, n * 2);

      //Check status code
      if(!error)
      {
         //Disable interrupts only on current CPU
         DPORT_INTERRUPT_DISABLE();

         //Read the result from RSA_Z_MEM
         for(i = 0; i < r->size; i++)
         {
            if(i < (n * 2))
            {
               r->data[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
            }
            else
            {
               r->data[i] = 0;
            }
         }

         //Restore the previous interrupt level
         DPORT_INTERRUPT_RESTORE();
      }

      //Clear the interrupt flag
      DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

      //Release exclusive access to the RSA module
      osReleaseMutex(&esp32CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpMod(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   size_t i;
   size_t n;
   size_t modLen;
   size_t expLen;
   uint32_t m;
   Mpi t;
   Mpi r2;

   //Initialize multiple precision integers
   mpiInit(&t);
   mpiInit(&r2);

   //Retrieve the length of the modulus, in 32-bit words
   modLen = mpiGetLength(p);
   //Retrieve the length of the exponent, in 32-bit words
   expLen = mpiGetLength(e);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen > 0 && modLen <= 128 && expLen > 0 && expLen <= 128)
   {
      //All numbers in calculation must be of the same length
      n = MAX(modLen, expLen);
      n = (n + 15) & ~15U;

      //Reduce the operand first
      error = mpiMod(&t, a, p);

      //Let R = b^n and pre-compute the quantity R^2 mod M
      if(!error)
      {
         error = mpiSetValue(&r2, 1);
      }

      if(!error)
      {
         error = mpiShiftLeft(&r2, n * 2 * 32);
      }

      if(!error)
      {
         error = mpiMod(&r2, &r2, p);
      }

      //Check status code
      if(!error)
      {
         //Acquire exclusive access to the RSA module
         osAcquireMutex(&esp32CryptoMutex);

         //Clear the interrupt flag
         DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
         //Set mode register
         DPORT_REG_WRITE(RSA_MODEXP_MODE_REG, (n / 16) - 1);

         //Copy the operand to RSA_X_MEM
         for(i = 0; i < n; i++)
         {
            if(i < t.size)
            {
               DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, t.data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the exponent to RSA_Y_MEM
         for(i = 0; i < n; i++)
         {
            if(i < e->size)
            {
               DPORT_REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, e->data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the modulus to RSA_M_MEM
         for(i = 0; i < n; i++)
         {
            if(i < p->size)
            {
               DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, p->data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
         for(i = 0; i < n; i++)
         {
            if(i < r2.size)
            {
               DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2.data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
            }
         }

         //Use Newton's method to compute the inverse of M[0] mod 2^32
         for(m = 2 - p->data[0], i = 0; i < 4; i++)
         {
            m = m * (2 - m * p->data[0]);
         }

         //Precompute M' = -1/M[0] mod 2^32;
         m = ~m + 1;

         //Write the value of M' to RSA_M_PRIME_REG
         DPORT_REG_WRITE(RSA_M_DASH_REG, m);

         //Start modular exponentiation
         DPORT_REG_WRITE(RSA_MODEXP_START_REG, 1);

         //Wait for the operation to complete
         while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
         {
         }

         //Adjust the size of the result if necessary
         error = mpiGrow(r, n);

         //Check status code
         if(!error)
         {
            //Disable interrupts only on current CPU
            DPORT_INTERRUPT_DISABLE();

            //Read the result from RSA_Z_MEM
            for(i = 0; i < r->size; i++)
            {
               if(i < n)
               {
                  r->data[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
               }
               else
               {
                  r->data[i] = 0;
               }
            }

            //Restore the previous interrupt level
            DPORT_INTERRUPT_RESTORE();
         }

         //Clear the interrupt flag
         DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

         //Release exclusive access to the RSA module
         osReleaseMutex(&esp32CryptoMutex);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release previously allocated memory
   mpiFree(&t);
   mpiFree(&r2);

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

   //Acquire exclusive access to the RSA module
   osAcquireMutex(&esp32CryptoMutex);

   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
   //Set mode register
   DPORT_REG_WRITE(RSA_MULT_MODE_REG, 8);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < 8; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   //The second operand will not be written to the base address of the
   //RSA_Z_MEM memory. This area must be filled with zeroes
   for(i = 0; i < 8; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
   }

   //The second operand must be written to the base address of the
   //RSA_Z_MEM memory plus the address offset 32
   for(i = 0; i < 8; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + 32 + i * 4, b[i]);
   }

   //Start large-number multiplication
   DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
   {
   }

   //Disable interrupts only on current CPU
   DPORT_INTERRUPT_DISABLE();

   //Read the result from RSA_Z_MEM
   for(i = 0; i < 16; i++)
   {
      u[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
   }

   //Restore the previous interrupt level
   DPORT_INTERRUPT_RESTORE();
   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

   //Release exclusive access to the RSA module
   osReleaseMutex(&esp32CryptoMutex);

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
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;

   //Acquire exclusive access to the RSA module
   osAcquireMutex(&esp32CryptoMutex);

   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
   //Set mode register
   DPORT_REG_WRITE(RSA_MULT_MODE_REG, 0);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < 14; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   //Pad the first operand with zeroes
   DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + 56, 0);
   DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + 60, 0);

   //Copy the modulus to RSA_M_MEM
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 4, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 8, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 12, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 16, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 20, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 24, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 28, 0xFFFFFFFE);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 32, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 36, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 40, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 44, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 48, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 52, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 56, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 60, 0x00000000);

   //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 4, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 8, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 12, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 16, 0x00000002);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 20, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 24, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 28, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 32, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 36, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 40, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 44, 0x00000003);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 48, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 52, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 56, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 60, 0x00000000);

   //Write the value of M' to RSA_M_PRIME_REG
   DPORT_REG_WRITE(RSA_M_DASH_REG, 0x00000001);
   //Start the first round of the operation
   DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

   //Wait for the first round to complete
   while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
   {
   }

   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

   //Copy the second operand to RSA_X_MEM
   for(i = 0; i < 14; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, b[i]);
   }

   //Pad the second operand with zeroes
   DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + 56, 0);
   DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + 60, 0);

   //Start the second round of the operation
   DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

   //Wait for the second round to complete
   while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
   {
   }

   //Disable interrupts only on current CPU
   DPORT_INTERRUPT_DISABLE();

   //Read the result from RSA_Z_MEM
   for(i = 0; i < 14; i++)
   {
      r[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
   }

   //Restore the previous interrupt level
   DPORT_INTERRUPT_RESTORE();
   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

   //Release exclusive access to the RSA module
   osReleaseMutex(&esp32CryptoMutex);
}

#endif
#endif
