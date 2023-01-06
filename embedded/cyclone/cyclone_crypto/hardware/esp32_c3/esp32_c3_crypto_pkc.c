/**
 * @file esp32_c3_crypto_pkc.c
 * @brief ESP32-C3 public-key hardware accelerator
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
#include "esp_crypto_lock.h"
#include "soc/hwcrypto_reg.h"
#include "driver/periph_ctrl.h"
#include "hardware/esp32_c3/esp32_c3_crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/curve25519.h"
#include "ecc/curve448.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_C3_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief RSA module initialization
 **/

void esp32c3RsaInit(void)
{
   //Enable RSA module
   periph_module_enable(PERIPH_RSA_MODULE);

   //Clear SYSTEM_RSA_MEM_PD bit
   REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

   //Software should query RSA_CLEAN_REG after being released from reset, and
   //before writing to any RSA Accelerator memory blocks or registers for the
   //first time
   while(REG_READ(RSA_QUERY_CLEAN_REG) == 0)
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

   //The accelerator supports large-number multiplication up to 1536 bits
   if(aLen <= 48 && bLen <= 48)
   {
      //All numbers in calculation must be of the same length
      n = 1;
      n = MAX(n, aLen);
      n = MAX(n, bLen);

      //Acquire exclusive access to the RSA module
      esp_crypto_mpi_lock_acquire();

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
      //Set mode register
      REG_WRITE(RSA_LENGTH_REG, (2 * n) - 1);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         if(i < a->size)
         {
            REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a->data[i]);
         }
         else
         {
            REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
         }
      }

      //The second operand will not be written to the base address of the
      //RSA_Z_MEM memory. This area must be filled with zeroes
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
      }

      //The second operand must be written to the base address of the
      //RSA_Z_MEM memory plus the address offset 4 * n
      for(i = 0; i < n; i++)
      {
         if(i < b->size)
         {
            REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, b->data[i]);
         }
         else
         {
            REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, 0);
         }
      }

      //Start large-number multiplication
      REG_WRITE(RSA_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
      {
      }

      //Set the sign of the result
      r->sign = (a->sign == b->sign) ? 1 : -1;

      //The length of the result is 2 x N bits
      error = mpiGrow(r, n * 2);

      //Check status code
      if(!error)
      {
         //Read the result from RSA_Z_MEM
         for(i = 0; i < r->size; i++)
         {
            if(i < (n * 2))
            {
               r->data[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
            }
            else
            {
               r->data[i] = 0;
            }
         }
      }

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

      //Release exclusive access to the RSA module
      esp_crypto_mpi_lock_release();
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

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(p);
   //Retrieve the length of the exponent, in bits
   expLen = mpiGetBitLength(e);

   //The accelerator supports operand lengths up to 3072 bits
   if(modLen > 0 && modLen <= 3072 && expLen > 0 && expLen <= 3072)
   {
      //All numbers in calculation must be of the same length
      n = MAX(modLen, expLen);
      n = (n + 31) / 32;

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
         esp_crypto_mpi_lock_acquire();

         //Clear the interrupt flag
         REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
         //Set mode register
         REG_WRITE(RSA_LENGTH_REG, n - 1);

         //Copy the operand to RSA_X_MEM
         for(i = 0; i < n; i++)
         {
            if(i < t.size)
            {
               REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, t.data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the exponent to RSA_Y_MEM
         for(i = 0; i < n; i++)
         {
            if(i < e->size)
            {
               REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, e->data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the modulus to RSA_M_MEM
         for(i = 0; i < n; i++)
         {
            if(i < p->size)
            {
               REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, p->data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
         for(i = 0; i < n; i++)
         {
            if(i < r2.size)
            {
               REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2.data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
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
         REG_WRITE(RSA_M_DASH_REG, m);

         //Enable search option
         REG_WRITE(RSA_SEARCH_ENABLE_REG, 1);
         REG_WRITE(RSA_SEARCH_POS_REG, expLen - 1);

         //Start modular exponentiation
         REG_WRITE(RSA_MODEXP_START_REG, 1);

         //Wait for the operation to complete
         while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
         {
         }

         //Adjust the size of the result if necessary
         error = mpiGrow(r, n);

         //Check status code
         if(!error)
         {
            //Read the result from RSA_Z_MEM
            for(i = 0; i < r->size; i++)
            {
               if(i < n)
               {
                  r->data[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
               }
               else
               {
                  r->data[i] = 0;
               }
            }
         }

         //Clear the interrupt flag
         REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

         //Release exclusive access to the RSA module
         esp_crypto_mpi_lock_release();
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

   //Acquire exclusive access to the RSA module
   esp_crypto_mpi_lock_acquire();

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
   //Set mode register
   REG_WRITE(RSA_LENGTH_REG, 7);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < 8; i++)
   {
      REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   //Copy the second operand to RSA_Y_MEM
   for(i = 0; i < 8; i++)
   {
      REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, b[i]);
   }

   //Copy the modulus to RSA_M_MEM
   REG_WRITE(RSA_MEM_M_BLOCK_BASE, 0xFFFFFFED);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 4, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 8, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 12, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 16, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 20, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 24, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 28, 0x7FFFFFFF);

   //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 0x000005A4);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 4, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 8, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 12, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 16, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 20, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 24, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 28, 0x00000000);

   //Write the value of M' to RSA_M_PRIME_REG
   REG_WRITE(RSA_M_DASH_REG, 0x286BCA1B);
   //Start large-number modular multiplication
   REG_WRITE(RSA_MOD_MULT_START_REG, 1);

   //Wait for the operation to complete
   while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
   {
   }

   //Read the result from RSA_Z_MEM
   for(i = 0; i < 8; i++)
   {
      r[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
   }

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

   //Release exclusive access to the RSA module
   esp_crypto_mpi_lock_release();
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
   esp_crypto_mpi_lock_acquire();

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
   //Set mode register
   REG_WRITE(RSA_LENGTH_REG, 13);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < 14; i++)
   {
      REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   //Copy the second operand to RSA_Y_MEM
   for(i = 0; i < 14; i++)
   {
      REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, b[i]);
   }

   //Copy the modulus to RSA_M_MEM
   REG_WRITE(RSA_MEM_M_BLOCK_BASE, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 4, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 8, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 12, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 16, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 20, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 24, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 28, 0xFFFFFFFE);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 32, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 36, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 40, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 44, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 48, 0xFFFFFFFF);
   REG_WRITE(RSA_MEM_M_BLOCK_BASE + 52, 0xFFFFFFFF);

   //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 0x00000002);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 4, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 8, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 12, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 16, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 20, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 24, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 28, 0x00000003);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 32, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 36, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 40, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 44, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 48, 0x00000000);
   REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 52, 0x00000000);

   //Write the value of M' to RSA_M_PRIME_REG
   REG_WRITE(RSA_M_DASH_REG, 0x00000001);
   //Start large-number modular multiplication
   REG_WRITE(RSA_MOD_MULT_START_REG, 1);

   //Wait for the operation to complete
   while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
   {
   }

   //Read the result from RSA_Z_MEM
   for(i = 0; i < 14; i++)
   {
      r[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
   }

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

   //Release exclusive access to the RSA module
   esp_crypto_mpi_lock_release();
}

#endif
#endif
