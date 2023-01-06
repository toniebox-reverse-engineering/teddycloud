/**
 * @file mimxrt1170_crypto_pkc.c
 * @brief i.MX RT1170 public-key hardware accelerator
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
#include "fsl_device_registers.h"
#include "fsl_caam.h"
#include "core/crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto_pkc.h"
#include "ecc/ec.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1170_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
PkhaArgs pkhaArgs;
PkhaEccArgs pkhaEccArgs;


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = A * B mod P
 * @param[in] a The first operand A
 * @param[in] b The second operand B
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiMulMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;
   status_t status;
   size_t aLen;
   size_t bLen;
   size_t modLen;
   size_t resultLen;
   caam_handle_t caamHandle;
   Mpi ta;
   Mpi tb;

   //Initialize multiple precision integers
   mpiInit(&ta);
   mpiInit(&tb);

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen <= 512)
   {
      //Reduce the first operand
      error = mpiMod(&ta, a, p);

      //Check status code
      if(!error)
      {
         //Reduce the second operand
         error = mpiMod(&tb, b, p);
      }

      //Check status code
      if(!error)
      {
         //Retrieve the length of the first operand, in bytes
         aLen = mpiGetByteLength(&ta);
         //Retrieve the length of the second operand, in bytes
         bLen = mpiGetByteLength(&tb);

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1170CryptoMutex);

         //Copy first operand
         mpiWriteRaw(&ta, pkhaArgs.a, aLen);
         //Copy second operand
         mpiWriteRaw(&tb, pkhaArgs.b, bLen);
         //Copy modulus
         mpiWriteRaw(p, pkhaArgs.p, modLen);

         //Perform modular multiplication
         status = CAAM_PKHA_ModMul(CAAM, &caamHandle, pkhaArgs.a, aLen,
            pkhaArgs.b, bLen, pkhaArgs.p, modLen, pkhaArgs.r, &resultLen,
            kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue,
            kCAAM_PKHA_NormalValue, kCAAM_PKHA_TimingEqualized);

         //Check status code
         if(status == kStatus_Success)
         {
            //Copy resulting integer
            error = mpiReadRaw(r, pkhaArgs.r, resultLen);
         }
         else
         {
            //Report an error
            error = ERROR_FAILURE;
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1170CryptoMutex);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release multiple precision integers
   mpiFree(&ta);
   mpiFree(&tb);

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
   status_t status;
   size_t scalarLen;
   size_t expLen;
   size_t modLen;
   size_t resultLen;
   caam_handle_t caamHandle;

   //Retrieve the length of the exponent, in bytes
   expLen = mpiGetByteLength(e);
   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen > 0 && modLen <= 512 && expLen > 0 && expLen <= 512)
   {
      //Reduce the integer first
      error = mpiMod(r, a, p);

      //Check status code
      if(!error)
      {
         //Retrieve the length of the integer, in bytes
         scalarLen = mpiGetByteLength(r);

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1170CryptoMutex);

         //Copy scalar
         mpiWriteRaw(r, pkhaArgs.a, scalarLen);
         //Copy exponent
         mpiWriteRaw(e, pkhaArgs.e, expLen);
         //Copy modulus
         mpiWriteRaw(p, pkhaArgs.p, modLen);

         //Perform modular exponentiation
         status = CAAM_PKHA_ModExp(CAAM, &caamHandle, pkhaArgs.a, scalarLen,
            pkhaArgs.p, modLen, pkhaArgs.e, expLen, pkhaArgs.r, &resultLen,
            kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue,
            kCAAM_PKHA_TimingEqualized);

         //Check status code
         if(status == kStatus_Success)
         {
            //Copy resulting integer
            error = mpiReadRaw(r, pkhaArgs.r, resultLen);
         }
         else
         {
            //Report an error
            error = ERROR_FAILURE;
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1170CryptoMutex);
      }
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
 * @brief Scalar multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   status_t status;
   size_t modLen;
   size_t scalarLen;
   caam_handle_t caamHandle;
   caam_pkha_ecc_point_t input;
   caam_pkha_ecc_point_t output;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the scalar, in bytes
   scalarLen = mpiGetByteLength(d);

   //Check the length of the operands
   if(modLen <= 66 && scalarLen <= 66)
   {
      //Set CAAM job ring
      caamHandle.jobRing = kCAAM_JobRing0;

      //Acquire exclusive access to the CAAM module
      osAcquireMutex(&mimxrt1170CryptoMutex);

      //Copy domain parameters
      mpiWriteRaw(&params->p, pkhaEccArgs.p, modLen);
      mpiWriteRaw(&params->a, pkhaEccArgs.a, modLen);
      mpiWriteRaw(&params->b, pkhaEccArgs.b, modLen);

      //Copy scalar
      mpiWriteRaw(d, pkhaEccArgs.d, scalarLen);

      //Copy input point
      mpiWriteRaw(&s->x, pkhaEccArgs.gx, modLen);
      mpiWriteRaw(&s->y, pkhaEccArgs.gy, modLen);
      input.X = pkhaEccArgs.gx;
      input.Y = pkhaEccArgs.gy;

      //Specify the buffer where to store the output point
      output.X = pkhaEccArgs.qx;
      output.Y = pkhaEccArgs.qy;

      //Perform scalar multiplication
      status = CAAM_PKHA_ECC_PointMul(CAAM, &caamHandle, &input, pkhaEccArgs.d,
         scalarLen, pkhaEccArgs.p, NULL, pkhaEccArgs.a, pkhaEccArgs.b,
         modLen, kCAAM_PKHA_TimingEqualized, kCAAM_PKHA_IntegerArith, &output);

      //Check status code
      if(status == kStatus_Success)
      {
         //Copy the x-coordinate of the result
         error = mpiReadRaw(&r->x, pkhaEccArgs.qx, modLen);

         //Check status code
         if(!error)
         {
            //Copy the y-coordinate of the result
            error = mpiReadRaw(&r->y, pkhaEccArgs.qy, modLen);
         }

         //Check status code
         if(!error)
         {
            //Set the z-coordinate of the result
            error = mpiSetValue(&r->z, 1);
         }
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the CAAM module
      osReleaseMutex(&mimxrt1170CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
