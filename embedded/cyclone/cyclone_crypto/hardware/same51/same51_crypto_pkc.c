/**
 * @file same51_crypto_pkc.c
 * @brief SAME51 public-key hardware accelerator (PUKCC)
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
#include "sam.h"
#include "pukcc/CryptoLib_typedef_pb.h"
#include "pukcc/CryptoLib_Headers_pb.h"
#include "core/crypto.h"
#include "hardware/same51/same51_crypto.h"
#include "hardware/same51/same51_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (SAME51_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
PPUKCL_PARAM pvPUKCLParam;
PUKCL_PARAM PUKCLParam;


/**
 * @brief Initialize PUKCC module
 **/

error_t pukccInit(void)
{
   //Enable PUKCC clock
   MCLK_REGS->MCLK_AHBMASK |= MCLK_AHBMASK_PUKCC_Msk;

   //Clear PUKCLParam structure
   osMemset(&PUKCLParam, 0, sizeof(PUKCL_PARAM));
   pvPUKCLParam = &PUKCLParam;

   //Initialize PUKCC
   vPUKCL_Process(SelfTest, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) != PUKCL_OK)
      return ERROR_FAILURE;

   //Check version number
   if(pvPUKCLParam->P.PUKCL_SelfTest.u4Version != PUKCL_VERSION)
      return ERROR_FAILURE;

   //The return values from the SelfTest service must be compared against
   //known values mentioned in the service description
   if(pvPUKCLParam->P.PUKCL_SelfTest.u4CheckNum1 != 0x6E70DDD2)
      return ERROR_FAILURE;

   if(pvPUKCLParam->P.PUKCL_SelfTest.u4CheckNum2 != 0x25C8D64F)
      return ERROR_FAILURE;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Import byte array
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] array Pointer to the byte array
 * @param[in] arrayLen Length of the array to be copied
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *pukccImportArray(uint8_t **dest, const uint8_t *array,
   size_t arrayLen, size_t totalLen)
{
   size_t i;
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Copy the byte array to the crypto memory
   for(i = 0; i < arrayLen; i++)
   {
      p[i] = array[arrayLen - 1 - i];
   }

   //Pad the data with zeroes
   while(i < totalLen)
   {
      p[i++] = 0;
   }

   //Advance data pointer
   *dest = p + i;

   //Return a pointer to the initialized area
   return p;
}


/**
 * @brief Import multiple-precision integer
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *pukccImportMpi(uint8_t **dest, const Mpi *src, size_t totalLen)
{
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Copy the multiple-precision integer to the crypto memory
   mpiExport(src, p, totalLen, MPI_FORMAT_LITTLE_ENDIAN);

   //Advance data pointer
   *dest = p + totalLen;

   //Return a pointer to the initialized area
   return p;
}


/**
 * @brief Initialize workspace area
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *pukccWorkspace(uint8_t **dest, size_t totalLen)
{
   size_t i;
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Initialize workspace area
   for(i = 0; i < totalLen; i++)
   {
      p[i] = 0;
   }

   //Advance data pointer
   *dest = p + i;

   //Return a pointer to the initialized area
   return p;
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
   size_t m;
   size_t n;
   uint8_t *pos;
   PukccFmultParams params;

   //Retrieve the length of the input integer, in bytes
   m = mpiGetByteLength(a);
   m = (m + 3U) & ~3U;

   //Retrieve the length of the modulus, in bytes
   n = mpiGetByteLength(b);
   n = (n + 3U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy input integer X
   params.x = pukccImportMpi(&pos, a, m);
   //Copy input integer Y
   params.y = pukccImportMpi(&pos, b, n);

   //Unused parameters
   params.z = 0;
   params.mod = 0;
   params.cns = 0;

   //Initialize output integer R
   params.r = pukccWorkspace(&pos, m + n);

   //Set Fmult service parameters
   PUKCL(u2Option) = SET_MULTIPLIEROPTION(PUKCL_FMULT_ONLY) |
      SET_CARRYOPTION(CARRY_NONE);
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_Fmult(u2ModLength) = 0;
   PUKCL_Fmult(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_Fmult(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_Fmult(u2XLength) = m;
   PUKCL_Fmult(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);
   PUKCL_Fmult(u2YLength) = n;
   PUKCL_Fmult(nu1YBase) = PUKCC_FAR_TO_NEAR(params.y);
   PUKCL_Fmult(nu1ZBase) = PUKCC_FAR_TO_NEAR(params.z);
   PUKCL_Fmult(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);

   //Perform multiplication
   vPUKCL_Process(Fmult, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //If FMult is without reduction, R is filled with the final result
      error = mpiImport(r, params.r, m + n, MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Set the sign of the result
         r->sign = (a->sign == b->sign) ? 1 : -1;
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Modulo operation
 * @param[out] r Resulting integer R = A mod P
 * @param[in] a The multiple precision integer to be reduced
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiMod2(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   size_t n;
   size_t modLen;
   uint8_t *pos;
   PukccRedModParams params;

   //Retrieve the length of the input integer, in bytes
   n = mpiGetByteLength(a);

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);
   modLen = (modLen + 3U) & ~3U;

   //Check the length of the input integer
   if(n > (2 * modLen + 4))
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, p, modLen + 4);
   //Initialize workspace CNS
   params.cns = pukccWorkspace(&pos, 68);
   //Initialize output integer R
   params.r = pukccWorkspace(&pos, modLen + 4);
   //Copy input integer X
   params.x = pukccImportMpi(&pos, a, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_REDUCTION | PUKCL_REDMOD_USING_DIVISION;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //If FMult is without reduction, R is filled with the final result
      error = mpiImport(r, params.r, modLen, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Modular inverse
 * @param[out] r Resulting integer R = A^-1 mod P
 * @param[in] a The multiple precision integer A
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiInvMod(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   size_t m;
   size_t n;
   uint8_t *pos;
   PukccGcdParams params;

   //Retrieve the length of the input integer, in bytes
   m = mpiGetByteLength(a);
   //Retrieve the length of the modulus, in bytes
   n = mpiGetByteLength(p);

   //Compute the length of the areas X, Y, A and Z
   n = MAX(n, m);
   n = (n + 7U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy input integer
   params.x = pukccImportMpi(&pos, a, n);
   //Copy modulus
   params.y = pukccImportMpi(&pos, p, n);
   //Initialize output integer A
   params.a = pukccWorkspace(&pos, n);
   //Initialize output integer Z
   params.z = pukccWorkspace(&pos, n + 4);
   //Initialize workspace >
   params.w = pukccWorkspace(&pos, 32);

   //Set GCD service parameters
   PUKCL(Specific).Gf2n = 0;
   PUKCL_GCD(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);
   PUKCL_GCD(nu1YBase) = PUKCC_FAR_TO_NEAR(params.y);
   PUKCL_GCD(nu1ABase) = PUKCC_FAR_TO_NEAR(params.a);
   PUKCL_GCD(nu1ZBase) = PUKCC_FAR_TO_NEAR(params.z);
   PUKCL_GCD(nu1WorkSpace) = PUKCC_FAR_TO_NEAR(params.w);
   PUKCL_GCD(u2Length) = n;

   //Calculate the modular inverse
   vPUKCL_Process(GCD, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Copy output integer Z
      error = mpiImport(r, params.a, n, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
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
   size_t n;
   size_t modLen;
   size_t expLen;
   uint8_t *pos;
   PukccExpModParams params;

   //Retrieve the length of the input integer, in bytes
   n = mpiGetByteLength(a);

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);
   modLen = (modLen + 3U) & ~3U;

   //Retrieve the length of the exponent, in bytes
   expLen = mpiGetByteLength(e);
   expLen = (expLen + 3U) & ~3U;

   //Check the length of the input integer
   if(n > (2 * modLen + 4))
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, p, modLen + 4);
   //Initialize reduction constant
   params.cns = pukccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = pukccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = pukccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy input number
      params.x = pukccImportMpi(&pos, a, 2 * modLen + 8);

      //Set RedMod service parameters
      PUKCL(u2Option) = PUKCL_REDMOD_REDUCTION | PUKCL_REDMOD_USING_FASTRED;
      PUKCL(Specific).CarryIn = 0;
      PUKCL(Specific).Gf2n = 0;
      PUKCL_RedMod(u2ModLength) = modLen;
      PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.x);
      PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

      //Perform fast modular reduction
      vPUKCL_Process(RedMod, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Set RedMod service parameters
      PUKCL(u2Option) = PUKCL_REDMOD_NORMALIZE;
      PUKCL(Specific).CarryIn = 0;
      PUKCL(Specific).Gf2n = 0;
      PUKCL_RedMod(u2ModLength) = modLen;
      PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.x);
      PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

      //Normalize the result
      vPUKCL_Process(RedMod, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //The number to be exponentiated is followed by four 32-bit words
      //that are used during the computations as a workspace
      pos = params.x + modLen;
      pukccWorkspace(&pos, 16);

      //The exponent must be given with a supplemental word on the LSB
      //side (low addresses). This word shall be set to zero
      params.exp = pukccWorkspace(&pos, 4);
      pukccImportMpi(&pos, e, expLen);

      //Initialize workspace
      params.w = pukccWorkspace(&pos, 3 * (modLen + 4) + 8);

      //Set ExpMod service parameters
      PUKCL(u2Option) = PUKCL_EXPMOD_REGULARRSA | PUKCL_EXPMOD_WINDOWSIZE_1 |
         PUKCL_EXPMOD_EXPINPUKCCRAM;
      PUKCL_ExpMod(u2ModLength) = modLen;
      PUKCL_ExpMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ExpMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ExpMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);
      PUKCL_ExpMod(nu1PrecompBase) = PUKCC_FAR_TO_NEAR(params.w);
      PUKCL_ExpMod(u2ExpLength) = expLen;
      PUKCL_ExpMod(pfu1ExpBase) = params.exp;
      PUKCL_ExpMod(u1Blinding) = 0;

      //Perform modular exponentiation
      vPUKCL_Process(ExpMod, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Copy resulting integer
      error = mpiImport(r, params.x, modLen, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Test whether a number is probable prime
 * @param[in] a Pointer to a multiple precision integer
 * @return Error code
 **/

error_t mpiCheckProbablePrime(const Mpi *a)
{
   error_t error;
   uint_t k;
   size_t n;
   uint8_t *pos;
   PukccPrimeGenParams params;

   //Retrieve the length of the input integer, in bits
   n = mpiGetBitLength(a);

   //Prime numbers of a size lower than 96 bits cannot be tested by this
   //service
   if(n < 96)
      return ERROR_INVALID_LENGTH;

   //The number of repetitions controls the error probability
   if(n >= 1300)
   {
      k = 2;
   }
   else if(n >= 850)
   {
      k = 3;
   }
   else if(n >= 650)
   {
      k = 4;
   }
   else if(n >= 550)
   {
      k = 5;
   }
   else if(n >= 450)
   {
      k = 6;
   }
   else if(n >= 400)
   {
      k = 7;
   }
   else if(n >= 350)
   {
      k = 8;
   }
   else if(n >= 300)
   {
      k = 9;
   }
   else if(n >= 250)
   {
      k = 12;
   }
   else if(n >= 200)
   {
      k = 15;
   }
   else if(n >= 150)
   {
      k = 18;
   }
   else
   {
      k = 27;
   }

   //Retrieve the length of the input integer, in bytes
   n = mpiGetByteLength(a);
   n = (n + 3U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //One additional word is used on the LSB side of the NBase parameter. As
   //a consequence, the parameter nu1NBase must never be at the beginning of
   //the crypto RAM, but at least at one word from the beginning
   pukccWorkspace(&pos, 4);

   //Copy the number to test
   params.n = pukccImportMpi(&pos, a, n + 4);
   //Cns is used as a workspace
   params.cns = pukccWorkspace(&pos, n + 12);
   //Rnd is used as a workspace
   params.rnd = pukccWorkspace(&pos, MAX(n + 16, 64));
   //Precomp is used as a precomputation workspace
   params.w = pukccWorkspace(&pos, MAX(3 * (n + 4), n + 72) + 8);
   //Exp is used as a workspace
   params.exp = pukccWorkspace(&pos, n + 4);

   //Unused parameter
   params.r = 0;

   //Set PrimeGen service parameters
   PUKCL(u2Option) = PUKCL_PRIMEGEN_TEST | PUKCL_EXPMOD_FASTRSA |
      PUKCL_EXPMOD_WINDOWSIZE_1;
   PUKCL_PrimeGen(u2NLength) = n;
   PUKCL_PrimeGen(nu1NBase) = PUKCC_FAR_TO_NEAR(params.n);
   PUKCL_PrimeGen(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_PrimeGen(nu1RndBase) = PUKCC_FAR_TO_NEAR(params.rnd);
   PUKCL_PrimeGen(nu1PrecompBase) = PUKCC_FAR_TO_NEAR(params.w);
   PUKCL_PrimeGen(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_PrimeGen(nu1ExpBase) = PUKCC_FAR_TO_NEAR(params.exp);
   PUKCL_PrimeGen(u1MillerRabinIterations) = k;
   PUKCL_PrimeGen(u2MaxIncrement) = 1;

   //Perform probable prime testing
   vPUKCL_Process(PrimeGen, pvPUKCLParam);

   //Check status code
   switch(PUKCL(u2Status))
   {
   case PUKCL_NUMBER_IS_PRIME:
      //The number is probably prime
      error = NO_ERROR;
      break;
   case PUKCL_NUMBER_IS_NOT_PRIME:
      //The number is not prime
      error = ERROR_INVALID_VALUE;
      break;
   default:
      //Report an error
      error = ERROR_FAILURE;
      break;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief RSA decryption primitive
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   size_t nLen;
   size_t dLen;
   size_t pLen;
   size_t qLen;
   size_t dpLen;
   size_t dqLen;
   size_t qinvLen;

   //Retrieve the length of the private key
   nLen = mpiGetByteLength(&key->n);
   dLen = mpiGetByteLength(&key->d);
   pLen = mpiGetByteLength(&key->p);
   qLen = mpiGetByteLength(&key->q);
   dpLen = mpiGetByteLength(&key->dp);
   dqLen = mpiGetByteLength(&key->dq);
   qinvLen = mpiGetByteLength(&key->qinv);

   //Sanity check
   if(nLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Use the Chinese remainder algorithm?
   if(nLen > 0 && pLen > 0 && qLen > 0 && dpLen > 0 && dqLen > 0 && qinvLen > 0)
   {
      size_t cLen;
      size_t modLen;
      size_t expLen;
      uint8_t *pos;
      PukccCrtParams params;

      //Retrieve the length of the ciphertext, in bytes
      cLen = mpiGetByteLength(c);

      //Retrieve the length of the modulus, in bytes
      modLen = MAX(pLen, qLen);
      modLen = MAX(modLen, 12);
      modLen = (modLen + 3U) & ~3U;

      //Retrieve the length of the reduced exponents, in bytes
      expLen = MAX(dpLen, dqLen);
      expLen = (expLen + 3U) & ~3U;

      //Check the length of the ciphertext
      if(cLen > (2 * modLen))
         return ERROR_INVALID_LENGTH;

      //Acquire exclusive access to the PUKCC accelerator
      osAcquireMutex(&same51CryptoMutex);

      //Point to the crypto memory
      pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

      //Copy primes
      params.q = pukccImportMpi(&pos, &key->q, modLen + 4);
      params.p = pukccImportMpi(&pos, &key->p, modLen + 4);

      //Copy input number
      params.x = pukccImportMpi(&pos, c, 2 * modLen + 16);

      //The reduced exponents must be given with a supplemental word on the
      //LSB side (low addresses). This word shall be set to zero
      params.dq = pukccWorkspace(&pos, 4);
      pukccImportMpi(&pos, &key->dq, expLen);
      params.dp = pukccWorkspace(&pos, 4);
      pukccImportMpi(&pos, &key->dp, expLen);

      //Copy R value
      params.r = pukccImportMpi(&pos, &key->qinv, modLen + 4);
      //Initialize workspace
      pukccWorkspace(&pos, 3 * (modLen + 4) + MAX(64, 1 * (modLen + 4)) + 8);

      //Set CRT service parameters
      PUKCL(u2Option) = PUKCL_EXPMOD_REGULARRSA | PUKCL_EXPMOD_WINDOWSIZE_1 |
         PUKCL_EXPMOD_EXPINPUKCCRAM;
      PUKCL_CRT(u2ModLength) = modLen;
      PUKCL_CRT(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.q);
      PUKCL_CRT(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);
      PUKCL_CRT(nu1PrecompBase) = PUKCC_FAR_TO_NEAR(params.r);
      PUKCL_CRT(u2ExpLength) = expLen;
      PUKCL_CRT(pfu1ExpBase) = params.dq;
      PUKCL_CRT(u1Blinding) = 0;

      //Perform modular exponentiation (with CRT)
      vPUKCL_Process(CRT, pvPUKCLParam);

      //Check status code
      if(PUKCL(u2Status) == PUKCL_OK)
      {
         //Copy resulting integer
         error = mpiImport(m, params.x, 2 * modLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the PUKCC accelerator
      osReleaseMutex(&same51CryptoMutex);
   }
   else if(nLen > 0 && dLen > 0)
   {
      //Perform modular exponentiation (without CRT)
      error = mpiExpMod(m, c, &key->d, &key->n);
   }
   else
   {
      //Invalid parameters
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the affine point S is on the curve
 * @param[in] ecParams EC domain parameters
 * @param[in] s Affine representation of the point
 * @return TRUE if the affine point S is on the curve, else FALSE
 **/

bool_t ecIsPointAffine(const EcDomainParameters *ecParams, const EcPoint *s)
{
   bool_t valid;
   size_t modLen;
   uint8_t *pos;
   PukccZpEcPointIsOnCurveParams params;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&ecParams->p);
   modLen = (modLen + 3U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, &ecParams->p, modLen + 4);
   //Initialize reduction constant
   params.cns = pukccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = pukccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = pukccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy point coordinates
      params.point.x = pukccImportMpi(&pos, &s->x, modLen + 4);
      params.point.y = pukccImportMpi(&pos, &s->y, modLen + 4);
      params.point.z = pukccWorkspace(&pos, modLen + 4);
      params.point.z[0] = 1;

      //Copy curve parameter a
      params.a = pukccImportMpi(&pos, &ecParams->a, modLen + 4);
      //Copy curve parameter b
      params.b = pukccImportMpi(&pos, &ecParams->b, modLen + 4);
      //Initialize workspace
      params.w = pukccWorkspace(&pos, 4 * modLen + 28);

      //Set ZpEcPointIsOnCurve service parameters
      PUKCL_ZpEcPointIsOnCurve(u2ModLength) = modLen;
      PUKCL_ZpEcPointIsOnCurve(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ZpEcPointIsOnCurve(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ZpEcPointIsOnCurve(nu1PointBase) = PUKCC_FAR_TO_NEAR(params.point.x);
      PUKCL_ZpEcPointIsOnCurve(nu1AParam) = PUKCC_FAR_TO_NEAR(params.a);
      PUKCL_ZpEcPointIsOnCurve(nu1BParam) = PUKCC_FAR_TO_NEAR(params.b);
      PUKCL_ZpEcPointIsOnCurve(nu1Workspace) = PUKCC_FAR_TO_NEAR(params.w);

      //Test whether the point is on the curve
      vPUKCL_Process(ZpEcPointIsOnCurve, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //The point S is on the elliptic curve
      valid = TRUE;
   }
   else
   {
      //The point S is not on the elliptic curve
      valid = FALSE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return TRUE if the affine point S is on the curve, else FALSE
   return valid;
}


/**
 * @brief Recover affine representation
 * @param[in] ecParams EC domain parameters
 * @param[out] r Affine representation of the point
 * @param[in] s Projective representation of the point
 * @return Error code
 **/

error_t ecAffinify(const EcDomainParameters *ecParams, EcPoint *r,
   const EcPoint *s)
{
   error_t error;
   size_t modLen;
   uint8_t *pos;
   PukccZpEcConvProjToAffineParams params;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&ecParams->p);
   modLen = (modLen + 3U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, &ecParams->p, modLen + 4);
   //Initialize reduction constant
   params.cns = pukccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = pukccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = pukccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy point coordinates
      params.point.x = pukccImportMpi(&pos, &s->x, modLen + 4);
      params.point.y = pukccImportMpi(&pos, &s->y, modLen + 4);
      params.point.z = pukccImportMpi(&pos, &s->z, modLen + 4);
      //Initialize workspace
      params.w = pukccWorkspace(&pos, 4 * modLen + 48);

      //Set ZpEccConvAffineToProjective service parameters
      PUKCL_ZpEcConvProjToAffine(u2ModLength) = modLen;
      PUKCL_ZpEcConvProjToAffine(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ZpEcConvProjToAffine(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ZpEcConvProjToAffine(nu1PointABase) = PUKCC_FAR_TO_NEAR(params.point.x);
      PUKCL_ZpEcConvProjToAffine(nu1Workspace) = PUKCC_FAR_TO_NEAR(params.w);

      //Convert point coordinates from projective to affine representation
      vPUKCL_Process(ZpEcConvProjToAffine, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Copy the x-coordinate of the result
      error = mpiImport(&r->x, params.point.x, modLen,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check error code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = mpiImport(&r->y, params.point.y, modLen,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check error code
      if(!error)
      {
         //Copy the z-coordinate of the result
         error = mpiImport(&r->z, params.point.z, modLen,
            MPI_FORMAT_LITTLE_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Scalar multiplication
 * @param[in] ecParams EC domain parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMult(const EcDomainParameters *ecParams, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   size_t kLen;
   size_t modLen;
   uint8_t *pos;
   PukccZpEccMulParams params;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&ecParams->p);
   modLen = (modLen + 3U) & ~3U;

   //Retrieve the length of the scalar number
   kLen = mpiGetByteLength(d);
   kLen = (kLen + 3U) & ~3U;

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, &ecParams->p, modLen + 4);
   //Initialize reduction constant
   params.cns = pukccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = pukccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = pukccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy scalar number
      params.k = pukccImportMpi(&pos, d, kLen + 4);

      //Copy point coordinates
      params.point.x = pukccImportMpi(&pos, &s->x, modLen + 4);
      params.point.y = pukccImportMpi(&pos, &s->y, modLen + 4);
      params.point.z = pukccWorkspace(&pos, modLen + 4);
      params.point.z[0] = 1;

      //Copy curve parameter a
      params.a = pukccImportMpi(&pos, &ecParams->a, modLen + 4);
      //Initialize workspace
      params.w = pukccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEccMulFast service parameters
      PUKCL_ZpEccMul(u2ModLength) = modLen;
      PUKCL_ZpEccMul(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ZpEccMul(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ZpEccMul(u2KLength) = kLen;
      PUKCL_ZpEccMul(nu1KBase) = PUKCC_FAR_TO_NEAR(params.k);
      PUKCL_ZpEccMul(nu1PointBase) = PUKCC_FAR_TO_NEAR(params.point.x);
      PUKCL_ZpEccMul(nu1ABase) = PUKCC_FAR_TO_NEAR(params.a);
      PUKCL_ZpEccMul(nu1Workspace) = PUKCC_FAR_TO_NEAR(params.w);

      //Perform scalar multiplication over GF(p)
      vPUKCL_Process(ZpEccMulFast, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Copy the x-coordinate of the result
      error = mpiImport(&r->x, params.point.x, modLen,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check error code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = mpiImport(&r->y, params.point.y, modLen,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check error code
      if(!error)
      {
         //Copy the z-coordinate of the result
         error = mpiImport(&r->z, params.point.z, modLen,
            MPI_FORMAT_LITTLE_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] ecParams EC domain parameters
 * @param[in] privateKey Signer's ECDSA private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *ecParams, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   size_t scalarLen;
   uint8_t *pos;
   PukccZpEcDsaGenerateParams params;
   Mpi k;

   //Check parameters
   if(ecParams == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&ecParams->p);
   modLen = (modLen + 3U) & ~3U;

   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&ecParams->q);
   //Compute the length of the scalar
   scalarLen = (orderLen + 3U) & ~3U;
   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Initialize multiple precision integer
   mpiInit(&k);

   //Generate a random number k such as 0 < k < q - 1
   error = mpiRandRange(&k, &ecParams->q, prngAlgo, prngContext);

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Check error code
   if(!error)
   {
      //Point to the crypto memory
      pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

      //Copy modulus
      params.mod = pukccImportMpi(&pos, &ecParams->p, modLen + 4);
      //Initialize reduction constant
      params.cns = pukccWorkspace(&pos, scalarLen + 12);
      //Initialize workspace R
      params.r = pukccWorkspace(&pos, 64);
      //Initialize workspace X
      params.x = pukccWorkspace(&pos, 2 * modLen + 8);

      //Set RedMod service parameters
      PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
      PUKCL(Specific).CarryIn = 0;
      PUKCL(Specific).Gf2n = 0;
      PUKCL_RedMod(u2ModLength) = modLen;
      PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
      PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

      //Perform modular reduction setup
      vPUKCL_Process(RedMod, pvPUKCLParam);

      //Check status code
      if(PUKCL(u2Status) != PUKCL_OK)
         error = ERROR_FAILURE;
   }

   //Check error code
   if(!error)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy base point coordinates
      params.basePoint.x = pukccImportMpi(&pos, &ecParams->g.x, modLen + 4);
      params.basePoint.y = pukccImportMpi(&pos, &ecParams->g.y, modLen + 4);
      params.basePoint.z = pukccImportMpi(&pos, &ecParams->g.z, modLen + 4);

      //Copy base point order
      params.order = pukccImportMpi(&pos, &ecParams->q, scalarLen + 4);
      //Copy curve parameter a
      params.a = pukccImportMpi(&pos, &ecParams->a, modLen + 4);
      //Copy private key
      params.privateKey = pukccImportMpi(&pos, &privateKey->d, scalarLen + 4);
      //Copy random scalar
      params.k = pukccImportMpi(&pos, &k, scalarLen + 4);
      //Copy digest
      params.h = pukccImportArray(&pos, digest, digestLen, scalarLen + 4);
      //Initialize workspace
      params.w = pukccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEcDsaGenerateFast service parameters
      PUKCL_ZpEcDsaGenerate(u2ModLength) = modLen;
      PUKCL_ZpEcDsaGenerate(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ZpEcDsaGenerate(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ZpEcDsaGenerate(nu1PointABase) = PUKCC_FAR_TO_NEAR(params.basePoint.x);
      PUKCL_ZpEcDsaGenerate(nu1OrderPointBase) = PUKCC_FAR_TO_NEAR(params.order);
      PUKCL_ZpEcDsaGenerate(nu1ABase) = PUKCC_FAR_TO_NEAR(params.a);
      PUKCL_ZpEcDsaGenerate(nu1PrivateKey) = PUKCC_FAR_TO_NEAR(params.privateKey);
      PUKCL_ZpEcDsaGenerate(u2ScalarLength) = scalarLen;
      PUKCL_ZpEcDsaGenerate(nu1ScalarNumber) = PUKCC_FAR_TO_NEAR(params.k);
      PUKCL_ZpEcDsaGenerate(nu1HashBase) = PUKCC_FAR_TO_NEAR(params.h);
      PUKCL_ZpEcDsaGenerate(nu1Workspace) = PUKCC_FAR_TO_NEAR(params.w);

      //Perform ECDSA signature generation
      vPUKCL_Process(ZpEcDsaGenerateFast, pvPUKCLParam);

      //Check status code
      if(PUKCL(u2Status) != PUKCL_OK)
         error = ERROR_FAILURE;
   }

   //Check error code
   if(!error)
   {
      //Copy the first part of the ECDSA signature
      error = mpiImport(&signature->r, params.basePoint.x, scalarLen,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check error code
   if(!error)
   {
      //Copy the second part of the ECDSA signature
      error = mpiImport(&signature->s, params.basePoint.x + scalarLen + 4,
         scalarLen, MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Check error code
   if(!error)
   {
      //Dump ECDSA signature
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->r);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->s);
   }

   //Release multiple precision integer
   mpiFree(&k);

   //Return error code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] ecParams EC domain parameters
 * @param[in] publicKey Signer's ECDSA public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcDomainParameters *ecParams,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   size_t scalarLen;
   uint8_t *pos;
   PukccZpEcDsaVerifyParams params;

   //Check parameters
   if(ecParams == NULL || publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //The verifier shall check that 0 < r < q
   if(mpiCompInt(&signature->r, 0) <= 0 ||
      mpiComp(&signature->r, &ecParams->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(mpiCompInt(&signature->s, 0) <= 0 ||
      mpiComp(&signature->s, &ecParams->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&ecParams->p);
   modLen = (modLen + 3U) & ~3U;

   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&ecParams->q);
   //Compute the length of the scalar
   scalarLen = (orderLen + 3U) & ~3U;
   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the PUKCC accelerator
   osAcquireMutex(&same51CryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) PUKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = pukccImportMpi(&pos, &ecParams->p, modLen + 4);
   //Initialize reduction constant
   params.cns = pukccWorkspace(&pos, scalarLen + 12);
   //Initialize workspace R
   params.r = pukccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = pukccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   PUKCL(u2Option) = PUKCL_REDMOD_SETUP;
   PUKCL(Specific).CarryIn = 0;
   PUKCL(Specific).Gf2n = 0;
   PUKCL_RedMod(u2ModLength) = modLen;
   PUKCL_RedMod(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
   PUKCL_RedMod(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
   PUKCL_RedMod(nu1RBase) = PUKCC_FAR_TO_NEAR(params.r);
   PUKCL_RedMod(nu1XBase) = PUKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vPUKCL_Process(RedMod, pvPUKCLParam);

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy base point coordinates
      params.basePoint.x = pukccImportMpi(&pos, &ecParams->g.x, modLen + 4);
      params.basePoint.y = pukccImportMpi(&pos, &ecParams->g.y, modLen + 4);
      params.basePoint.z = pukccImportMpi(&pos, &ecParams->g.z, modLen + 4);

      //Copy base point order
      params.order = pukccImportMpi(&pos, &ecParams->q, scalarLen + 4);
      //Copy curve parameter a
      params.a = pukccImportMpi(&pos, &ecParams->a, modLen + 4);

      //Copy public key
      params.publicKey.x = pukccImportMpi(&pos, &publicKey->q.x, modLen + 4);
      params.publicKey.y = pukccImportMpi(&pos, &publicKey->q.y, modLen + 4);
      params.publicKey.z = pukccWorkspace(&pos, modLen + 4);
      params.publicKey.z[0] = 1;

      //Copy digest
      params.h = pukccImportArray(&pos, digest, digestLen, scalarLen + 4);

      //Copy signature
      params.r = pukccImportMpi(&pos, &signature->r, scalarLen + 4);
      params.s = pukccImportMpi(&pos, &signature->s, scalarLen + 4);

      //Initialize workspace
      params.w = pukccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEcDsaVerifyFast service parameters
      PUKCL(u2Option) = 0;
      PUKCL_ZpEcDsaVerify(u2ModLength) = modLen;
      PUKCL_ZpEcDsaVerify(nu1ModBase) = PUKCC_FAR_TO_NEAR(params.mod);
      PUKCL_ZpEcDsaVerify(nu1CnsBase) = PUKCC_FAR_TO_NEAR(params.cns);
      PUKCL_ZpEcDsaVerify(nu1PointABase) = PUKCC_FAR_TO_NEAR(params.basePoint.x);
      PUKCL_ZpEcDsaVerify(nu1OrderPointBase) = PUKCC_FAR_TO_NEAR(params.order);
      PUKCL_ZpEcDsaVerify(nu1ABase) = PUKCC_FAR_TO_NEAR(params.a);
      PUKCL_ZpEcDsaVerify(nu1PointPublicKeyGen) = PUKCC_FAR_TO_NEAR(params.publicKey.x);
      PUKCL_ZpEcDsaVerify(u2ScalarLength) = scalarLen;
      PUKCL_ZpEcDsaVerify(nu1HashBase) = PUKCC_FAR_TO_NEAR(params.h);
      PUKCL_ZpEcDsaVerify(nu1PointSignature) = PUKCC_FAR_TO_NEAR(params.r);
      PUKCL_ZpEcDsaVerify(nu1Workspace) = PUKCC_FAR_TO_NEAR(params.w);

      //Perform ECDSA signature verification
      vPUKCL_Process(ZpEcDsaVerifyFast, pvPUKCLParam);
   }

   //Check status code
   if(PUKCL(u2Status) == PUKCL_OK)
   {
      //The ECDSA signature is valid
      error = NO_ERROR;
   }
   else if(PUKCL(u2Status) == PUKCL_WRONG_SIGNATURE)
   {
      //The ECDSA signature is not valid
      error = ERROR_INVALID_SIGNATURE;
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the PUKCC accelerator
   osReleaseMutex(&same51CryptoMutex);

   //Return status code
   return error;
}

#endif
