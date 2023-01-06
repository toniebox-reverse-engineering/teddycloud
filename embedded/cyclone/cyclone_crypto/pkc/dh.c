/**
 * @file dh.c
 * @brief Diffie-Hellman key exchange
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
 * The Diffie-Hellman key agreement protocol allows two users to exchange a
 * secret key over an insecure medium without any prior secrets. Refer to
 * PKCS #3 (Diffie-Hellman Key-Agreement Standard)
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkc/dh.h"
#include "debug.h"

//Check crypto library configuration
#if (DH_SUPPORT == ENABLED)


/**
 * @brief Initialize Diffie-Hellman context
 * @param[in] context Pointer to the Diffie-Hellman context
 **/

void dhInit(DhContext *context)
{
   //Initialize Diffie-Hellman parameters
   dhInitParameters(&context->params);

   //Initialize private and public values
   mpiInit(&context->xa);
   mpiInit(&context->ya);
   mpiInit(&context->yb);
}


/**
 * @brief Release Diffie-Hellman context
 * @param[in] context Pointer to the Diffie-Hellman context
 **/

void dhFree(DhContext *context)
{
   //Release Diffie-Hellman parameters
   dhFreeParameters(&context->params);

   //Release private and public values
   mpiFree(&context->xa);
   mpiFree(&context->ya);
   mpiFree(&context->yb);
}


/**
 * @brief Initialize Diffie-Hellman parameters
 * @param[in] params Pointer to the Diffie-Hellman parameters
 **/

void dhInitParameters(DhParameters *params)
{
   //Initialize prime modulus
   mpiInit(&params->p);
   //Initialize generator
   mpiInit(&params->g);
}


/**
 * @brief Release Diffie-Hellman parameters
 * @param[in] params Pointer to the Diffie-Hellman parameters
 **/

void dhFreeParameters(DhParameters *params)
{
   //Release prime modulus
   mpiFree(&params->p);
   //Release generator
   mpiFree(&params->g);
}


/**
 * @brief Diffie-Hellman key pair generation
 * @param[in] context Pointer to the Diffie-Hellman context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t dhGenerateKeyPair(DhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   error_t error;
   uint_t k;

   //Debug message
   TRACE_DEBUG("Generating Diffie-Hellman key pair...\r\n");

   //Get the length in bits of the prime p
   k = mpiGetBitLength(&context->params.p);
   //Ensure the length is valid
   if(k == 0)
      return ERROR_INVALID_PARAMETER;

   //The private value shall be randomly generated
   error = mpiRand(&context->xa, k, prngAlgo, prngContext);
   //Any error to report?
   if(error)
      return error;

   //The private value shall be less than p
   if(mpiComp(&context->xa, &context->params.p) >= 0)
   {
      //Shift value to the right
      error = mpiShiftRight(&context->xa, 1);
      //Any error to report?
      if(error)
         return error;
   }

   //Debug message
   TRACE_DEBUG("  Private value:\r\n");
   TRACE_DEBUG_MPI("    ", &context->xa);

   //Calculate the corresponding public value (ya = g ^ xa mod p)
   error = mpiExpModRegular(&context->ya, &context->params.g, &context->xa,
      &context->params.p);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Public value:\r\n");
   TRACE_DEBUG_MPI("    ", &context->ya);

   //Check public value
   error = dhCheckPublicKey(&context->params, &context->ya);
   //Weak public value?
   if(error)
      return error;

   //Public value successfully generated
   return NO_ERROR;
}


/**
 * @brief Check Diffie-Hellman public value
 * @param[in] params Pointer to the Diffie-Hellman parameters
 * @param[in] publicKey Public value to be checked
 * @return Error code
 **/

error_t dhCheckPublicKey(DhParameters *params, const Mpi *publicKey)
{
   error_t error;
   Mpi a;

   //Initialize multiple precision integer
   mpiInit(&a);
   //Precompute p - 1
   error = mpiSubInt(&a, &params->p, 1);

   //Check status
   if(!error)
   {
      //Reject weak public values 1 and p - 1
      if(mpiCompInt(publicKey, 1) <= 0)
      {
         error = ERROR_ILLEGAL_PARAMETER;
      }
      else if(mpiComp(publicKey, &a) >= 0)
      {
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }

   //Free previously allocated resources
   mpiFree(&a);
   //Return status code
   return error;
}


/**
 * @brief Compute Diffie-Hellman shared secret
 * @param[in] context Pointer to the Diffie-Hellman context
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

error_t dhComputeSharedSecret(DhContext *context, uint8_t *output,
   size_t outputSize, size_t *outputLen)
{
   error_t error;
   size_t k;
   Mpi z;

   //Debug message
   TRACE_DEBUG("Computing Diffie-Hellman shared secret...\r\n");

   //Get the length in octets of the prime modulus
   k = mpiGetByteLength(&context->params.p);

   //Make sure that the output buffer is large enough
   if(outputSize < k)
      return ERROR_INVALID_LENGTH;

   //The multiple precision integer must be initialized before it can be used
   mpiInit(&z);

   //Start of exception handling block
   do
   {
      //Calculate the shared secret key (k = yb ^ xa mod p)
      error = mpiExpModRegular(&z, &context->yb, &context->xa,
         &context->params.p);
      //Any error to report?
      if(error)
         break;

      //Convert the resulting integer to an octet string
      error = mpiWriteRaw(&z, output, k);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting shared secret
      *outputLen = k;

      //Debug message
      TRACE_DEBUG("  Shared secret (%" PRIuSIZE " bytes):\r\n", *outputLen);
      TRACE_DEBUG_ARRAY("    ", output, *outputLen);

      //End of exception handling block
   } while(0);

   //Release previously allocated resources
   mpiFree(&z);
   //Return status code
   return error;
}

#endif
