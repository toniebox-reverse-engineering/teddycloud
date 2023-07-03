/**
 * @file ecdh.c
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
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
#include "core/crypto.h"
#include "ecc/ecdh.h"
#include "debug.h"

//Check crypto library configuration
#if (ECDH_SUPPORT == ENABLED)


/**
 * @brief Initialize ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhInit(EcdhContext *context)
{
   //Initialize EC domain parameters
   ecInitDomainParameters(&context->params);

   //Initialize private and public keys
   ecInitPrivateKey(&context->da);
   ecInitPublicKey(&context->qa);
   ecInitPublicKey(&context->qb);
}


/**
 * @brief Release ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhFree(EcdhContext *context)
{
   //Release EC domain parameters
   ecFreeDomainParameters(&context->params);

   //Release private and public keys
   ecFreePrivateKey(&context->da);
   ecFreePublicKey(&context->qa);
   ecFreePublicKey(&context->qb);
}


/**
 * @brief ECDH key pair generation
 * @param[in] context Pointer to the ECDH context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ecdhGenerateKeyPair(EcdhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   error_t error;

   //Debug message
   TRACE_DEBUG("Generating ECDH key pair...\r\n");

   //Weierstrass elliptic curve?
   if(context->params.type == EC_CURVE_TYPE_SECT_K1 ||
      context->params.type == EC_CURVE_TYPE_SECT_R1 ||
      context->params.type == EC_CURVE_TYPE_SECT_R2 ||
      context->params.type == EC_CURVE_TYPE_SECP_K1 ||
      context->params.type == EC_CURVE_TYPE_SECP_R1 ||
      context->params.type == EC_CURVE_TYPE_SECP_R2 ||
      context->params.type == EC_CURVE_TYPE_BRAINPOOLP_R1)
   {
      //Generate an EC key pair
      error = ecGenerateKeyPair(prngAlgo, prngContext, &context->params,
         &context->da, &context->qa);
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(context->params.type == EC_CURVE_TYPE_X25519)
   {
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qa[CURVE25519_BYTE_LEN];
      uint8_t g[CURVE25519_BYTE_LEN];

      //Generate 32 random bytes
      error = prngAlgo->read(prngContext, da, CURVE25519_BYTE_LEN);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Private key:\r\n");
         TRACE_DEBUG_ARRAY("    ", da, CURVE25519_BYTE_LEN);

         //Get the u-coordinate of the base point
         error = mpiExport(&context->params.g.x, g, CURVE25519_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Generate the public value using X25519 function
         error = x25519(qa, da, g);
      }

      //Check status code
      if(!error)
      {
         //Save private key
         error = mpiImport(&context->da.d, da, CURVE25519_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Public key:\r\n");
         TRACE_DEBUG_ARRAY("    ", qa, CURVE25519_BYTE_LEN);

         //Save public key
         error = mpiImport(&context->qa.q.x, qa, CURVE25519_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(context->params.type == EC_CURVE_TYPE_X448)
   {
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qa[CURVE448_BYTE_LEN];
      uint8_t g[CURVE448_BYTE_LEN];

      //Generate 56 random bytes
      error = prngAlgo->read(prngContext, da, CURVE448_BYTE_LEN);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Private key:\r\n");
         TRACE_DEBUG_ARRAY("    ", da, CURVE448_BYTE_LEN);

         //Get the u-coordinate of the base point
         error = mpiExport(&context->params.g.x, g, CURVE448_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Generate the public value using X448 function
         error = x448(qa, da, g);
      }

      //Check status code
      if(!error)
      {
         //Save private key
         error = mpiImport(&context->da.d, da, CURVE448_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Public key:\r\n");
         TRACE_DEBUG_ARRAY("    ", qa, CURVE448_BYTE_LEN);

         //Save public key
         error = mpiImport(&context->qa.q.x, qa, CURVE448_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);
      }
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check ECDH public key
 * @param[in] params EC domain parameters
 * @param[in] publicKey Public key to be checked
 * @return Error code
 **/

error_t ecdhCheckPublicKey(const EcDomainParameters *params, EcPoint *publicKey)
{
   bool_t valid;

   //Initialize flag
   valid = FALSE;

   //Weierstrass elliptic curve?
   if(params->type == EC_CURVE_TYPE_SECT_K1 ||
      params->type == EC_CURVE_TYPE_SECT_R1 ||
      params->type == EC_CURVE_TYPE_SECT_R2 ||
      params->type == EC_CURVE_TYPE_SECP_K1 ||
      params->type == EC_CURVE_TYPE_SECP_R1 ||
      params->type == EC_CURVE_TYPE_SECP_R2 ||
      params->type == EC_CURVE_TYPE_BRAINPOOLP_R1)
   {
      //Verify that 0 <= Qx < p
      if(mpiCompInt(&publicKey->x, 0) >= 0 &&
         mpiComp(&publicKey->x, &params->p) < 0)
      {
         //Verify that 0 <= Qy < p
         if(mpiCompInt(&publicKey->y, 0) >= 0 &&
            mpiComp(&publicKey->y, &params->p) < 0)
         {
            //Check whether the point is on the curve
            valid = ecIsPointAffine(params, publicKey);
         }
      }

      //Valid point?
      if(valid)
      {
         //If the cofactor is not 1, the implementation must verify that n.Q
         //is the point at the infinity
         if(params->h != 1)
         {
            error_t error;
            EcPoint r;

            //Initialize flag
            valid = FALSE;
            //Initialize EC points
            ecInit(&r);

            //Convert the peer's public key to projective representation
            error = ecProjectify(params, publicKey, publicKey);

            //Check status code
            if(!error)
            {
               //Compute R = n.Q
               error = ecMult(params, &r, &params->q, publicKey);
            }

            //Check status code
            if(!error)
            {
               //Verify that the result is the point at the infinity
               if(mpiCompInt(&r.z, 0) == 0)
               {
                  valid = TRUE;
               }
            }

            //Release EC point
            ecFree(&r);
         }
      }
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(params->type == EC_CURVE_TYPE_X25519)
   {
      //The public key does not need to be validated
      valid = TRUE;
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(params->type == EC_CURVE_TYPE_X448)
   {
      //The public key does not need to be validated
      valid = TRUE;
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Just for sanity
      valid = FALSE;
   }

   //Return status code
   if(valid)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_ILLEGAL_PARAMETER;
   }
}


/**
 * @brief Compute ECDH shared secret
 * @param[in] context Pointer to the ECDH context
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

error_t ecdhComputeSharedSecret(EcdhContext *context,
   uint8_t *output, size_t outputSize, size_t *outputLen)
{
   error_t error;

   //Debug message
   TRACE_DEBUG("Computing Diffie-Hellman shared secret...\r\n");

   //Weierstrass elliptic curve?
   if(context->params.type == EC_CURVE_TYPE_SECT_K1 ||
      context->params.type == EC_CURVE_TYPE_SECT_R1 ||
      context->params.type == EC_CURVE_TYPE_SECT_R2 ||
      context->params.type == EC_CURVE_TYPE_SECP_K1 ||
      context->params.type == EC_CURVE_TYPE_SECP_R1 ||
      context->params.type == EC_CURVE_TYPE_SECP_R2 ||
      context->params.type == EC_CURVE_TYPE_BRAINPOOLP_R1)
   {
      size_t k;
      EcPoint z;

      //Get the length in octets of the prime modulus
      k = mpiGetByteLength(&context->params.p);

      //Make sure that the output buffer is large enough
      if(outputSize >= k)
      {
         //Length of the resulting shared secret
         *outputLen = k;

         //Initialize EC points
         ecInit(&z);

         //Convert the peer's public key to projective representation
         error = ecProjectify(&context->params, &context->qb.q, &context->qb.q);

         //Check status code
         if(!error)
         {
            //Compute Z = da.Qb
            error = ecMult(&context->params, &z, &context->da.d, &context->qb.q);
         }

         //Check status code
         if(!error)
         {
            //Convert Z to affine representation
            error = ecAffinify(&context->params, &z, &z);
         }

         //Check status code
         if(!error)
         {
            //The shared secret is the x-coordinate of Z
            error = mpiExport(&z.x, output, k, MPI_FORMAT_BIG_ENDIAN);
         }

         //Release EC point
         ecFree(&z);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(context->params.type == EC_CURVE_TYPE_X25519)
   {
      uint_t i;
      uint8_t mask;
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qb[CURVE25519_BYTE_LEN];

      //Make sure that the output buffer is large enough
      if(outputSize >= CURVE25519_BYTE_LEN)
      {
         //Length of the resulting shared secret
         *outputLen = CURVE25519_BYTE_LEN;

         //Retrieve private key
         error = mpiExport(&context->da.d, da, CURVE25519_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Get peer's public key
            error = mpiExport(&context->qb.q.x, qb, CURVE25519_BYTE_LEN,
               MPI_FORMAT_LITTLE_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Generate shared secret K using X25519 function
            error = x25519(output, da, qb);
         }

         //Since Curve25519 has a cofactor of 8, an input point of small order
         //will eliminate any contribution from the other party's private key
         if(!error)
         {
            //This situation can be detected by checking for the all-zero output
            for(mask = 0, i = 0; i < CURVE25519_BYTE_LEN; i++)
            {
               mask |= output[i];
            }

            //Check whether K is the all-zero value and abort if so (refer to
            //RFC 8422, sections 5.10 and 5.11)
            if(mask == 0)
            {
               error = ERROR_ILLEGAL_PARAMETER;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(context->params.type == EC_CURVE_TYPE_X448)
   {
      uint_t i;
      uint8_t mask;
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qb[CURVE448_BYTE_LEN];

      //Make sure that the output buffer is large enough
      if(outputSize >= CURVE448_BYTE_LEN)
      {
         //Length of the resulting shared secret
         *outputLen = CURVE448_BYTE_LEN;

         //Retrieve private key
         error = mpiExport(&context->da.d, da, CURVE448_BYTE_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Get peer's public key
            error = mpiExport(&context->qb.q.x, qb, CURVE448_BYTE_LEN,
               MPI_FORMAT_LITTLE_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Generate shared secret K using X448 function
            error = x448(output, da, qb);
         }

         //Since Curve448 has a cofactor of 4, an input point of small order
         //will eliminate any contribution from the other party's private key
         if(!error)
         {
            //This situation can be detected by checking for the all-zero output
            for(mask = 0, i = 0; i < CURVE448_BYTE_LEN; i++)
            {
               mask |= output[i];
            }

            //Check whether K is the all-zero value and abort if so (refer to
            //RFC 8422, sections 5.10 and 5.11)
            if(mask == 0)
            {
               error = ERROR_ILLEGAL_PARAMETER;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  Shared secret (%" PRIuSIZE " bytes):\r\n", *outputLen);
      TRACE_DEBUG_ARRAY("    ", output, *outputLen);
   }

   //Return status code
   return error;
}

#endif
