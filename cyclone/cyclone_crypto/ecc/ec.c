/**
 * @file ec.c
 * @brief ECC (Elliptic Curve Cryptography)
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
#include "ecc/ec.h"
#include "debug.h"

//Check crypto library configuration
#if (EC_SUPPORT == ENABLED)

//EC Public Key OID (1.2.840.10045.2.1)
const uint8_t EC_PUBLIC_KEY_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};


/**
 * @brief Initialize EC domain parameters
 * @param[in] params Pointer to the EC domain parameters to initialize
 **/

void ecInitDomainParameters(EcDomainParameters *params)
{
   //Initialize structure
   params->name = NULL;
   params->type = EC_CURVE_TYPE_NONE;
   params->mod = NULL;

   //Initialize EC domain parameters
   mpiInit(&params->p);
   mpiInit(&params->a);
   mpiInit(&params->b);
   ecInit(&params->g);
   mpiInit(&params->q);
}


/**
 * @brief Release EC domain parameters
 * @param[in] params Pointer to the EC domain parameters to free
 **/

void ecFreeDomainParameters(EcDomainParameters *params)
{
   //Release previously allocated resources
   mpiFree(&params->p);
   mpiFree(&params->a);
   mpiFree(&params->b);
   ecFree(&params->g);
   mpiFree(&params->q);
}


/**
 * @brief Load EC domain parameters
 * @param[out] params Pointer to the structure to be initialized
 * @param[in] curveInfo Elliptic curve parameters
 * @return Error code
 **/

error_t ecLoadDomainParameters(EcDomainParameters *params,
   const EcCurveInfo *curveInfo)
{
   error_t error;

   //Check parameters
   if(params == NULL || curveInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("Loading %s EC domain parameters...\r\n", curveInfo->name);

   //Curve name
   params->name = curveInfo->name;
   //Curve type
   params->type = curveInfo->type;

   //Import prime modulus
   MPI_CHECK(mpiReadRaw(&params->p, curveInfo->p, curveInfo->pLen));
   //Import parameter a
   MPI_CHECK(mpiReadRaw(&params->a, curveInfo->a, curveInfo->aLen));
   //Import parameter b
   MPI_CHECK(mpiReadRaw(&params->b, curveInfo->b, curveInfo->bLen));
   //Import the x-coordinate of the base point G
   MPI_CHECK(mpiReadRaw(&params->g.x, curveInfo->gx, curveInfo->gxLen));
   //Import the y-coordinate of the base point G
   MPI_CHECK(mpiReadRaw(&params->g.y, curveInfo->gy, curveInfo->gyLen));
   //Import base point order q
   MPI_CHECK(mpiReadRaw(&params->q, curveInfo->q, curveInfo->qLen));

   //Normalize base point G
   MPI_CHECK(mpiSetValue(&params->g.z, 1));

   //Cofactor h
   params->h = curveInfo->h;
   //Fast modular reduction
   params->mod = curveInfo->mod;

   //Debug message
   TRACE_DEBUG("  p:\r\n");
   TRACE_DEBUG_MPI("    ", &params->p);
   TRACE_DEBUG("  a:\r\n");
   TRACE_DEBUG_MPI("    ", &params->a);
   TRACE_DEBUG("  b:\r\n");
   TRACE_DEBUG_MPI("    ", &params->b);
   TRACE_DEBUG("  Gx:\r\n");
   TRACE_DEBUG_MPI("    ", &params->g.x);
   TRACE_DEBUG("  Gy:\r\n");
   TRACE_DEBUG_MPI("    ", &params->g.y);
   TRACE_DEBUG("  q:\r\n");
   TRACE_DEBUG_MPI("    ", &params->q);

end:
   //Return status code
   return error;
}


/**
 * @brief Initialize an EC public key
 * @param[in] key Pointer to the EC public key to initialize
 **/

void ecInitPublicKey(EcPublicKey *key)
{
   //Initialize EC point
   ecInit(&key->q);
}


/**
 * @brief Release an EC public key
 * @param[in] key Pointer to the EC public key to free
 **/

void ecFreePublicKey(EcPublicKey *key)
{
   //Free EC point
   ecFree(&key->q);
}


/**
 * @brief Initialize an EC private key
 * @param[in] key Pointer to the EC private key to initialize
 **/

void ecInitPrivateKey(EcPrivateKey *key)
{
   //Initialize multiple precision integer
   mpiInit(&key->d);

   //Initialize private key slot
   key->slot = -1;
}


/**
 * @brief Release an EdDSA private key
 * @param[in] key Pointer to the EC public key to free
 **/

void ecFreePrivateKey(EcPrivateKey *key)
{
   //Free multiple precision integer
   mpiFree(&key->d);
}


/**
 * @brief EC key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[out] privateKey EC private key
 * @param[out] publicKey EC public key
 * @return Error code
 **/

__weak_func error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, EcPrivateKey *privateKey,
   EcPublicKey *publicKey)
{
   error_t error;

   //Generate a private key
   error = ecGeneratePrivateKey(prngAlgo, prngContext, params, privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = ecGeneratePublicKey(params, privateKey, publicKey);
   }

   //Return status code
   return error;
}


/**
 * @brief EC private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[out] privateKey EC private key
 * @return Error code
 **/

error_t ecGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, EcPrivateKey *privateKey)
{
   error_t error;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || params == NULL ||
      privateKey == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Generate a random number d such as 0 < d < q - 1
   error = mpiRandRange(&privateKey->d, &params->q, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  Private key:\r\n");
      TRACE_DEBUG_MPI("    ", &privateKey->d);
   }

   //Return status code
   return error;
}


/**
 * @brief Derive the public key from an EC private key
 * @param[in] params EC domain parameters
 * @param[in] privateKey EC private key
 * @param[out] publicKey EC public key
 * @return Error code
 **/

error_t ecGeneratePublicKey(const EcDomainParameters *params,
   const EcPrivateKey *privateKey, EcPublicKey *publicKey)
{
   error_t error;

   //Check parameters
   if(params == NULL || privateKey == NULL || publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Compute Q = d.G
   EC_CHECK(ecMult(params, &publicKey->q, &privateKey->d, &params->g));

   //Convert the public key to affine representation
   EC_CHECK(ecAffinify(params, &publicKey->q, &publicKey->q));

   //Debug message
   TRACE_DEBUG("  Public key X:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.x);
   TRACE_DEBUG("  Public key Y:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.y);

end:
   //Return status code
   return error;
}


/**
 * @brief Initialize elliptic curve point
 * @param[in,out] r Pointer to the EC point to be initialized
 **/

void ecInit(EcPoint *r)
{
   //Initialize structure
   mpiInit(&r->x);
   mpiInit(&r->y);
   mpiInit(&r->z);
}


/**
 * @brief Release an elliptic curve point
 * @param[in,out] r Pointer to the EC point to initialize to free
 **/

void ecFree(EcPoint *r)
{
   //Release previously allocated resources
   mpiFree(&r->x);
   mpiFree(&r->y);
   mpiFree(&r->z);
}


/**
 * @brief Copy EC point
 * @param[out] r Destination EC point
 * @param[in] s Source EC point
 * @return Error code
 **/

error_t ecCopy(EcPoint *r, const EcPoint *s)
{
   error_t error;

   //R and S are the same instance?
   if(r == s)
      return NO_ERROR;

   //Copy coordinates
   MPI_CHECK(mpiCopy(&r->x, &s->x));
   MPI_CHECK(mpiCopy(&r->y, &s->y));
   MPI_CHECK(mpiCopy(&r->z, &s->z));

end:
   //Return status code
   return error;
}


/**
 * @brief Convert an octet string to an EC point
 * @param[in] params EC domain parameters
 * @param[out] r EC point resulting from the conversion
 * @param[in] data Pointer to the octet string
 * @param[in] length Length of the octet string
 * @return Error code
 **/

error_t ecImport(const EcDomainParameters *params, EcPoint *r,
   const uint8_t *data, size_t length)
{
   error_t error;

   //Montgomery or Edwards curve?
   if(params->type == EC_CURVE_TYPE_X25519 ||
      params->type == EC_CURVE_TYPE_X448 ||
      params->type == EC_CURVE_TYPE_ED25519 ||
      params->type == EC_CURVE_TYPE_ED448)
   {
      //Empty octet string?
      if(length == 0)
         return ERROR_ILLEGAL_PARAMETER;

      //Check the length of the octet string
      if((params->type == EC_CURVE_TYPE_X25519 && length != 32) ||
         (params->type == EC_CURVE_TYPE_X448 && length != 56) ||
         (params->type == EC_CURVE_TYPE_ED25519 && length != 32) ||
         (params->type == EC_CURVE_TYPE_ED448 && length != 57))
      {
         return ERROR_ILLEGAL_PARAMETER;
      }

      //Convert the octet string to a multiple precision integer
      error = mpiImport(&r->x, data, length, MPI_FORMAT_LITTLE_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }
   //Weierstrass curve?
   else
   {
      size_t k;

      //Get the length in octets of the prime
      k = mpiGetByteLength(&params->p);

      //Check the length of the octet string
      if(length != (k * 2 + 1))
         return ERROR_ILLEGAL_PARAMETER;

      //Compressed point representation is not supported
      if(data[0] != EC_POINT_FORMAT_UNCOMPRESSED)
         return ERROR_ILLEGAL_PARAMETER;

      //Convert the x-coordinate to a multiple precision integer
      error = mpiImport(&r->x, data + 1, k, MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;

      //Convert the y-coordinate to a multiple precision integer
      error = mpiImport(&r->y, data + k + 1, k, MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Convert an EC point to an octet string
 * @param[in] params EC domain parameters
 * @param[in] a EC point to be converted
 * @param[out] data Pointer to the octet string
 * @param[out] length Length of the resulting octet string
 * @return Error code
 **/

error_t ecExport(const EcDomainParameters *params, const EcPoint *a,
   uint8_t *data, size_t *length)
{
   error_t error;
   size_t k;

   //Get the length in octets of the prime
   k = mpiGetByteLength(&params->p);

   //Montgomery curve?
   if(params->type == EC_CURVE_TYPE_X25519 ||
      params->type == EC_CURVE_TYPE_X448)
   {
      //Convert the u-coordinate to an octet string
      error = mpiExport(&a->x, data, k, MPI_FORMAT_LITTLE_ENDIAN);
      //Conversion failed?
      if(error)
         return error;

      //Return the total number of bytes that have been written
      *length = k;
   }
   //Weierstrass curve?
   else
   {
      //Point compression is not used
      data[0] = EC_POINT_FORMAT_UNCOMPRESSED;

      //Convert the x-coordinate to an octet string
      error = mpiExport(&a->x, data + 1, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         return error;

      //Convert the y-coordinate to an octet string
      error = mpiExport(&a->y, data + k + 1, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         return error;

      //Return the total number of bytes that have been written
      *length = k * 2 + 1;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute projective representation
 * @param[in] params EC domain parameters
 * @param[out] r Projective representation of the point
 * @param[in] s Affine representation of the point
 * @return Error code
 **/

error_t ecProjectify(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s)
{
   error_t error;

   //Copy point
   EC_CHECK(ecCopy(r, s));
   //Map the point to projective space
   MPI_CHECK(mpiSetValue(&r->z, 1));

end:
   //Return status code
   return error;
}


/**
 * @brief Recover affine representation
 * @param[in] params EC domain parameters
 * @param[out] r Affine representation of the point
 * @param[in] s Projective representation of the point
 * @return Error code
 **/

__weak_func error_t ecAffinify(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s)
{
   error_t error;
   Mpi a;
   Mpi b;

   //Point at the infinity?
   if(mpiCompInt(&s->z, 0) == 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize multiple precision integers
   mpiInit(&a);
   mpiInit(&b);

   //Compute a = 1/Sz mod p
   MPI_CHECK(mpiInvMod(&a, &s->z, &params->p));

   //Set Rx = a^2 * Sx mod p
   EC_CHECK(ecSqrMod(params, &b, &a));
   EC_CHECK(ecMulMod(params, &r->x, &b, &s->x));

   //Set Ry = a^3 * Sy mod p
   EC_CHECK(ecMulMod(params, &b, &b, &a));
   EC_CHECK(ecMulMod(params, &r->y, &b, &s->y));

   //Set Rz = 1
   MPI_CHECK(mpiSetValue(&r->z, 1));

end:
   //Release multiple precision integers
   mpiFree(&a);
   mpiFree(&b);

   //Return status code
   return error;
}


/**
 * @brief Check whether the affine point S is on the curve
 * @param[in] params EC domain parameters
 * @param[in] s Affine representation of the point
 * @return TRUE if the affine point S is on the curve, else FALSE
 **/

__weak_func bool_t ecIsPointAffine(const EcDomainParameters *params, const EcPoint *s)
{
   error_t error;
   Mpi t1;
   Mpi t2;

   //Initialize multiple precision integers
   mpiInit(&t1);
   mpiInit(&t2);

   //Compute t1 = (Sx^3 + a * Sx + b) mod p
   EC_CHECK(ecSqrMod(params, &t1, &s->x));
   EC_CHECK(ecMulMod(params, &t1, &t1, &s->x));
   EC_CHECK(ecMulMod(params, &t2, &params->a, &s->x));
   EC_CHECK(ecAddMod(params, &t1, &t1, &t2));
   EC_CHECK(ecAddMod(params, &t1, &t1, &params->b));

   //Compute t2 = Sy^2
   EC_CHECK(ecSqrMod(params, &t2, &s->y));

   //Check whether the point is on the elliptic curve
   if(mpiComp(&t1, &t2) != 0)
      error = ERROR_FAILURE;

end:
   //Release multiple precision integers
   mpiFree(&t1);
   mpiFree(&t2);

   //Return TRUE if the affine point S is on the curve, else FALSE
   return error ? FALSE : TRUE;
}


/**
 * @brief Point doubling
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = 2S
 * @param[in] s Point S
 * @return Error code
 **/

error_t ecDouble(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s)
{
   error_t error;
   Mpi t1;
   Mpi t2;
   Mpi t3;
   Mpi t4;
   Mpi t5;

   //Initialize multiple precision integers
   mpiInit(&t1);
   mpiInit(&t2);
   mpiInit(&t3);
   mpiInit(&t4);
   mpiInit(&t5);

   //Set t1 = Sx
   MPI_CHECK(mpiCopy(&t1, &s->x));
   //Set t2 = Sy
   MPI_CHECK(mpiCopy(&t2, &s->y));
   //Set t3 = Sz
   MPI_CHECK(mpiCopy(&t3, &s->z));

   //Point at the infinity?
   if(mpiCompInt(&t3, 0) == 0)
   {
      //Set R = (1, 1, 0)
      MPI_CHECK(mpiSetValue(&r->x, 1));
      MPI_CHECK(mpiSetValue(&r->y, 1));
      MPI_CHECK(mpiSetValue(&r->z, 0));
   }
   else
   {
      //SECP K1 elliptic curve?
      if(params->type == EC_CURVE_TYPE_SECP_K1)
      {
         //Compute t5 = t1^2
         EC_CHECK(ecSqrMod(params, &t5, &t1));
         //Compute t4 = 3 * t5
         EC_CHECK(ecAddMod(params, &t4, &t5, &t5));
         EC_CHECK(ecAddMod(params, &t4, &t4, &t5));
      }
      //SECP R1 elliptic curve?
      else if(params->type == EC_CURVE_TYPE_SECP_R1)
      {
         //Compute t4 = t3^2
         EC_CHECK(ecSqrMod(params, &t4, &t3));
         //Compute t5 = t1 - t4
         EC_CHECK(ecSubMod(params, &t5, &t1, &t4));
         //Compute t4 = t1 + t4
         EC_CHECK(ecAddMod(params, &t4, &t1, &t4));
         //Compute t5 = t4 * t5
         EC_CHECK(ecMulMod(params, &t5, &t4, &t5));
         //Compute t4 = 3 * t5
         EC_CHECK(ecAddMod(params, &t4, &t5, &t5));
         EC_CHECK(ecAddMod(params, &t4, &t4, &t5));
      }
      else
      {
         //Compute t4 = t3^4
         EC_CHECK(ecSqrMod(params, &t4, &t3));
         EC_CHECK(ecSqrMod(params, &t4, &t4));
         //Compute t4 = a * t4
         EC_CHECK(ecMulMod(params, &t4, &t4, &params->a));
         //Compute t5 = t1^2
         EC_CHECK(ecSqrMod(params, &t5, &t1));
         //Compute t4 = t4 + 3 * t5
         EC_CHECK(ecAddMod(params, &t4, &t4, &t5));
         EC_CHECK(ecAddMod(params, &t4, &t4, &t5));
         EC_CHECK(ecAddMod(params, &t4, &t4, &t5));
      }

      //Compute t3 = t3 * t2
      EC_CHECK(ecMulMod(params, &t3, &t3, &t2));
      //Compute t3 = 2 * t3
      EC_CHECK(ecAddMod(params, &t3, &t3, &t3));
      //Compute t2 = t2^2
      EC_CHECK(ecSqrMod(params, &t2, &t2));
      //Compute t5 = t1 * t2
      EC_CHECK(ecMulMod(params, &t5, &t1, &t2));
      //Compute t5 = 4 * t5
      EC_CHECK(ecAddMod(params, &t5, &t5, &t5));
      EC_CHECK(ecAddMod(params, &t5, &t5, &t5));
      //Compute t1 = t4^2
      EC_CHECK(ecSqrMod(params, &t1, &t4));
      //Compute t1 = t1 - 2 * t5
      EC_CHECK(ecSubMod(params, &t1, &t1, &t5));
      EC_CHECK(ecSubMod(params, &t1, &t1, &t5));
      //Compute t2 = t2^2
      EC_CHECK(ecSqrMod(params, &t2, &t2));
      //Compute t2 = 8 * t2
      EC_CHECK(ecAddMod(params, &t2, &t2, &t2));
      EC_CHECK(ecAddMod(params, &t2, &t2, &t2));
      EC_CHECK(ecAddMod(params, &t2, &t2, &t2));
      //Compute t5 = t5 - t1
      EC_CHECK(ecSubMod(params, &t5, &t5, &t1));
      //Compute t5 = t4 * t5
      EC_CHECK(ecMulMod(params, &t5, &t4, &t5));
      //Compute t2 = t5 - t2
      EC_CHECK(ecSubMod(params, &t2, &t5, &t2));

      //Set Rx = t1
      MPI_CHECK(mpiCopy(&r->x, &t1));
      //Set Ry = t2
      MPI_CHECK(mpiCopy(&r->y, &t2));
      //Set Rz = t3
      MPI_CHECK(mpiCopy(&r->z, &t3));
   }

end:
   //Release multiple precision integers
   mpiFree(&t1);
   mpiFree(&t2);
   mpiFree(&t3);
   mpiFree(&t4);
   mpiFree(&t5);

   //Return status code
   return error;
}


/**
 * @brief Point addition (helper routine)
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = S + T
 * @param[in] s First operand
 * @param[in] t Second operand
 * @return Error code
 **/

error_t ecAdd(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t)
{
   error_t error;
   Mpi t1;
   Mpi t2;
   Mpi t3;
   Mpi t4;
   Mpi t5;
   Mpi t6;
   Mpi t7;

   //Initialize multiple precision integers
   mpiInit(&t1);
   mpiInit(&t2);
   mpiInit(&t3);
   mpiInit(&t4);
   mpiInit(&t5);
   mpiInit(&t6);
   mpiInit(&t7);

   //Set t1 = Sx
   MPI_CHECK(mpiCopy(&t1, &s->x));
   //Set t2 = Sy
   MPI_CHECK(mpiCopy(&t2, &s->y));
   //Set t3 = Sz
   MPI_CHECK(mpiCopy(&t3, &s->z));
   //Set t4 = Tx
   MPI_CHECK(mpiCopy(&t4, &t->x));
   //Set t5 = Ty
   MPI_CHECK(mpiCopy(&t5, &t->y));

   //Check whether Tz != 1
   if(mpiCompInt(&t->z, 1) != 0)
   {
      //Compute t6 = Tz
      MPI_CHECK(mpiCopy(&t6, &t->z));
      //Compute t7 = t6^2
      EC_CHECK(ecSqrMod(params, &t7, &t6));
      //Compute t1 = t1 * t7
      EC_CHECK(ecMulMod(params, &t1, &t1, &t7));
      //Compute t7 = t6 * t7
      EC_CHECK(ecMulMod(params, &t7, &t6, &t7));
      //Compute t2 = t2 * t7
      EC_CHECK(ecMulMod(params, &t2, &t2, &t7));
   }

   //Compute t7 = t3^2
   EC_CHECK(ecSqrMod(params, &t7, &t3));
   //Compute t4 = t4 * t7
   EC_CHECK(ecMulMod(params, &t4, &t4, &t7));
   //Compute t7 = t3 * t7
   EC_CHECK(ecMulMod(params, &t7, &t3, &t7));
   //Compute t5 = t5 * t7
   EC_CHECK(ecMulMod(params, &t5, &t5, &t7));
   //Compute t4 = t1 - t4
   EC_CHECK(ecSubMod(params, &t4, &t1, &t4));
   //Compute t5 = t2 - t5
   EC_CHECK(ecSubMod(params, &t5, &t2, &t5));

   //Check whether t4 == 0
   if(mpiCompInt(&t4, 0) == 0)
   {
      //Check whether t5 == 0
      if(mpiCompInt(&t5, 0) == 0)
      {
         //Set R = (0, 0, 0)
         MPI_CHECK(mpiSetValue(&r->x, 0));
         MPI_CHECK(mpiSetValue(&r->y, 0));
         MPI_CHECK(mpiSetValue(&r->z, 0));
      }
      else
      {
         //Set R = (1, 1, 0)
         MPI_CHECK(mpiSetValue(&r->x, 1));
         MPI_CHECK(mpiSetValue(&r->y, 1));
         MPI_CHECK(mpiSetValue(&r->z, 0));
      }
   }
   else
   {
      //Compute t1 = 2 * t1 - t4
      EC_CHECK(ecAddMod(params, &t1, &t1, &t1));
      EC_CHECK(ecSubMod(params, &t1, &t1, &t4));
      //Compute t2 = 2 * t2 - t5
      EC_CHECK(ecAddMod(params, &t2, &t2, &t2));
      EC_CHECK(ecSubMod(params, &t2, &t2, &t5));

      //Check whether Tz != 1
      if(mpiCompInt(&t->z, 1) != 0)
      {
         //Compute t3 = t3 * t6
         EC_CHECK(ecMulMod(params, &t3, &t3, &t6));
      }

      //Compute t3 = t3 * t4
      EC_CHECK(ecMulMod(params, &t3, &t3, &t4));
      //Compute t7 = t4^2
      EC_CHECK(ecSqrMod(params, &t7, &t4));
      //Compute t4 = t4 * t7
      EC_CHECK(ecMulMod(params, &t4, &t4, &t7));
      //Compute t7 = t1 * t7
      EC_CHECK(ecMulMod(params, &t7, &t1, &t7));
      //Compute t1 = t5^2
      EC_CHECK(ecSqrMod(params, &t1, &t5));
      //Compute t1 = t1 - t7
      EC_CHECK(ecSubMod(params, &t1, &t1, &t7));
      //Compute t7 = t7 - 2 * t1
      EC_CHECK(ecAddMod(params, &t6, &t1, &t1));
      EC_CHECK(ecSubMod(params, &t7, &t7, &t6));
      //Compute t5 = t5 * t7
      EC_CHECK(ecMulMod(params, &t5, &t5, &t7));
      //Compute t4 = t2 * t4
      EC_CHECK(ecMulMod(params, &t4, &t2, &t4));
      //Compute t2 = t5 - t4
      EC_CHECK(ecSubMod(params, &t2, &t5, &t4));

      //Compute t2 = t2 / 2
      if(mpiIsEven(&t2))
      {
         MPI_CHECK(mpiShiftRight(&t2, 1));
      }
      else
      {
         MPI_CHECK(mpiAdd(&t2, &t2, &params->p));
         MPI_CHECK(mpiShiftRight(&t2, 1));
      }

      //Set Rx = t1
      MPI_CHECK(mpiCopy(&r->x, &t1));
      //Set Ry = t2
      MPI_CHECK(mpiCopy(&r->y, &t2));
      //Set Rz = t3
      MPI_CHECK(mpiCopy(&r->z, &t3));
   }

end:
   //Release multiple precision integers
   mpiFree(&t1);
   mpiFree(&t2);
   mpiFree(&t3);
   mpiFree(&t4);
   mpiFree(&t5);
   mpiFree(&t6);
   mpiFree(&t7);

   //Return status code
   return error;
}


/**
 * @brief Point addition
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = S + T
 * @param[in] s First operand
 * @param[in] t Second operand
 * @return Error code
 **/

error_t ecFullAdd(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t)
{
   error_t error;

   //Check whether Sz == 0
   if(mpiCompInt(&s->z, 0) == 0)
   {
      //Set R = T
      MPI_CHECK(mpiCopy(&r->x, &t->x));
      MPI_CHECK(mpiCopy(&r->y, &t->y));
      MPI_CHECK(mpiCopy(&r->z, &t->z));
   }
   //Check whether Tz == 0
   else if(mpiCompInt(&t->z, 0) == 0)
   {
      //Set R = S
      MPI_CHECK(mpiCopy(&r->x, &s->x));
      MPI_CHECK(mpiCopy(&r->y, &s->y));
      MPI_CHECK(mpiCopy(&r->z, &s->z));
   }
   else
   {
      //Compute R = S + T
      EC_CHECK(ecAdd(params, r, s, t));

      //Check whether R == (0, 0, 0)
      if(mpiCompInt(&r->x, 0) == 0 &&
         mpiCompInt(&r->y, 0) == 0 &&
         mpiCompInt(&r->z, 0) == 0)
      {
         //Compute R = 2 * S
         EC_CHECK(ecDouble(params, r, s));
      }
   }

end:
   //Return status code
   return error;
}


/**
 * @brief Point subtraction
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = S - T
 * @param[in] s First operand
 * @param[in] t Second operand
 * @return Error code
 **/

error_t ecFullSub(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t)
{
   error_t error;
   EcPoint u;

   //Initialize EC point
   ecInit(&u);

   //Set Ux = Tx and Uz = Tz
   MPI_CHECK(mpiCopy(&u.x, &t->x));
   MPI_CHECK(mpiCopy(&u.z, &t->z));
   //Set Uy = p - Ty
   MPI_CHECK(mpiSub(&u.y, &params->p, &t->y));

   //Compute R = S + U
   EC_CHECK(ecFullAdd(params, r, s, &u));

end:
   //Release EC point
   ecFree(&u);

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

__weak_func error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   uint_t i;
   Mpi h;

   //Initialize multiple precision integer
   mpiInit(&h);

   //Check whether d == 0
   if(mpiCompInt(d, 0) == 0)
   {
      //Set R = (1, 1, 0)
      MPI_CHECK(mpiSetValue(&r->x, 1));
      MPI_CHECK(mpiSetValue(&r->y, 1));
      MPI_CHECK(mpiSetValue(&r->z, 0));
   }
   //Check whether d == 1
   else if(mpiCompInt(d, 1) == 0)
   {
      //Set R = S
      MPI_CHECK(mpiCopy(&r->x, &s->x));
      MPI_CHECK(mpiCopy(&r->y, &s->y));
      MPI_CHECK(mpiCopy(&r->z, &s->z));
   }
   //Check whether Sz == 0
   else if(mpiCompInt(&s->z, 0) == 0)
   {
      //Set R = (1, 1, 0)
      MPI_CHECK(mpiSetValue(&r->x, 1));
      MPI_CHECK(mpiSetValue(&r->y, 1));
      MPI_CHECK(mpiSetValue(&r->z, 0));
   }
   else
   {
      //Check whether Sz != 1
      if(mpiCompInt(&s->z, 1) != 0)
      {
         //Normalize S
         EC_CHECK(ecAffinify(params, r, s));
         EC_CHECK(ecProjectify(params, r, r));
      }
      else
      {
         //Set R = S
         MPI_CHECK(mpiCopy(&r->x, &s->x));
         MPI_CHECK(mpiCopy(&r->y, &s->y));
         MPI_CHECK(mpiCopy(&r->z, &s->z));
      }

//Left-to-right binary method
#if 0
      for(i = mpiGetBitLength(d) - 1; i >= 1; i--)
      {
         //Point doubling
         EC_CHECK(ecDouble(params, r, r));

         if(mpiGetBitValue(d, i - 1))
         {
            //Compute R = R + S
            EC_CHECK(ecFullAdd(params, r, r, s));
         }
      }
//Fast left-to-right binary method
#else
      //Precompute h = 3 * d
      MPI_CHECK(mpiAdd(&h, d, d));
      MPI_CHECK(mpiAdd(&h, &h, d));

      //Scalar multiplication
      for(i = mpiGetBitLength(&h) - 2; i >= 1; i--)
      {
         //Point doubling
         EC_CHECK(ecDouble(params, r, r));

         //Check whether h(i) == 1 and k(i) == 0
         if(mpiGetBitValue(&h, i) && !mpiGetBitValue(d, i))
         {
            //Compute R = R + S
            EC_CHECK(ecFullAdd(params, r, r, s));
         }
         //Check whether h(i) == 0 and k(i) == 1
         else if(!mpiGetBitValue(&h, i) && mpiGetBitValue(d, i))
         {
            //Compute R = R - S
            EC_CHECK(ecFullSub(params, r, r, s));
         }
      }
#endif
   }

end:
   //Release multiple precision integer
   mpiFree(&h);

   //Return status code
   return error;
}


/**
 * @brief An auxiliary function for the twin multiplication
 * @param[in] t An integer T such as 0 <= T <= 31
 * @return Output value
 **/

uint_t ecTwinMultF(uint_t t)
{
   uint_t h;

   //Check the value of T
   if(18 <= t && t < 22)
   {
      h = 9;
   }
   else if(14 <= t && t < 18)
   {
      h = 10;
   }
   else if(22 <= t && t < 24)
   {
      h = 11;
   }
   else if(4 <= t && t < 12)
   {
      h = 14;
   }
   else
   {
      h = 12;
   }

   //Return value
   return h;
}


/**
 * @brief Twin multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d0.S + d1.T
 * @param[in] d0 An integer d such as 0 <= d0 < p
 * @param[in] s EC point
 * @param[in] d1 An integer d such as 0 <= d1 < p
 * @param[in] t EC point
 * @return Error code
 **/

error_t ecTwinMult(const EcDomainParameters *params, EcPoint *r,
   const Mpi *d0, const EcPoint *s, const Mpi *d1, const EcPoint *t)
{
   error_t error;
   int_t k;
   uint_t m;
   uint_t m0;
   uint_t m1;
   uint_t c0;
   uint_t c1;
   uint_t h0;
   uint_t h1;
   int_t u0;
   int_t u1;
   EcPoint spt;
   EcPoint smt;

   //Initialize EC points
   ecInit(&spt);
   ecInit(&smt);

   //Precompute SpT = S + T
   EC_CHECK(ecFullAdd(params, &spt, s, t));
   //Precompute SmT = S - T
   EC_CHECK(ecFullSub(params, &smt, s, t));

   //Let m0 be the bit length of d0
   m0 = mpiGetBitLength(d0);
   //Let m1 be the bit length of d1
   m1 = mpiGetBitLength(d1);
   //Let m = MAX(m0, m1)
   m = MAX(m0, m1);

   //Let c be a 2 x 6 binary matrix
   c0 = mpiGetBitValue(d0, m - 4);
   c0 |= mpiGetBitValue(d0, m - 3) << 1;
   c0 |= mpiGetBitValue(d0, m - 2) << 2;
   c0 |= mpiGetBitValue(d0, m - 1) << 3;
   c1 = mpiGetBitValue(d1, m - 4);
   c1 |= mpiGetBitValue(d1, m - 3) << 1;
   c1 |= mpiGetBitValue(d1, m - 2) << 2;
   c1 |= mpiGetBitValue(d1, m - 1) << 3;

   //Set R = (1, 1, 0)
   MPI_CHECK(mpiSetValue(&r->x, 1));
   MPI_CHECK(mpiSetValue(&r->y, 1));
   MPI_CHECK(mpiSetValue(&r->z, 0));

   //Calculate both multiplications at the same time
   for(k = m; k >= 0; k--)
   {
      //Compute h(0) = 16 * c(0,1) + 8 * c(0,2) + 4 * c(0,3) + 2 * c(0,4) + c(0,5)
      h0 = c0 & 0x1F;

      //Check whether c(0,0) == 1
      if(c0 & 0x20)
      {
         h0 = 31 - h0;
      }

      //Compute h(1) = 16 * c(1,1) + 8 * c(1,2) + 4 * c(1,3) + 2 * c(1,4) + c(1,5)
      h1 = c1 & 0x1F;

      //Check whether c(1,0) == 1
      if(c1 & 0x20)
      {
         h1 = 31 - h1;
      }

      //Compute u(0)
      if(h0 < ecTwinMultF(h1))
      {
         u0 = 0;
      }
      else if(c0 & 0x20)
      {
         u0 = -1;
      }
      else
      {
         u0 = 1;
      }

      //Compute u(1)
      if(h1 < ecTwinMultF(h0))
      {
         u1 = 0;
      }
      else if(c1 & 0x20)
      {
         u1 = -1;
      }
      else
      {
         u1 = 1;
      }

      //Update c matrix
      c0 <<= 1;
      c0 |= mpiGetBitValue(d0, k - 5);
      c0 ^= u0 ? 0x20 : 0x00;
      c1 <<= 1;
      c1 |= mpiGetBitValue(d1, k - 5);
      c1 ^= u1 ? 0x20 : 0x00;

      //Point doubling
      EC_CHECK(ecDouble(params, r, r));

      //Check u(0) and u(1)
      if(u0 == -1 && u1 == -1)
      {
         //Compute R = R - SpT
         EC_CHECK(ecFullSub(params, r, r, &spt));
      }
      else if(u0 == -1 && u1 == 0)
      {
         //Compute R = R - S
         EC_CHECK(ecFullSub(params, r, r, s));
      }
      else if(u0 == -1 && u1 == 1)
      {
         //Compute R = R - SmT
         EC_CHECK(ecFullSub(params, r, r, &smt));
      }
      else if(u0 == 0 && u1 == -1)
      {
         //Compute R = R - T
         EC_CHECK(ecFullSub(params, r, r, t));
      }
      else if(u0 == 0 && u1 == 1)
      {
         //Compute R = R + T
         EC_CHECK(ecFullAdd(params, r, r, t));
      }
      else if(u0 == 1 && u1 == -1)
      {
         //Compute R = R + SmT
         EC_CHECK(ecFullAdd(params, r, r, &smt));
      }
      else if(u0 == 1 && u1 == 0)
      {
         //Compute R = R + S
         EC_CHECK(ecFullAdd(params, r, r, s));
      }
      else if(u0 == 1 && u1 == 1)
      {
         //Compute R = R + SpT
         EC_CHECK(ecFullAdd(params, r, r, &spt));
      }
   }

end:
   //Release EC points
   ecFree(&spt);
   ecFree(&smt);

   //Return status code
   return error;
}


/**
 * @brief Fast modular addition
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 * @return Error code
 **/

error_t ecAddMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b)
{
   error_t error;

   //Compute R = A + B
   MPI_CHECK(mpiAdd(r, a, b));

   //Compute R = (A + B) mod p
   if(mpiComp(r, &params->p) >= 0)
   {
      MPI_CHECK(mpiSub(r, r, &params->p));
   }

end:
   //Return status code
   return error;
}


/**
 * @brief Fast modular subtraction
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 * @return Error code
 **/

error_t ecSubMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b)
{
   error_t error;

   //Compute R = A - B
   MPI_CHECK(mpiSub(r, a, b));

   //Compute R = (A - B) mod p
   if(mpiCompInt(r, 0) < 0)
   {
      MPI_CHECK(mpiAdd(r, r, &params->p));
   }

end:
   //Return status code
   return error;
}


/**
 * @brief Fast modular multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 * @return Error code
 **/

__weak_func error_t ecMulMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b)
{
   error_t error;

   //Compute R = A * B
   MPI_CHECK(mpiMul(r, a, b));

   //Compute R = (A * B) mod p
   if(params->mod != NULL)
   {
      MPI_CHECK(params->mod(r, &params->p));
   }
   else
   {
      MPI_CHECK(mpiMod(r, r, &params->p));
   }

end:
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

__weak_func error_t ecSqrMod(const EcDomainParameters *params, Mpi *r, const Mpi *a)
{
   error_t error;

   //Compute R = A ^ 2
   MPI_CHECK(mpiMul(r, a, a));

   //Compute R = (A ^ 2) mod p
   if(params->mod != NULL)
   {
      MPI_CHECK(params->mod(r, &params->p));
   }
   else
   {
      MPI_CHECK(mpiMod(r, r, &params->p));
   }

end:
   //Return status code
   return error;
}

#endif
