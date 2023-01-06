/**
 * @file ecdsa.c
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm)
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
#include "ecc/ecdsa.h"
#include "mpi/mpi.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (ECDSA_SUPPORT == ENABLED)

//ECDSA with SHA-1 OID (1.2.840.10045.4.1)
const uint8_t ECDSA_WITH_SHA1_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
//ECDSA with SHA-224 OID (1.2.840.10045.4.3.1)
const uint8_t ECDSA_WITH_SHA224_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01};
//ECDSA with SHA-256 OID (1.2.840.10045.4.3.2)
const uint8_t ECDSA_WITH_SHA256_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
//ECDSA with SHA-384 OID (1.2.840.10045.4.3.3)
const uint8_t ECDSA_WITH_SHA384_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
//ECDSA with SHA-512 OID (1.2.840.10045.4.3.4)
const uint8_t ECDSA_WITH_SHA512_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
//ECDSA with SHA-3-224 OID (2.16.840.1.101.3.4.3.9)
const uint8_t ECDSA_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09};
//ECDSA with SHA-3-256 OID (2.16.840.1.101.3.4.3.10)
const uint8_t ECDSA_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A};
//ECDSA with SHA-3-384 OID (2.16.840.1.101.3.4.3.11)
const uint8_t ECDSA_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B};
//ECDSA with SHA-3-512 OID (2.16.840.1.101.3.4.3.12)
const uint8_t ECDSA_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C};


/**
 * @brief Initialize an ECDSA signature
 * @param[in] signature Pointer to the ECDSA signature to initialize
 **/

void ecdsaInitSignature(EcdsaSignature *signature)
{
   //Initialize multiple precision integers
   mpiInit(&signature->r);
   mpiInit(&signature->s);
}


/**
 * @brief Release an ECDSA signature
 * @param[in] signature Pointer to the ECDSA signature to free
 **/

void ecdsaFreeSignature(EcdsaSignature *signature)
{
   //Release multiple precision integers
   mpiFree(&signature->r);
   mpiFree(&signature->s);
}


/**
 * @brief Encode ECDSA signature using ASN.1
 * @param[in] signature (R, S) integer pair
 * @param[out] data Pointer to the buffer where to store the resulting ASN.1 structure
 * @param[out] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t ecdsaWriteSignature(const EcdsaSignature *signature, uint8_t *data,
   size_t *length)
{
   error_t error;
   size_t k;
   size_t n;
   size_t rLen;
   size_t sLen;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Writing ECDSA signature...\r\n");

   //Dump (R, S) integer pair
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //Calculate the length of R
   rLen = mpiGetByteLength(&signature->r);
   //Calculate the length of S
   sLen = mpiGetByteLength(&signature->s);

   //Make sure the (R, S) integer pair is valid
   if(rLen == 0 || sLen == 0)
      return ERROR_INVALID_LENGTH;

   //R and S are always encoded in the smallest possible number of octets
   if(mpiGetBitValue(&signature->r, (rLen * 8) - 1))
      rLen++;
   if(mpiGetBitValue(&signature->s, (sLen * 8) - 1))
      sLen++;

   //The first pass computes the length of the ASN.1 sequence
   n = 0;

   //The parameter R is encapsulated within an ASN.1 structure
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rLen;
   tag.value = NULL;

   //Compute the length of the corresponding ASN.1 structure
   error = asn1WriteTag(&tag, FALSE, NULL, NULL);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ASN.1 sequence
   n += tag.totalLength;

   //The parameter S is encapsulated within an ASN.1 structure
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = sLen;
   tag.value = NULL;

   //Compute the length of the corresponding ASN.1 structure
   error = asn1WriteTag(&tag, FALSE, NULL, NULL);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ASN.1 sequence
   n += tag.totalLength;

   //The second pass encodes the ASN.1 structure
   k = 0;

   //The (R, S) integer pair is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = n;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Encode the parameter R using ASN.1
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rLen;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Convert R to an octet string
   error = mpiWriteRaw(&signature->r, data + k, rLen);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += rLen;

   //Encode the parameter S using ASN.1
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = sLen;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Convert S to an octet string
   error = mpiWriteRaw(&signature->s, data + k, sLen);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += sLen;

   //Dump ECDSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", data, k);

   //Total length of the ASN.1 structure
   *length = k;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read an ASN.1 encoded ECDSA signature
 * @param[in] data Pointer to the ASN.1 structure to decode
 * @param[in] length Length of the ASN.1 structure
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaReadSignature(const uint8_t *data, size_t length,
   EcdsaSignature *signature)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Reading ECDSA signature...\r\n");

   //Dump ECDSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", data, length);

   //Start of exception handling block
   do
   {
      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //Read the contents of the ASN.1 structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Malformed ECDSA signature?
      if(length != tag.totalLength)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the first field
      data = tag.value;
      length = tag.length;

      //Read the parameter R
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Make sure R is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Convert the octet string to a multiple precision integer
      error = mpiReadRaw(&signature->r, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the parameter S
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Make sure S is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Convert the octet string to a multiple precision integer
      error = mpiReadRaw(&signature->s, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Malformed ECDSA signature?
      if(length != tag.totalLength)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Dump (R, S) integer pair
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->r);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->s);

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecdsaFreeSignature(signature);
   }

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi k;
   Mpi z;
   EcPoint r1;

   //Check parameters
   if(params == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("ECDSA signature generation...\r\n");
   TRACE_DEBUG("  private key:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->d);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);

   //Initialize multiple precision integers
   mpiInit(&k);
   mpiInit(&z);
   //Initialize EC point
   ecInit(&r1);

   //Generate a random number k such as 0 < k < q - 1
   MPI_CHECK(mpiRandRange(&k, &params->q, prngAlgo, prngContext));

   //Debug message
   TRACE_DEBUG("  k:\r\n");
   TRACE_DEBUG_MPI("    ", &k);

   //Let N be the bit length of q
   n = mpiGetBitLength(&params->q);
   //Compute N = MIN(N, outlen)
   n = MIN(n, digestLen * 8);

   //Convert the digest to a multiple precision integer
   MPI_CHECK(mpiReadRaw(&z, digest, (n + 7) / 8));

   //Keep the leftmost N bits of the hash value
   if((n % 8) != 0)
   {
      MPI_CHECK(mpiShiftRight(&z, 8 - (n % 8)));
   }

   //Debug message
   TRACE_DEBUG("  z:\r\n");
   TRACE_DEBUG_MPI("    ", &z);

   //Compute R1 = (x1, y1) = k.G
   EC_CHECK(ecMult(params, &r1, &k, &params->g));
   EC_CHECK(ecAffinify(params, &r1, &r1));

   //Debug message
   TRACE_DEBUG("  x1:\r\n");
   TRACE_DEBUG_MPI("    ", &r1.x);
   TRACE_DEBUG("  y1:\r\n");
   TRACE_DEBUG_MPI("    ", &r1.y);

   //Compute r = x1 mod q
   MPI_CHECK(mpiMod(&signature->r, &r1.x, &params->q));

   //Compute k ^ -1 mod q
   MPI_CHECK(mpiInvMod(&k, &k, &params->q));

   //Compute s = k ^ -1 * (z + x * r) mod q
   MPI_CHECK(mpiMul(&signature->s, &privateKey->d, &signature->r));
   MPI_CHECK(mpiAdd(&signature->s, &signature->s, &z));
   MPI_CHECK(mpiMod(&signature->s, &signature->s, &params->q));
   MPI_CHECK(mpiMulMod(&signature->s, &signature->s, &k, &params->q));

   //Dump ECDSA signature
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

end:
   //Release multiple precision integers
   mpiFree(&k);
   mpiFree(&z);
   //Release EC point
   ecFree(&r1);

   //Clean up side effects if necessary
   if(error)
   {
      //Release (R, S) integer pair
      mpiFree(&signature->r);
      mpiFree(&signature->s);
   }

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] params EC domain parameters
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecdsaVerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcdsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi w;
   Mpi z;
   Mpi u1;
   Mpi u2;
   Mpi v;
   EcPoint v0;
   EcPoint v1;

   //Check parameters
   if(params == NULL || publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("ECDSA signature verification...\r\n");
   TRACE_DEBUG("  public key X:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.x);
   TRACE_DEBUG("  public key Y:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.y);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //The verifier shall check that 0 < r < q
   if(mpiCompInt(&signature->r, 0) <= 0 ||
      mpiComp(&signature->r, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(mpiCompInt(&signature->s, 0) <= 0 ||
      mpiComp(&signature->s, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //Initialize multiple precision integers
   mpiInit(&w);
   mpiInit(&z);
   mpiInit(&u1);
   mpiInit(&u2);
   mpiInit(&v);
   //Initialize EC points
   ecInit(&v0);
   ecInit(&v1);

   //Let N be the bit length of q
   n = mpiGetBitLength(&params->q);
   //Compute N = MIN(N, outlen)
   n = MIN(n, digestLen * 8);

   //Convert the digest to a multiple precision integer
   MPI_CHECK(mpiReadRaw(&z, digest, (n + 7) / 8));

   //Keep the leftmost N bits of the hash value
   if((n % 8) != 0)
   {
      MPI_CHECK(mpiShiftRight(&z, 8 - (n % 8)));
   }

   //Compute w = s ^ -1 mod q
   MPI_CHECK(mpiInvMod(&w, &signature->s, &params->q));
   //Compute u1 = z * w mod q
   MPI_CHECK(mpiMulMod(&u1, &z, &w, &params->q));
   //Compute u2 = r * w mod q
   MPI_CHECK(mpiMulMod(&u2, &signature->r, &w, &params->q));

   //Compute V0 = (x0, y0) = u1.G + u2.Q
   EC_CHECK(ecProjectify(params, &v1, &publicKey->q));
   EC_CHECK(ecTwinMult(params, &v0, &u1, &params->g, &u2, &v1));
   EC_CHECK(ecAffinify(params, &v0, &v0));

   //Debug message
   TRACE_DEBUG("  x0:\r\n");
   TRACE_DEBUG_MPI("    ", &v0.x);
   TRACE_DEBUG("  y0:\r\n");
   TRACE_DEBUG_MPI("    ", &v0.y);

   //Compute v = x0 mod q
   MPI_CHECK(mpiMod(&v, &v0.x, &params->q));

   //Debug message
   TRACE_DEBUG("  v:\r\n");
   TRACE_DEBUG_MPI("    ", &v);

   //If v = r, then the signature is verified. If v does not equal r,
   //then the message or the signature may have been modified
   if(!mpiComp(&v, &signature->r))
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_INVALID_SIGNATURE;
   }

end:
   //Release multiple precision integers
   mpiFree(&w);
   mpiFree(&z);
   mpiFree(&u1);
   mpiFree(&u2);
   mpiFree(&v);
   //Release EC points
   ecFree(&v0);
   ecFree(&v1);

   //Return status code
   return error;
}

#endif
