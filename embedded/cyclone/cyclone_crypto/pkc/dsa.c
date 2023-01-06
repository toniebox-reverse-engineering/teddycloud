/**
 * @file dsa.c
 * @brief DSA (Digital Signature Algorithm)
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
 * The Digital Signature Algorithm (DSA) is a an algorithm developed by the
 * NSA to generate a digital signature for the authentication of electronic
 * documents. Refer to FIPS 186-3 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkc/dsa.h"
#include "mpi/mpi.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (DSA_SUPPORT == ENABLED)

//DSA OID (1.2.840.10040.4.1)
const uint8_t DSA_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01};
//DSA with SHA-1 OID (1.2.840.10040.4.3)
const uint8_t DSA_WITH_SHA1_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03};
//DSA with SHA-224 OID (2.16.840.1.101.3.4.3.1)
const uint8_t DSA_WITH_SHA224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01};
//DSA with SHA-256 OID (2.16.840.1.101.3.4.3.2)
const uint8_t DSA_WITH_SHA256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02};
//DSA with SHA-384 OID (2.16.840.1.101.3.4.3.3)
const uint8_t DSA_WITH_SHA384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03};
//DSA with SHA-512 OID (2.16.840.1.101.3.4.3.4)
const uint8_t DSA_WITH_SHA512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04};
//DSA with SHA-3-224 OID (2.16.840.1.101.3.4.3.5)
const uint8_t DSA_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05};
//DSA with SHA-3-256 OID (2.16.840.1.101.3.4.3.6)
const uint8_t DSA_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06};
//DSA with SHA-3-384 OID (2.16.840.1.101.3.4.3.7)
const uint8_t DSA_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07};
//DSA with SHA-3-512 OID (2.16.840.1.101.3.4.3.8)
const uint8_t DSA_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08};


/**
 * @brief Initialize DSA domain parameters
 * @param[in] params Pointer to the DSA domain parameters to initialize
 **/

void dsaInitDomainParameters(DsaDomainParameters *params)
{
   //Initialize multiple precision integers
   mpiInit(&params->p);
   mpiInit(&params->q);
   mpiInit(&params->g);
}


/**
 * @brief Release DSA domain parameters
 * @param[in] params Pointer to the DSA domain parameters to free
 **/

void dsaFreeDomainParameters(DsaDomainParameters *params)
{
   //Free multiple precision integers
   mpiFree(&params->p);
   mpiFree(&params->q);
   mpiFree(&params->g);
}


/**
 * @brief Initialize a DSA public key
 * @param[in] key Pointer to the DSA public key to initialize
 **/

void dsaInitPublicKey(DsaPublicKey *key)
{
   //Initialize DSA domain parameters
   dsaInitDomainParameters(&key->params);
   //Initialize public key value
   mpiInit(&key->y);
}


/**
 * @brief Release a DSA public key
 * @param[in] key Pointer to the DSA public key to free
 **/

void dsaFreePublicKey(DsaPublicKey *key)
{
   //Free DSA domain parameters
   dsaFreeDomainParameters(&key->params);
   //Free public key value
   mpiFree(&key->y);
}


/**
 * @brief Initialize a DSA private key
 * @param[in] key Pointer to the DSA private key to initialize
 **/

void dsaInitPrivateKey(DsaPrivateKey *key)
{
   //Initialize DSA domain parameters
   dsaInitDomainParameters(&key->params);
   //Initialize secret exponent
   mpiInit(&key->x);

   //Initialize private key slot
   key->slot = -1;
}


/**
 * @brief Release a DSA private key
 * @param[in] key Pointer to the DSA public key to free
 **/

void dsaFreePrivateKey(DsaPrivateKey *key)
{
   //Free DSA domain parameters
   dsaFreeDomainParameters(&key->params);
   //Free secret exponent
   mpiFree(&key->x);
}


/**
 * @brief Initialize a DSA signature
 * @param[in] signature Pointer to the DSA signature to initialize
 **/

void dsaInitSignature(DsaSignature *signature)
{
   //Initialize multiple precision integers
   mpiInit(&signature->r);
   mpiInit(&signature->s);
}


/**
 * @brief Release a DSA signature
 * @param[in] signature Pointer to the DSA signature to free
 **/

void dsaFreeSignature(DsaSignature *signature)
{
   //Release multiple precision integers
   mpiFree(&signature->r);
   mpiFree(&signature->s);
}


/**
 * @brief Encode DSA signature using ASN.1
 * @param[in] signature (R, S) integer pair
 * @param[out] data Pointer to the buffer where to store the resulting ASN.1 structure
 * @param[out] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t dsaWriteSignature(const DsaSignature *signature, uint8_t *data, size_t *length)
{
   error_t error;
   size_t k;
   size_t n;
   size_t rLen;
   size_t sLen;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Writing DSA signature...\r\n");

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

   //Dump DSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", data, k);

   //Total length of the ASN.1 structure
   *length = k;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read an ASN.1 encoded DSA signature
 * @param[in] data Pointer to the ASN.1 structure to decode
 * @param[in] length Length of the ASN.1 structure
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t dsaReadSignature(const uint8_t *data, size_t length, DsaSignature *signature)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Reading DSA signature...\r\n");

   //Dump DSA signature
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

      //Malformed DSA signature?
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

      //Malformed DSA signature?
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
      dsaFreeSignature(signature);
   }

   //Return status code
   return error;
}


/**
 * @brief DSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] key Signer's DSA private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t dsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const DsaPrivateKey *key, const uint8_t *digest, size_t digestLen,
   DsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi k;
   Mpi z;

   //Check parameters
   if(key == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("DSA signature generation...\r\n");
   TRACE_DEBUG("  p:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.p);
   TRACE_DEBUG("  q:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.q);
   TRACE_DEBUG("  g:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.g);
   TRACE_DEBUG("  x:\r\n");
   TRACE_DEBUG_MPI("    ", &key->x);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);

   //Initialize multiple precision integers
   mpiInit(&k);
   mpiInit(&z);

   //Generate a random number k such as 0 < k < q - 1
   MPI_CHECK(mpiRandRange(&k, &key->params.q, prngAlgo, prngContext));

   //Debug message
   TRACE_DEBUG("  k:\r\n");
   TRACE_DEBUG_MPI("    ", &k);

   //Let N be the bit length of q
   n = mpiGetBitLength(&key->params.q);
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

   //Compute r = (g ^ k mod p) mod q
   MPI_CHECK(mpiExpModRegular(&signature->r, &key->params.g, &k, &key->params.p));
   MPI_CHECK(mpiMod(&signature->r, &signature->r, &key->params.q));

   //Compute k ^ -1 mod q
   MPI_CHECK(mpiInvMod(&k, &k, &key->params.q));

   //Compute s = k ^ -1 * (z + x * r) mod q
   MPI_CHECK(mpiMul(&signature->s, &key->x, &signature->r));
   MPI_CHECK(mpiAdd(&signature->s, &signature->s, &z));
   MPI_CHECK(mpiMod(&signature->s, &signature->s, &key->params.q));
   MPI_CHECK(mpiMulMod(&signature->s, &signature->s, &k, &key->params.q));

   //Dump DSA signature
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

end:
   //Release multiple precision integers
   mpiFree(&k);
   mpiFree(&z);

   //Clean up side effects if necessary
   if(error)
   {
      //Release (R, S) integer pair
      mpiFree(&signature->r);
      mpiFree(&signature->r);
   }

   //Return status code
   return error;
}


/**
 * @brief DSA signature verification
 * @param[in] key Signer's DSA public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t dsaVerifySignature(const DsaPublicKey *key,
   const uint8_t *digest, size_t digestLen, const DsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi w;
   Mpi z;
   Mpi u1;
   Mpi u2;
   Mpi v;

   //Check parameters
   if(key == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("DSA signature verification...\r\n");
   TRACE_DEBUG("  p:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.p);
   TRACE_DEBUG("  q:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.q);
   TRACE_DEBUG("  g:\r\n");
   TRACE_DEBUG_MPI("    ", &key->params.g);
   TRACE_DEBUG("  y:\r\n");
   TRACE_DEBUG_MPI("    ", &key->y);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //The verifier shall check that 0 < r < q
   if(mpiCompInt(&signature->r, 0) <= 0 ||
      mpiComp(&signature->r, &key->params.q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(mpiCompInt(&signature->s, 0) <= 0 ||
      mpiComp(&signature->s, &key->params.q) >= 0)
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

   //Let N be the bit length of q
   n = mpiGetBitLength(&key->params.q);
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
   MPI_CHECK(mpiInvMod(&w, &signature->s, &key->params.q));
   //Compute u1 = z * w mod q
   MPI_CHECK(mpiMulMod(&u1, &z, &w, &key->params.q));
   //Compute u2 = r * w mod q
   MPI_CHECK(mpiMulMod(&u2, &signature->r, &w, &key->params.q));

   //Compute v = ((g ^ u1) * (y ^ u2) mod p) mod q
   MPI_CHECK(mpiExpModFast(&v, &key->params.g, &u1, &key->params.p));
   MPI_CHECK(mpiExpModFast(&w, &key->y, &u2, &key->params.p));
   MPI_CHECK(mpiMulMod(&v, &v, &w, &key->params.p));
   MPI_CHECK(mpiMod(&v, &v, &key->params.q));

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

   //Return status code
   return error;
}

#endif
