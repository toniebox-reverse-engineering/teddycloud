/**
 * @file x509_key_format.c
 * @brief Formatting of ASN.1 encoded keys
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
#include "pkix/x509_key_format.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "ecc/eddsa.h"
#include "hash/sha1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED || PEM_SUPPORT == ENABLED)


/**
 * @brief Format SubjectPublicKeyInfo structure
 * @param[in] publicKeyInfo Subject's public key information
 * @param[in] publicKey Pointer to the public key (RSA, DSA, ECDSA or EdDSA)
 * @param[out] keyId Subject's key identifier (optional parameter)
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSubjectPublicKeyInfo(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const void *publicKey, uint8_t *keyId, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Get the public key identifier
   oid = publicKeyInfo->oid;
   oidLen = publicKeyInfo->oidLen;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

#if (DSA_SUPPORT == ENABLED)
   //Valid DSA public key?
   if(publicKey != NULL && !oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      const DsaPublicKey *dsaPublicKey;

      //Point to the DSA public key
      dsaPublicKey = (DsaPublicKey *) publicKey;

      //Format AlgorithmIdentifier field
      error = x509FormatAlgorithmIdentifier(publicKeyInfo,
         &dsaPublicKey->params, p, &n);
   }
   else
#endif
   {
      //Format AlgorithmIdentifier field
      error = x509FormatAlgorithmIdentifier(publicKeyInfo, NULL, p, &n);
   }

   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   p[0] = 0;

#if (RSA_SUPPORT == ENABLED)
   //RSA or RSA-PSS algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Valid RSA public key?
      if(publicKey != NULL)
      {
         //Export the RSA public key to ASN.1 format
         error = x509ExportRsaPublicKey(publicKey, p + 1, &n);
      }
      else
      {
         //Format RSAPublicKey structure
         error = x509FormatRsaPublicKey(&publicKeyInfo->rsaPublicKey,
            p + 1, &n);
      }
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Valid DSA public key?
      if(publicKey != NULL)
      {
         //Export the DSA public key to ASN.1 format
         error = x509ExportDsaPublicKey(publicKey, p + 1, &n);
      }
      else
      {
         //Format DSAPublicKey structure
         error = x509FormatDsaPublicKey(&publicKeyInfo->dsaPublicKey,
            p + 1, &n);
      }
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Valid EC public key?
      if(publicKey != NULL)
      {
         //Export the EC public key to ASN.1 format
         error = x509ExportEcPublicKey(publicKeyInfo, publicKey,
            p + 1, &n);
      }
      else
      {
         //Format ECPublicKey structure
         error = x509FormatEcPublicKey(&publicKeyInfo->ecPublicKey,
            p + 1, &n);
      }
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 algorithm identifier?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Valid EdDSA public key?
      if(publicKey != NULL)
      {
         //Export the EdDSA public key to ASN.1 format
         error = x509ExportEddsaPublicKey(publicKey, ED25519_PUBLIC_KEY_LEN,
            p + 1, &n);
      }
      else
      {
         //The SubjectPublicKey contains the byte stream of the public key
         error = x509FormatEcPublicKey(&publicKeyInfo->ecPublicKey,
            p + 1, &n);
      }
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 algorithm identifier?
   if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Valid EdDSA public key?
      if(publicKey != NULL)
      {
         //Export the EdDSA public key to ASN.1 format
         error = x509ExportEddsaPublicKey(publicKey, ED448_PUBLIC_KEY_LEN,
            p + 1, &n);
      }
      else
      {
         //The SubjectPublicKey contains the byte stream of the public key
         error = x509FormatEcPublicKey(&publicKeyInfo->ecPublicKey,
            p + 1, &n);
      }
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Any error to report?
   if(error)
      return error;

   //The keyIdentifier parameter is optional
   if(keyId != NULL)
   {
      //The keyIdentifier is composed of the 160-bit SHA-1 hash of the value
      //of the bit string subjectPublicKey (excluding the tag, length, and
      //number of unused bits)
      error = sha1Compute(p + 1, n, keyId);
      //Any error to report?
      if(error)
         return error;
   }

   //The public key is encapsulated within a bit string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_BIT_STRING;
   tag.length = n + 1;
   tag.value = p;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The SubjectPublicKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format AlgorithmIdentifier structure
 * @param[in] publicKeyInfo Subject's public key information
 * @param[in] params Pointer to the domain parameters (DSA or ECDSA)
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatAlgorithmIdentifier(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const void *params, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Get the public key identifier
   oid = publicKeyInfo->oid;
   oidLen = publicKeyInfo->oidLen;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format algorithm OID
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = oidLen;
   tag.value = oid;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //The parameters field must have ASN.1 type NULL for this algorithm
      //identifier (refer to RFC 3279, section 2.3.1)
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_NULL;
      tag.length = 0;
      tag.value = NULL;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
   }
   //RSA-PSS algorithm identifier?
   else if(!oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //The parameters may be either absent or present when used as subject
      //public key information (refer to RFC 4055, section 3.1)
      n = 0;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Valid DSA domain parameters?
      if(params != NULL)
      {
         //Export the DSA domain parameters to ASN.1 format
         error = x509ExportDsaParameters(params, p, &n);
      }
      else
      {
         //Format DSAParameters structure
         error = x509FormatDsaParameters(&publicKeyInfo->dsaParams, p, &n);
      }
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   //ECDSA algorithm identifier?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Format ECParameters structure
      error = x509FormatEcParameters(&publicKeyInfo->ecParams, p, &n);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!oidComp(oid, oidLen, X25519_OID, sizeof(X25519_OID)) ||
      !oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      n = 0;
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!oidComp(oid, oidLen, X448_OID, sizeof(X448_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      n = 0;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The AlgorithmIdentifier structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSAPublicKey structure
 * @param[in] rsaPublicKey Pointer to the RSA public key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPublicKey(const X509RsaPublicKey *rsaPublicKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Write Modulus field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rsaPublicKey->nLen;
   tag.value = rsaPublicKey->n;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write PublicExponent field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rsaPublicKey->eLen;
   tag.value = rsaPublicKey->e;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The public key is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write RSAPublicKey structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS parameters
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssParameters(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format hashAlgorithm parameter
   error = x509FormatRsaPssHashAlgo(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format maskGenAlgorithm parameter
   error = x509FormatRsaPssMaskGenAlgo(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format saltLength parameter
   error = x509FormatRsaPssSaltLength(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The RSASSA-PSS parameters are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS hash algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default hash algorithm is SHA-1
   if(rsaPssParams->hashAlgo != NULL && rsaPssParams->hashAlgoLen > 0)
   {
      //Write the hash algorithm identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->hashAlgoLen;
      tag.value = rsaPssParams->hashAlgo;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //The hashAlgorithm parameter is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode each parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS mask generation algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssMaskGenAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The default mask generation function is MGF1
   if(rsaPssParams->maskGenAlgo != NULL && rsaPssParams->maskGenAlgoLen > 0)
   {
      //Write the mask generation algorithm identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->maskGenAlgoLen;
      tag.value = rsaPssParams->maskGenAlgo;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      length += n;

      //Write the algorithm identifier of the one-way hash function employed
      //with the mask generation function
      error = x509FormatRsaPssMaskGenHashAlgo(rsaPssParams, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      length += n;

      //The maskGenAlgorithm parameter is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &length);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode each parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 1;
      tag.length = length;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS mask generation hash algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssMaskGenHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default hash algorithm is SHA-1
   if(rsaPssParams->maskGenHashAlgo != NULL &&
      rsaPssParams->maskGenHashAlgoLen > 0)
   {
      //Write the algorithm identifier of the one-way hash function employed
      //with the mask generation function
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->maskGenHashAlgoLen;
      tag.value = rsaPssParams->maskGenHashAlgo;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //The hash algorithm identifier is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS salt length
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssSaltLength(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default length of the salt is 20
   if(rsaPssParams->saltLen != 20)
   {
      //Write the length of the salt
      error = asn1WriteInt32((int32_t) rsaPssParams->saltLen, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the saltLength parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 2;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format DSAPublicKey structure
 * @param[in] dsaPublicKey Pointer to the DSA public key
 * @param[out] output Buffer where to format the DSAPublicKey structure
 * @param[out] written Length of the DSAPublicKey structure
 * @return Error code
 **/

error_t x509FormatDsaPublicKey(const X509DsaPublicKey *dsaPublicKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Write public key
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = dsaPublicKey->yLen;
   tag.value = dsaPublicKey->y;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format DSA domain parameters
 * @param[in] dsaParams Pointer to the DSA domain parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatDsaParameters(const X509DsaParameters *dsaParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Write parameter p
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = dsaParams->pLen;
   tag.value = dsaParams->p;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write parameter q
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = dsaParams->qLen;
   tag.value = dsaParams->q;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write parameter g
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = dsaParams->gLen;
   tag.value = dsaParams->g;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The DSA domain parameters are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write DSAParameters structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ECPublicKey structure
 * @param[in] ecPublicKey Pointer to the EC public key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatEcPublicKey(const X509EcPublicKey *ecPublicKey,
   uint8_t *output, size_t *written)
{
   size_t n;

   //Retrieve the length of the EC public key
   n = ecPublicKey->qLen;

   //Copy the EC public key
   osMemcpy(output, ecPublicKey->q, n);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ECParameters structure
 * @param[in] ecParams Pointer to the EC parameters
 * @param[out] output Buffer where to format the ECParameters structure
 * @param[out] written Length of the ECParameters structure
 * @return Error code
 **/

error_t x509FormatEcParameters(const X509EcParameters *ecParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The namedCurve field identifies all the required values for a particular
   //set of elliptic curve domain parameters to be represented by an object
   //identifier
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = ecParams->namedCurveLen;
   tag.value = ecParams->namedCurve;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an RSA public key to ASN.1 format
 * @param[in] publicKey Pointer to the RSA public key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportRsaPublicKey(const RsaPublicKey *publicKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Write Modulus field
   error = asn1WriteMpi(&publicKey->n, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write PublicExponent field
   error = asn1WriteMpi(&publicKey->e, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The public key is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write RSAPublicKey structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an RSA private key to ASN.1 format
 * @param[in] privateKey Pointer to the RSA private key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Write Version field
   error = asn1WriteInt32(0, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Modulus field
   error = asn1WriteMpi(&privateKey->n, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write PublicExponent field
   error = asn1WriteMpi(&privateKey->e, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write PrivateExponent field
   error = asn1WriteMpi(&privateKey->d, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Prime1 field
   error = asn1WriteMpi(&privateKey->p, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Prime2 field
   error = asn1WriteMpi(&privateKey->q, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Exponent1 field
   error = asn1WriteMpi(&privateKey->dp, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Exponent2 field
   error = asn1WriteMpi(&privateKey->dq, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //Write Coefficient field
   error = asn1WriteMpi(&privateKey->qinv, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the RSAPrivateKey structure
   length += n;

   //Advance data pointer
   if(output != NULL)
   {
      p += n;
   }

   //The private key is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write RSAPrivateKey structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a DSA public key to ASN.1 format
 * @param[in] publicKey Pointer to the DSA public key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportDsaPublicKey(const DsaPublicKey *publicKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Write public key
   error = asn1WriteMpi(&publicKey->y, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a DSA private key to ASN.1 format
 * @param[in] privateKey Pointer to the DSA private key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Write private key
   error = asn1WriteMpi(&privateKey->x, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export DSA domain parameters to ASN.1 format
 * @param[in] params Pointer to the DSA domain parameters
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportDsaParameters(const DsaDomainParameters *params,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Write parameter p
   error = asn1WriteMpi(&params->p, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write parameter q
   error = asn1WriteMpi(&params->q, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write parameter g
   error = asn1WriteMpi(&params->g, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The DSA domain parameters are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

   //Write DSAParameters structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an EC public key to ASN.1 format
 * @param[in] publicKeyInfo Public key information
 * @param[in] publicKey Pointer to the EC public key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportEcPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const EcPoint *publicKey, uint8_t *output, size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   const EcCurveInfo *curveInfo;
   EcDomainParameters params;

   //Initialize EC domain parameters
   ecInitDomainParameters(&params);

   //Retrieve EC domain parameters
   curveInfo = x509GetCurveInfo(publicKeyInfo->ecParams.namedCurve,
      publicKeyInfo->ecParams.namedCurveLen);

   //Make sure the specified elliptic curve is supported
   if(curveInfo != NULL)
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(&params, curveInfo);
   }
   else
   {
      //Invalid EC domain parameters
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Check status code
   if(!error)
   {
      //Format ECPublicKey structure
      error = ecExport(&params, publicKey, output, written);
   }

   //Release EC domain parameters
   ecFreeDomainParameters(&params);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EdDSA public key to ASN.1 format
 * @param[in] publicKey Pointer to the EdDSA public key
 * @param[in] publicKeyLen Length of the EdDSA public key, in bytes
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportEddsaPublicKey(const EddsaPublicKey *publicKey,
   size_t publicKeyLen, uint8_t *output, size_t *written)
{
   error_t error;

   //The SubjectPublicKey contains the byte stream of the public key
   error = mpiExport(&publicKey->q, output, publicKeyLen,
      MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = publicKeyLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an EdDSA private key to ASN.1 format
 * @param[in] privateKey Pointer to the EdDSA private key
 * @param[in] privateKeyLen Length of the EdDSA private key, in bytes
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509ExportEddsaPrivateKey(const EddsaPrivateKey *privateKey,
   size_t privateKeyLen, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The private key is always an opaque byte sequence
   error = mpiExport(&privateKey->d, output, privateKeyLen,
      MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The private key is encapsulated within an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = privateKeyLen;
   tag.value = output;

   //Write CurvePrivateKey structure
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}

#endif
