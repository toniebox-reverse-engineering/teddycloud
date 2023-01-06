/**
 * @file x509_key_parse.c
 * @brief Parsing of ASN.1 encoded keys
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
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "ecc/eddsa.h"
#include "hash/sha1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED || PEM_SUPPORT == ENABLED)


/**
 * @brief Parse SubjectPublicKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] publicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;
   size_t n;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing SubjectPublicKeyInfo...\r\n");

   //Clear the SubjectPublicKeyInfo structure
   osMemset(publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The public key information is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   publicKeyInfo->rawData = data;
   publicKeyInfo->rawDataLen = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read AlgorithmIdentifier field
   error = x509ParseAlgorithmIdentifier(data, length, &n, publicKeyInfo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The SubjectPublicKey is encapsulated within a bit string
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

   //Point to the public key
   data = tag.value + 1;
   length = tag.length - 1;

   //Get the public key algorithm identifier
   oid = publicKeyInfo->oid;
   oidLen = publicKeyInfo->oidLen;

#if (RSA_SUPPORT == ENABLED)
   //RSA or RSA-PSS algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(data, length, &publicKeyInfo->rsaPublicKey);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DSAPublicKey structure
      error = x509ParseDsaPublicKey(data, length, &publicKeyInfo->dsaPublicKey);
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!oidComp(oid, oidLen, X25519_OID, sizeof(X25519_OID)) ||
      !oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!oidComp(oid, oidLen, X448_OID, sizeof(X448_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse AlgorithmIdentifier structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] publicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAlgorithmIdentifier(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AlgorithmIdentifier...\r\n");

   //Read AlgorithmIdentifier field
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read algorithm identifier (OID)
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the algorithm identifier
   publicKeyInfo->oid = tag.value;
   publicKeyInfo->oidLen = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //The parameters field must have ASN.1 type NULL for this algorithm
      //identifier (refer to RFC 3279, section 2.3.1)
      error = NO_ERROR;
   }
   //RSA-PSS algorithm identifier?
   else if(!asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //The parameters may be either absent or present when used as subject
      //public key information (refer to RFC 4055, section 3.1)
      error = NO_ERROR;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DsaParameters structure
      error = x509ParseDsaParameters(data, length,
         &publicKeyInfo->dsaParams);
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length,
         &publicKeyInfo->ecParams);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!asn1CheckOid(&tag, X25519_OID, sizeof(X25519_OID)) ||
      !asn1CheckOid(&tag, ED25519_OID, sizeof(ED25519_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      error = NO_ERROR;
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!asn1CheckOid(&tag, X448_OID, sizeof(X448_OID)) ||
      !asn1CheckOid(&tag, ED448_OID, sizeof(ED448_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      error = NO_ERROR;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse RSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPublicKey(const uint8_t *data, size_t length,
   X509RsaPublicKey *rsaPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RSAPublicKey...\r\n");

   //Read RSAPublicKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Modulus field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the modulus
   rsaPublicKey->n = tag.value;
   rsaPublicKey->nLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PublicExponent field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the public exponent
   rsaPublicKey->e = tag.value;
   rsaPublicKey->eLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RSASSA-PSS parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssParameters(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
   error_t error;
   Asn1Tag tag;

   //Clear RSASSA-PSS parameters
   osMemset(rsaPssParams, 0, sizeof(X509RsaPssParameters));

#if (SHA1_SUPPORT == ENABLED)
   //The default hash algorithm is SHA-1 (refer to RFC 4055, section 3.1)
   rsaPssParams->hashAlgo = SHA1_OID;
   rsaPssParams->hashAlgoLen = sizeof(SHA1_OID);
#endif

#if (RSA_SUPPORT == ENABLED)
   //The default mask generation function is MGF1 with SHA-1
   rsaPssParams->maskGenAlgo = MGF1_OID;
   rsaPssParams->maskGenAlgoLen = sizeof(MGF1_OID);
#endif

#if (SHA1_SUPPORT == ENABLED)
   //MGF1 requires a one-way hash function that is identified in the
   //parameters field of the MGF1 algorithm identifier
   rsaPssParams->maskGenHashAlgo = SHA1_OID;
   rsaPssParams->maskGenHashAlgoLen = sizeof(SHA1_OID);
#endif

   //The default length of the salt is 20
   rsaPssParams->saltLen = 20;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse RSASSA-PSS parameters
   while(length > 0)
   {
      //Read current parameter
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //The tags in this sequence are explicit
      if(!asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0))
      {
         //Parse hashAlgorithm parameter
         error = x509ParseRsaPssHashAlgo(tag.value, tag.length,
            rsaPssParams);
      }
      else if(!asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1))
      {
         //Parse maskGenAlgorithm parameter
         error = x509ParseRsaPssMaskGenAlgo(tag.value, tag.length,
            rsaPssParams);
      }
      else if(!asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 2))
      {
         //Parse saltLength parameter
         error = x509ParseRsaPssSaltLength(tag.value, tag.length,
            rsaPssParams);
      }
      else
      {
         //Discard current parameter
         error = NO_ERROR;
      }

      //Any parsing error?
      if(error)
         return error;

      //Next parameter
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RSASSA-PSS hash algorithm
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssHashAlgo(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read hash algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the hash algorithm identifier
   rsaPssParams->hashAlgo = tag.value;
   rsaPssParams->hashAlgoLen = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse RSASSA-PSS mask generation algorithm
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssMaskGenAlgo(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read mask generation algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the mask generation algorithm identifier
   rsaPssParams->maskGenAlgo = tag.value;
   rsaPssParams->maskGenAlgoLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the algorithm identifier of the one-way hash function employed
   //with the mask generation function
   error = x509ParseRsaPssMaskGenHashAlgo(data, length, rsaPssParams);
   //Any error to report?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse RSASSA-PSS mask generation hash algorithm
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssMaskGenHashAlgo(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the algorithm identifier of the one-way hash function employed
   //with the mask generation function
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the hash algorithm identifier
   rsaPssParams->maskGenHashAlgo = tag.value;
   rsaPssParams->maskGenHashAlgoLen = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse RSASSA-PSS salt length
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssSaltLength(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
   error_t error;
   int32_t saltLen;
   Asn1Tag tag;

   //Read the saltLength field
   error = asn1ReadInt32(data, length, &tag, &saltLen);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Sanity check
   if(saltLen < 0)
      return ERROR_INVALID_SYNTAX;

   //Save the length of the salt
   rsaPssParams->saltLen = (size_t) saltLen;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse DSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaPublicKey(const uint8_t *data, size_t length,
   X509DsaPublicKey *dsaPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing DSAPublicKey...\r\n");

   //Read DSAPublicKey structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the DSA public value
   dsaPublicKey->y = tag.value;
   dsaPublicKey->yLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DSA domain parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaParameters(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing DSAParameters...\r\n");

   //Read DSAParameters structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read the parameter p
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter p
   dsaParams->p = tag.value;
   dsaParams->pLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter q
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter q
   dsaParams->q = tag.value;
   dsaParams->qLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter g
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter g
   dsaParams->g = tag.value;
   dsaParams->gLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey)
{
   //Debug message
   TRACE_DEBUG("      Parsing ECPublicKey...\r\n");

   //Make sure the EC public key is valid
   if(length == 0)
      return ERROR_BAD_CERTIFICATE;

   //Save the EC public key
   ecPublicKey->q = data;
   ecPublicKey->qLen = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECParameters structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcParameters(const uint8_t *data, size_t length,
   X509EcParameters *ecParams)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing ECParameters...\r\n");

   //Read namedCurve field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The namedCurve field identifies all the required values for a particular
   //set of elliptic curve domain parameters to be represented by an object
   //identifier
   ecParams->namedCurve = tag.value;
   ecParams->namedCurveLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import an RSA public key
 * @param[in] publicKeyInfo Public key information
 * @param[out] publicKey RSA public key
 * @return Error code
 **/

error_t x509ImportRsaPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   RsaPublicKey *publicKey)
{
   error_t error;

#if (RSA_SUPPORT == ENABLED)
   const uint8_t *oid;
   size_t oidLen;

   //Get the public key algorithm identifier
   oid = publicKeyInfo->oid;
   oidLen = publicKeyInfo->oidLen;

   //RSA algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Sanity check
      if(publicKeyInfo->rsaPublicKey.n != NULL &&
         publicKeyInfo->rsaPublicKey.e != NULL)
      {
         //Read modulus
         error = mpiImport(&publicKey->n, publicKeyInfo->rsaPublicKey.n,
            publicKeyInfo->rsaPublicKey.nLen, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read public exponent
            error = mpiImport(&publicKey->e, publicKeyInfo->rsaPublicKey.e,
               publicKeyInfo->rsaPublicKey.eLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("RSA public key:\r\n");
            TRACE_DEBUG("  Modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->n);
            TRACE_DEBUG("  Public exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->e);
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import a DSA public key
 * @param[in] publicKeyInfo Public key information
 * @param[out] publicKey DSA public key
 * @return Error code
 **/

error_t x509ImportDsaPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   DsaPublicKey *publicKey)
{
   error_t error;

#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen, DSA_OID,
      sizeof(DSA_OID)))
   {
      //Sanity check
      if(publicKeyInfo->dsaParams.p != NULL &&
         publicKeyInfo->dsaParams.q != NULL &&
         publicKeyInfo->dsaParams.g != NULL &&
         publicKeyInfo->dsaPublicKey.y != NULL)
      {
         //Read parameter p
         error = mpiImport(&publicKey->params.p, publicKeyInfo->dsaParams.p,
            publicKeyInfo->dsaParams.pLen, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read parameter q
            error = mpiImport(&publicKey->params.q, publicKeyInfo->dsaParams.q,
               publicKeyInfo->dsaParams.qLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read parameter g
            error = mpiImport(&publicKey->params.g, publicKeyInfo->dsaParams.g,
               publicKeyInfo->dsaParams.gLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read public value
            error = mpiImport(&publicKey->y, publicKeyInfo->dsaPublicKey.y,
               publicKeyInfo->dsaPublicKey.yLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("DSA public key:\r\n");
            TRACE_DEBUG("  Parameter p:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.p);
            TRACE_DEBUG("  Parameter q:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.q);
            TRACE_DEBUG("  Parameter g:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.g);
            TRACE_DEBUG("  Public value y:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->y);
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import an EC public key
 * @param[in] publicKeyInfo Public key information
 * @param[out] publicKey EC public key
 * @return Error code
 **/

error_t x509ImportEcPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   EcPublicKey *publicKey)
{
   error_t error;

#if (EC_SUPPORT == ENABLED)
   const EcCurveInfo *curveInfo;
   EcDomainParameters params;

   //EC public key identifier?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen, EC_PUBLIC_KEY_OID,
      sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Sanity check
      if(publicKeyInfo->ecParams.namedCurve != NULL &&
         publicKeyInfo->ecPublicKey.q != NULL)
      {
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
            //Read the EC public key
            error = ecImport(&params, &publicKey->q, publicKeyInfo->ecPublicKey.q,
               publicKeyInfo->ecPublicKey.qLen);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  Public key X:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->q.x);
            TRACE_DEBUG("  Public key Y:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->q.y);
         }

         //Release EC domain parameters
         ecFreeDomainParameters(&params);
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import EC domain parameters
 * @param[in] ecParams Pointer to the ECParameters structure
 * @param[out] params EC domain parameters
 * @return Error code
 **/

error_t x509ImportEcParameters(const X509EcParameters *ecParams,
   EcDomainParameters *params)
{
   error_t error;

#if (EC_SUPPORT == ENABLED)
   const EcCurveInfo *curveInfo;

   //Retrieve EC domain parameters
   curveInfo = ecGetCurveInfo(ecParams->namedCurve, ecParams->namedCurveLen);

   //Make sure the specified elliptic curve is supported
   if(curveInfo != NULL)
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(params, curveInfo);
   }
   else
#endif
   {
      //Invalid EC domain parameters
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import an EdDSA public key
 * @param[in] publicKeyInfo Public key information
 * @param[out] publicKey EdDSA public key
 * @return Error code
 **/

error_t x509ImportEddsaPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   EddsaPublicKey *publicKey)
{
   error_t error;

#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 algorithm identifier?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen, ED25519_OID,
      sizeof(ED25519_OID)))
   {
      //Check the length of the Ed25519 public key
      if(publicKeyInfo->ecPublicKey.q != NULL &&
         publicKeyInfo->ecPublicKey.qLen == ED25519_PUBLIC_KEY_LEN)
      {
         //Read the Ed25519 public key
         error = mpiImport(&publicKey->q, publicKeyInfo->ecPublicKey.q,
            publicKeyInfo->ecPublicKey.qLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 algorithm identifier?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen, ED448_OID,
      sizeof(ED448_OID)))
   {
      //Check the length of the Ed448 public key
      if(publicKeyInfo->ecPublicKey.q != NULL &&
         publicKeyInfo->ecPublicKey.qLen == ED448_PUBLIC_KEY_LEN)
      {
         //Read the Ed448 public key
         error = mpiImport(&publicKey->q, publicKeyInfo->ecPublicKey.q,
            publicKeyInfo->ecPublicKey.qLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("EdDSA public key:\r\n");
      TRACE_DEBUG_MPI("  ", &publicKey->q);
   }

   //Return status code
   return error;
}

#endif
