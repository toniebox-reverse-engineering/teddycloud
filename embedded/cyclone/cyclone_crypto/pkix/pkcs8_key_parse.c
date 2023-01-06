/**
 * @file pkcs8_key_parse.c
 * @brief PKCS #8 key parsing
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
#include "pkix/pkcs8_key_parse.h"
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Parse PrivateKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] privateKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParsePrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;
   size_t n;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Clear the PrivateKeyInfo structure
   osMemset(privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The private key information is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read Version field
   error = asn1ReadInt32(data, length, &tag, &privateKeyInfo->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateKeyAlgorithm field
   error = pkcs8ParsePrivateKeyAlgo(data, length, &n, privateKeyInfo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The PrivateKey is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the private key
   data = tag.value;
   length = tag.length;

   //Get the private key algorithm identifier
   oid = privateKeyInfo->oid;
   oidLen = privateKeyInfo->oidLen;

#if (RSA_SUPPORT == ENABLED)
   //RSA or RSA-PSS algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Read RSAPrivateKey structure
      error = pkcs8ParseRsaPrivateKey(data, length,
         &privateKeyInfo->rsaPrivateKey);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DSAPrivateKey structure
      error = pkcs8ParseDsaPrivateKey(data, length, NULL,
         &privateKeyInfo->dsaPrivateKey);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECPrivateKey structure
      error = pkcs8ParseEcPrivateKey(data, length, &privateKeyInfo->ecParams,
         &privateKeyInfo->ecPrivateKey);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!oidComp(oid, oidLen, X25519_OID, sizeof(X25519_OID)) ||
      !oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Read CurvePrivateKey structure
      error = pkcs8ParseEddsaPrivateKey(data, length,
         &privateKeyInfo->eddsaPrivateKey);
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!oidComp(oid, oidLen, X448_OID, sizeof(X448_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Read CurvePrivateKey structure
      error = pkcs8ParseEddsaPrivateKey(data, length,
         &privateKeyInfo->eddsaPrivateKey);
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
 * @brief Parse PrivateKeyAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] privateKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParsePrivateKeyAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the PrivateKeyAlgorithm structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the private key algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the private key algorithm identifier
   privateKeyInfo->oid = tag.value;
   privateKeyInfo->oidLen = tag.length;

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
         &privateKeyInfo->dsaParams);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length,
         &privateKeyInfo->ecParams);
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
 * @brief Parse RSAPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPrivateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParseRsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8RsaPrivateKey *rsaPrivateKey)
{
   error_t error;
   Asn1Tag tag;

   //Read RSAPrivateKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Version field
   error = asn1ReadInt32(data, length, &tag, &rsaPrivateKey->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

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
   rsaPrivateKey->n = tag.value;
   rsaPrivateKey->nLen = tag.length;

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
   rsaPrivateKey->e = tag.value;
   rsaPrivateKey->eLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateExponent field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the private exponent
   rsaPrivateKey->d = tag.value;
   rsaPrivateKey->dLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Prime1 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the first factor
   rsaPrivateKey->p = tag.value;
   rsaPrivateKey->pLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Prime2 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the second factor
   rsaPrivateKey->q = tag.value;
   rsaPrivateKey->qLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Exponent1 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the first exponent
   rsaPrivateKey->dp = tag.value;
   rsaPrivateKey->dpLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Exponent2 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the second exponent
   rsaPrivateKey->dq = tag.value;
   rsaPrivateKey->dqLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Coefficient field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the coefficient
   rsaPrivateKey->qinv = tag.value;
   rsaPrivateKey->qinvLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DSAPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaParams DSA domain parameters
 * @param[out] dsaPrivateKey DSA private key
 * @return Error code
 **/

error_t pkcs8ParseDsaPrivateKey(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams, Pkcs8DsaPrivateKey *dsaPrivateKey)
{
   error_t error;
   int32_t version;
   Asn1Tag tag;

   //The DSA domain parameters can be optionally parsed
   if(dsaParams != NULL)
   {
      //Read DSAPrivateKey structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read version
      error = asn1ReadInt32(data, length, &tag, &version);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the parameter p
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
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
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
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
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Save the parameter g
      dsaParams->g = tag.value;
      dsaParams->gLen = tag.length;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the public value y
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Read the private value x
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the private value x
   dsaPrivateKey->x = tag.value;
   dsaPrivateKey->xLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecParams EC domain parameters
 * @param[out] ecPrivateKey EC private key
 * @return Error code
 **/

error_t pkcs8ParseEcPrivateKey(const uint8_t *data, size_t length,
   X509EcParameters *ecParams, Pkcs8EcPrivateKey *ecPrivateKey)
{
   error_t error;
   Asn1Tag tag;

   //Read ECPrivateKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Version field
   error = asn1ReadInt32(data, length, &tag, &ecPrivateKey->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateKey field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the EC private key
   ecPrivateKey->d = tag.value;
   ecPrivateKey->dLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Loop through optional attributes
   while(length > 0)
   {
      //Read current attribute
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Explicit tagging shall be used to encode each optional attribute
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //Parameters attribute?
      if(tag.objType == 0)
      {
         //Parse ECParameters structure
         error = x509ParseEcParameters(tag.value, tag.length, ecParams);
         //Any error to report?
         if(error)
            return error;
      }

      //Next attribute
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CurvePrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] eddsaPrivateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParseEddsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPrivateKey *eddsaPrivateKey)
{
   error_t error;
   Asn1Tag tag;

   //The CurvePrivateKey structure is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the EdDSA private key
   eddsaPrivateKey->d = tag.value;
   eddsaPrivateKey->dLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import an RSA private key
 * @param[in] privateKeyInfo Private key information
 * @param[out] privateKey RSA private key
 * @return Error code
 **/

error_t pkcs8ImportRsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   RsaPrivateKey *privateKey)
{
   error_t error;

#if (RSA_SUPPORT == ENABLED)
   const uint8_t *oid;
   size_t oidLen;

   //Get the private key algorithm identifier
   oid = privateKeyInfo->oid;
   oidLen = privateKeyInfo->oidLen;

   //RSA or RSA-PSS algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Sanity check
      if(privateKeyInfo->rsaPrivateKey.n != NULL &&
         privateKeyInfo->rsaPrivateKey.e != NULL &&
         privateKeyInfo->rsaPrivateKey.d != NULL &&
         privateKeyInfo->rsaPrivateKey.p != NULL &&
         privateKeyInfo->rsaPrivateKey.q != NULL &&
         privateKeyInfo->rsaPrivateKey.dp != NULL &&
         privateKeyInfo->rsaPrivateKey.dq != NULL &&
         privateKeyInfo->rsaPrivateKey.qinv != NULL)
      {
         //Read modulus
         error = mpiImport(&privateKey->n, privateKeyInfo->rsaPrivateKey.n,
            privateKeyInfo->rsaPrivateKey.nLen, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read public exponent
            error = mpiImport(&privateKey->e, privateKeyInfo->rsaPrivateKey.e,
               privateKeyInfo->rsaPrivateKey.eLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read private exponent
            error = mpiImport(&privateKey->d, privateKeyInfo->rsaPrivateKey.d,
               privateKeyInfo->rsaPrivateKey.dLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read first factor
            error = mpiImport(&privateKey->p, privateKeyInfo->rsaPrivateKey.p,
               privateKeyInfo->rsaPrivateKey.pLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read second factor
            error = mpiImport(&privateKey->q, privateKeyInfo->rsaPrivateKey.q,
               privateKeyInfo->rsaPrivateKey.qLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read first exponent
            error = mpiImport(&privateKey->dp, privateKeyInfo->rsaPrivateKey.dp,
               privateKeyInfo->rsaPrivateKey.dpLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read second exponent
            error = mpiImport(&privateKey->dq, privateKeyInfo->rsaPrivateKey.dq,
               privateKeyInfo->rsaPrivateKey.dqLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read coefficient
            error = mpiImport(&privateKey->qinv, privateKeyInfo->rsaPrivateKey.qinv,
               privateKeyInfo->rsaPrivateKey.qinvLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("RSA private key:\r\n");
            TRACE_DEBUG("  Modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->n);
            TRACE_DEBUG("  Public exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->e);
            TRACE_DEBUG("  Private exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->d);
            TRACE_DEBUG("  Prime 1:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->p);
            TRACE_DEBUG("  Prime 2:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->q);
            TRACE_DEBUG("  Prime exponent 1:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->dp);
            TRACE_DEBUG("  Prime exponent 2:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->dq);
            TRACE_DEBUG("  Coefficient:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->qinv);
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import a DSA private key
 * @param[in] privateKeyInfo Private key information
 * @param[out] privateKey DSA private key
 * @return Error code
 **/

error_t pkcs8ImportDsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   DsaPrivateKey *privateKey)
{
   error_t error;

#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(privateKeyInfo->oid, privateKeyInfo->oidLen, DSA_OID,
      sizeof(DSA_OID)))
   {
      //Sanity check
      if(privateKeyInfo->dsaParams.p != NULL &&
         privateKeyInfo->dsaParams.q != NULL &&
         privateKeyInfo->dsaParams.g != NULL &&
         privateKeyInfo->dsaPrivateKey.x != NULL)
      {
         //Read parameter p
         error = mpiImport(&privateKey->params.p, privateKeyInfo->dsaParams.p,
            privateKeyInfo->dsaParams.pLen, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read parameter q
            error = mpiImport(&privateKey->params.q, privateKeyInfo->dsaParams.q,
               privateKeyInfo->dsaParams.qLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read parameter g
            error = mpiImport(&privateKey->params.g, privateKeyInfo->dsaParams.g,
               privateKeyInfo->dsaParams.gLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read private value
            error = mpiImport(&privateKey->x, privateKeyInfo->dsaPrivateKey.x,
               privateKeyInfo->dsaPrivateKey.xLen, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("DSA private key:\r\n");
            TRACE_DEBUG("  Parameter p:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.p);
            TRACE_DEBUG("  Parameter q:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.q);
            TRACE_DEBUG("  Parameter g:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.g);
            TRACE_DEBUG("  Private value x:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->x);
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import an EC private key
 * @param[in] privateKeyInfo Private key information
 * @param[out] privateKey EC private key
 * @return Error code
 **/

error_t pkcs8ImportEcPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   EcPrivateKey *privateKey)
{
   error_t error;

#if (EC_SUPPORT == ENABLED)
   //EC public key algorithm identifier?
   if(!oidComp(privateKeyInfo->oid, privateKeyInfo->oidLen, EC_PUBLIC_KEY_OID,
      sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Sanity check
      if(privateKeyInfo->ecPrivateKey.d != NULL)
      {
         //Read the EC private key
         error = mpiImport(&privateKey->d, privateKeyInfo->ecPrivateKey.d,
            privateKeyInfo->ecPrivateKey.dLen, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("EC private key:\r\n");
            TRACE_DEBUG_MPI("  ", &privateKey->d);
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import an EdDSA private key
 * @param[in] privateKeyInfo Private key information
 * @param[out] privateKey EdDSA private key
 * @return Error code
 **/

error_t pkcs8ImportEddsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   EddsaPrivateKey *privateKey)
{
   error_t error;

#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 algorithm identifier?
   if(!oidComp(privateKeyInfo->oid, privateKeyInfo->oidLen, ED25519_OID,
      sizeof(ED25519_OID)))
   {
      //Check the length of the Ed25519 private key
      if(privateKeyInfo->eddsaPrivateKey.d != NULL &&
         privateKeyInfo->eddsaPrivateKey.dLen == ED25519_PRIVATE_KEY_LEN)
      {
         //Read the Ed25519 private key
         error = mpiImport(&privateKey->d, privateKeyInfo->eddsaPrivateKey.d,
            privateKeyInfo->eddsaPrivateKey.dLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //The private key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 algorithm identifier?
   if(!oidComp(privateKeyInfo->oid, privateKeyInfo->oidLen, ED448_OID,
      sizeof(ED448_OID)))
   {
      //Check the length of the Ed448 private key
      if(privateKeyInfo->eddsaPrivateKey.d != NULL &&
         privateKeyInfo->eddsaPrivateKey.dLen == ED448_PRIVATE_KEY_LEN)
      {
         //Read the Ed448 private key
         error = mpiImport(&privateKey->d, privateKeyInfo->eddsaPrivateKey.d,
            privateKeyInfo->eddsaPrivateKey.dLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //The private key is not valid
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
      TRACE_DEBUG("EdDSA private key:\r\n");
      TRACE_DEBUG_MPI("  ", &privateKey->d);
   }

   //Return status code
   return error;
}

#endif
