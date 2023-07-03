/**
 * @file pkcs8_key_format.c
 * @brief PKCS #8 key formatting
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
#include "pkix/pkcs8_key_format.h"
#include "pkix/x509_key_format.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Format an RSA private key
 * @param[in] privateKey Pointer to the RSA private key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs8FormatRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Export the RSA private key to ASN.1 format
   error = x509ExportRsaPrivateKey(privateKey, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The RSAPrivateKey structure is encapsulated within an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;
   tag.value = output;

   //Write PrivateKey structure
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
 * @brief Format a DSA private key
 * @param[in] privateKey Pointer to the RSA private key
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs8FormatDsaPrivateKey(const DsaPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Export the DSA private key to ASN.1 format
   error = x509ExportDsaPrivateKey(privateKey, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The DSAPrivateKey structure is encapsulated within an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;
   tag.value = output;

   //Write PrivateKey structure
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
 * @brief Format an EC private key
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] privateKey EC private key
 * @param[in] publicKey EC public key (optional parameter)
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs8FormatEcPrivateKey(const EcCurveInfo *curveInfo,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
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

   //Format Version field (refer to RFC 5915, section 3)
   error = asn1WriteInt32(1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ECPrivateKey structure
   length += n;

   //If the output parameter is NULL, then the function calculates the
   //length of the resulting PEM file without copying any data
   if(output != NULL)
   {
      //Advance data pointer
      p += n;

      //Write the EC private key
      error = mpiWriteRaw(&privateKey->d, p, curveInfo->pLen);
      //Any error to report?
      if(error)
         return error;
   }

   //Format PrivateKey field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = curveInfo->pLen;
   tag.value = p;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ECPrivateKey structure
   n = tag.totalLength;
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The public key is optional
   if(publicKey != NULL)
   {
      //Format PublicKey field
      error = pkcs8FormatEcPublicKey(curveInfo, publicKey, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Update the length of the ECPrivateKey structure
      length += n;

      //Advance data pointer
      if(output != NULL)
         p += n;
   }

   //Format ECPrivateKey field
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

   //Get the length of the ECPrivateKey structure
   n = tag.totalLength;

   //The PrivateKey field is an octet string whose contents are the value
   //of the private key
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;
   tag.value = output;

   //Write the corresponding ASN.1 tag
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
 * @brief Format an EC public key
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] publicKey EC public key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs8FormatEcPublicKey(const EcCurveInfo *curveInfo,
   const EcPublicKey *publicKey, uint8_t *output, size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EcDomainParameters params;
   Asn1Tag tag;

   //Initialize EC domain parameters
   ecInitDomainParameters(&params);

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   output[0] = 0;

   //Load EC domain parameters
   error = ecLoadDomainParameters(&params, curveInfo);

   //Check status code
   if(!error)
   {
      //Format ECPublicKey structure
      error = ecExport(&params, &publicKey->q, output + 1, &n);
   }

   //Check status code
   if(!error)
   {
      //The public key is encapsulated within a bit string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_BIT_STRING;
      tag.length = n + 1;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
   }

   //Check status code
   if(!error)
   {
      //Explicit tagging shall be used to encode the public key
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 1;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, written);
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
 * @brief Format an EdDSA private key
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] privateKey EdDSA private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs8FormatEddsaPrivateKey(const EcCurveInfo *curveInfo,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 curve identifier?
   if(!oidComp(curveInfo->oid, curveInfo->oidSize, ED25519_OID,
      sizeof(ED25519_OID)))
   {
      //Export the EdDSA private key to ASN.1 format
      error = x509ExportEddsaPrivateKey(privateKey, ED25519_PRIVATE_KEY_LEN,
         output, &n);
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 curve identifier?
   if(!oidComp(curveInfo->oid, curveInfo->oidSize, ED448_OID,
      sizeof(ED448_OID)))
   {
      //Export the EdDSA private key to ASN.1 format
      error = x509ExportEddsaPrivateKey(privateKey, ED448_PRIVATE_KEY_LEN,
         output, &n);
   }
   else
#endif
   //Unknown curve identifier?
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Any error to report?
   if(error)
      return error;

   //The CurvePrivateKey structure is encapsulated within an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;
   tag.value = output;

   //Write PrivateKey structure
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
