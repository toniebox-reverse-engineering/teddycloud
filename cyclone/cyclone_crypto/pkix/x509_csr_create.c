/**
 * @file x509_csr_create.c
 * @brief CSR (Certificate Signing Request) generation
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
#include "pkix/x509_cert_create.h"
#include "pkix/x509_csr_create.h"
#include "pkix/x509_key_format.h"
#include "pkix/x509_signature.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Generate a CSR (Certificate Signing Request)
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] certReqInfo Certificate request information
 * @param[in] subjectPublicKey Pointer to the subject's public key
 * @param[in] signatureAlgo Signature algorithm
 * @param[in] signerPrivateKey Pointer to the subject's private key
 * @param[out] output Buffer where to store the CSR
 * @param[out] written Length of the resulting CSR
 * @return Error code
 **/

error_t x509CreateCsr(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertRequestInfo *certReqInfo, const void *subjectPublicKey,
   const X509SignatureAlgoId *signatureAlgo, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   uint8_t *input;
   size_t inputLen;
   Asn1Tag tag;

   //Check parameters
   if(certReqInfo == NULL || subjectPublicKey == NULL ||
      signatureAlgo == NULL || signerPrivateKey == NULL || written == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Point to the buffer where to write the CSR
   p = output;
   //Length of the CSR
   length = 0;

   //Format CertificationRequestInfo structure
   error = x509FormatCertRequestInfo(certReqInfo, subjectPublicKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //The ASN.1 DER-encoded CertificationRequestInfo is used as the input to
   //the signature function
   input = p;
   inputLen = n;

   //Advance data pointer
   p += n;
   length += n;

   //Format SignatureAlgorithm structure
   error = x509FormatSignatureAlgo(signatureAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format Signature structure
   error = x509FormatSignatureValue(prngAlgo, prngContext, input, inputLen,
      signatureAlgo, &certReqInfo->subjectPublicKeyInfo, signerPrivateKey,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The CSR is encapsulated within a sequence
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
 * @brief Format CertificationRequestInfo structure
 * @param[in] certReqInfo Certification request information
 * @param[in] publicKey Pointer to the subject's public key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatCertRequestInfo(const X509CertRequestInfo *certReqInfo,
   const void *publicKey, uint8_t *output, size_t *written)
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

   //Format Version field
   error = asn1WriteInt32(certReqInfo->version, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format Subject field
   error = x509FormatName(&certReqInfo->subject, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format SubjectPublicKeyInfo field
   error = x509FormatSubjectPublicKeyInfo(&certReqInfo->subjectPublicKeyInfo,
      publicKey, NULL, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format Attributes field
   error = x509FormatAttributes(&certReqInfo->attributes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The CertificationRequestInfo structure is encapsulated within a sequence
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
 * @brief Format CSR attributes
 * @param[in] attributes Pointer to the CSR attributes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatAttributes(const X509Attributes *attributes,
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

   //Format PKCS#9 Challenge Password attribute
   error = x509FormatChallengePassword(&attributes->challengePwd, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format PKCS#9 Extension Request attribute
   error = x509FormatExtensionRequest(&attributes->extensionReq, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Explicit tagging shall be used to encode the Extensions structure
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
   tag.objType = 0;
   tag.length = length;
   tag.value = output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &length);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ChallengePassword attribute
 * @param[in] challengePwd Value of the attribute
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatChallengePassword(const X509ChallengePassword *challengePwd,
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

   //Valid challenge password?
   if(challengePwd->value != NULL && challengePwd->length > 0)
   {
      //Format attribute identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_CHALLENGE_PASSWORD_OID);
      tag.value = X509_CHALLENGE_PASSWORD_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      length += n;

      //Format challenge password
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_UTF8_STRING;
      tag.length = challengePwd->length;
      tag.value = (uint8_t *) challengePwd->value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Attribute value is encapsulated within a set
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SET;
      tag.length = n;
      tag.value = p;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The attribute is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length + n;
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
 * @brief Format ExtensionRequest attribute
 * @param[in] extensionReq Value of the attribute
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatExtensionRequest(const X509Extensions *extensionReq,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t m;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format attribute identifier
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = sizeof(X509_EXTENSION_REQUEST_OID);
   tag.value = X509_EXTENSION_REQUEST_OID;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &m);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += m;

   //Format NetscapeCertType extension
   error = x509FormatNsCertType(&extensionReq->nsCertType, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format BasicConstraints extension
   error = x509FormatBasicConstraints(&extensionReq->basicConstraints,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format KeyUsage extension
   error = x509FormatKeyUsage(&extensionReq->keyUsage, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format SubjectAltName extension
   error = x509FormatSubjectAltName(&extensionReq->subjectAltName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format SubjectKeyIdentifier extension
   error = x509FormatSubjectKeyId(&extensionReq->subjectKeyId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format AuthorityKeyIdentifier extension
   error = x509FormatAuthorityKeyId(&extensionReq->authKeyId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Any extensions written?
   if(length > 0)
   {
      //Point to the first certificate extension
      p = output + m;

      //Certificate extensions are encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;
      tag.value = p;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &length);
      //Any error to report?
      if(error)
         return error;

      //Attribute value is encapsulated within a set
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SET;
      tag.length = length;
      tag.value = p;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &length);
      //Any error to report?
      if(error)
         return error;

      //The attribute is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length + m;
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

#endif
