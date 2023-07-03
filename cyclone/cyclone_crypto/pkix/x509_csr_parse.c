/**
 * @file x509_csr_parse.c
 * @brief CSR (Certificate Signing Request) parsing
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
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_csr_parse.h"
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse a CSR (Certificate Signing Request)
 * @param[in] data Pointer to the CSR to parse
 * @param[in] length Length of the CSR
 * @param[out] csrInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCsr(const uint8_t *data, size_t length,
   X509CsrInfo *csrInfo)
{
   error_t error;
   size_t totalLength;
   X509Attributes *attributes;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Parsing X.509 CSR...\r\n");

   //Check parameters
   if(data == NULL || csrInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the CSR information structure
   osMemset(csrInfo, 0, sizeof(X509CsrInfo));

   //Point to the CSR attributes
   attributes = &csrInfo->certReqInfo.attributes;
   //Where pathLenConstraint does not appear, no limit is imposed
   attributes->extensionReq.basicConstraints.pathLenConstraint = -1;

   //The CSR is encapsulated within a sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse CertificationRequestInfo structure
   error = x509ParseCertRequestInfo(data, length, &totalLength,
      &csrInfo->certReqInfo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &totalLength,
      &csrInfo->signatureAlgo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse Signature structure
   error = x509ParseSignatureValue(data, length, &totalLength,
      &csrInfo->signatureValue);
   //Any error to report?
   if(error)
      return error;

   //CSR successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse CertificationRequestInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certReqInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCertRequestInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertRequestInfo *certReqInfo)
{
   error_t error;
   int32_t version;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing CertificationRequestInfo...\r\n");

   //Read the contents of the CertificationRequestInfo structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER-encoded CertificationRequestInfo is used as the input
   //to the signature function
   certReqInfo->rawData = data;
   certReqInfo->rawDataLen = tag.totalLength;

   //Point to the very first field of the CertificationRequestInfo
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = asn1ReadInt32(data, length, &tag, &version);
   //Any parsing error?
   if(error)
      return error;

   //Save version number
   certReqInfo->version = (X509Version) version;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse Subject field
   error = x509ParseName(data, length, &n, &certReqInfo->subject);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SubjectPublicKeyInfo field
   error = x509ParseSubjectPublicKeyInfo(data, length, &n,
      &certReqInfo->subjectPublicKeyInfo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Attributes field
   error = x509ParseAttributes(data, length, &n, &certReqInfo->attributes);
   //Any parsing error?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse CSR attributes
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] attributes Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, X509Attributes *attributes)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Attribute attribute;

   //Debug message
   TRACE_DEBUG("    Parsing Attributes...\r\n");

   //Explicit tagging is used to encode the Attributes field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
      return error;

   //This field is a collection of attributes providing additional information
   //about the subject of the certificate
   attributes->rawData = tag.value;
   attributes->rawDataLen = tag.length;

   //Point to the first item of the collection
   data = tag.value;
   length = tag.length;

   //Loop through the collection of attributes
   while(length > 0)
   {
      //Each item binds an attribute identifier to one or more attribute values
      error = x509ParseAttribute(data, length, &n, &attribute);
      //Any error to report?
      if(error)
         return error;

      //PKCS#9 Challenge Password attribute found?
      if(!oidComp(attribute.oid, attribute.oidLen,
         X509_CHALLENGE_PASSWORD_OID, sizeof(X509_CHALLENGE_PASSWORD_OID)))
      {
         //The interpretation of challenge passwords is intended to be specified
         //by certificate issuers
         error = x509ParseChallengePassword(attribute.value,
            attribute.valueLen, &attributes->challengePwd);
      }
      //PKCS#9 Extension Request attribute found?
      else if(!oidComp(attribute.oid, attribute.oidLen,
         X509_EXTENSION_REQUEST_OID, sizeof(X509_EXTENSION_REQUEST_OID)))
      {
         //This attribute may be used to carry information about certificate
         //extensions the requester wishes to be included in a certificate
         error = x509ParseExtensionRequest(attribute.value,
            attribute.valueLen, &attributes->extensionReq);
      }
      //Unknown attribute?
      else
      {
         //Discard current attribute
         error = NO_ERROR;
      }

      //Any parsing error?
      if(error)
         return error;

      //Next attribute
      data += n;
      length -= n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CSR attribute
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] attribute Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, X509Attribute *attribute)
{
   error_t error;
   Asn1Tag tag;

   //The attribute is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the attribute
   *totalLength = tag.totalLength;

   //Each item binds an attribute identifier to one or more attribute values
   data = tag.value;
   length = tag.length;

   //Read attribute identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the object identifier
   attribute->oid = tag.value;
   attribute->oidLen = tag.length;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Attribute values are encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Save the value of the attribute
   attribute->value = tag.value;
   attribute->valueLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ChallengePassword attribute
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] challengePwd Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseChallengePassword(const uint8_t *data, size_t length,
   X509ChallengePassword *challengePwd)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ChallengePassword...\r\n");

   //Read attribute value
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save challenge password
   challengePwd->value = (char_t *) tag.value;
   challengePwd->length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ExtensionRequest attribute
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] extensionReq Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtensionRequest(const uint8_t *data, size_t length,
   X509Extensions *extensionReq)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //Debug message
   TRACE_DEBUG("      Parsing ExtensionRequest...\r\n");

   //This field is a sequence of one or more certificate extensions
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   extensionReq->rawData = tag.value;
   extensionReq->rawDataLen = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Loop through the extensions
   while(length > 0)
   {
      //Each extension includes an OID and a value
      error = x509ParseExtension(data, length, &n, &extension);
      //Any error to report?
      if(error)
         return error;

      //BasicConstraints extension found?
      if(!oidComp(extension.oid, extension.oidLen,
         X509_BASIC_CONSTRAINTS_OID, sizeof(X509_BASIC_CONSTRAINTS_OID)))
      {
         //Parse BasicConstraints extension
         error = x509ParseBasicConstraints(extension.critical, extension.value,
            extension.valueLen, &extensionReq->basicConstraints);
      }
      //NameConstraints extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_NAME_CONSTRAINTS_OID, sizeof(X509_NAME_CONSTRAINTS_OID)))
      {
         //Parse NameConstraints extension
         error = x509ParseNameConstraints(extension.critical, extension.value,
            extension.valueLen, &extensionReq->nameConstraints);
      }
      //KeyUsage extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_KEY_USAGE_OID, sizeof(X509_KEY_USAGE_OID)))
      {
         //Parse KeyUsage extension
         error = x509ParseKeyUsage(extension.critical, extension.value,
            extension.valueLen, &extensionReq->keyUsage);
      }
      //ExtendedKeyUsage extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_EXTENDED_KEY_USAGE_OID, sizeof(X509_EXTENDED_KEY_USAGE_OID)))
      {
         //Parse ExtendedKeyUsage extension
         error = x509ParseExtendedKeyUsage(extension.critical, extension.value,
            extension.valueLen, &extensionReq->extKeyUsage);
      }
      //SubjectAltName extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_SUBJECT_ALT_NAME_OID, sizeof(X509_SUBJECT_ALT_NAME_OID)))
      {
         //Parse SubjectAltName extension
         error = x509ParseSubjectAltName(extension.critical, extension.value,
            extension.valueLen, &extensionReq->subjectAltName);
      }
      //SubjectKeyIdentifier extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_SUBJECT_KEY_ID_OID, sizeof(X509_SUBJECT_KEY_ID_OID)))
      {
         //Parse SubjectKeyIdentifier extension
         error = x509ParseSubjectKeyId(extension.critical, extension.value,
            extension.valueLen, &extensionReq->subjectKeyId);
      }
      //AuthorityKeyIdentifier extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_AUTHORITY_KEY_ID_OID, sizeof(X509_AUTHORITY_KEY_ID_OID)))
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthorityKeyId(extension.critical, extension.value,
            extension.valueLen, &extensionReq->authKeyId);
      }
      //NetscapeCertType extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_NS_CERT_TYPE_OID, sizeof(X509_NS_CERT_TYPE_OID)))
      {
         //Parse NetscapeCertType extension
         error = x509ParseNsCertType(extension.critical, extension.value,
            extension.valueLen, &extensionReq->nsCertType);
      }
      //Unknown extension?
      else
      {
         //Discard current extension
         error = NO_ERROR;
      }

      //Any parsing error?
      if(error)
         return error;

      //Next extension
      data += n;
      length -= n;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
