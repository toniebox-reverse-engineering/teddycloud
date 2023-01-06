/**
 * @file x509_crl_parse.c
 * @brief CRL (Certificate Revocation List)
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
#include "pkix/x509_crl_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse a CRL (Certificate Revocation List)
 * @param[in] data Pointer to the CRL to parse
 * @param[in] length Length of the CRL
 * @param[out] crlInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrl(const uint8_t *data, size_t length,
   X509CrlInfo *crlInfo)
{
   error_t error;
   size_t totalLength;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Parsing X.509 CRL...\r\n");

   //Check parameters
   if(data == NULL || crlInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the CRL information structure
   osMemset(crlInfo, 0, sizeof(X509CrlInfo));

   //The CRL is encapsulated within a sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse TBSCertList structure
   error = x509ParseTbsCertList(data, length, &totalLength,
      &crlInfo->tbsCertList);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &totalLength,
      &crlInfo->signatureAlgo);
   //Any error to report?
   if(error)
      return error;

   //This field must contain the same algorithm identifier as the signature
   //field in the TBSCertList sequence (refer to RFC 5280, section 5.1.1.2)
   if(oidComp(crlInfo->signatureAlgo.oid, crlInfo->signatureAlgo.oidLen,
      crlInfo->tbsCertList.signatureAlgo.oid, crlInfo->tbsCertList.signatureAlgo.oidLen))
   {
      //Report an error
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureValue structure
   error = x509ParseSignatureValue(data, length, &totalLength,
      &crlInfo->signatureValue);
   //Any error to report?
   if(error)
      return error;

   //CRL successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse TBSCertList structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsCertList Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseTbsCertList(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing TBSCertList...\r\n");

   //Read the contents of the TBSCertList structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER-encoded TBSCertList is used as the input to the
   //signature function
   tbsCertList->rawData = data;
   tbsCertList->rawDataLen = tag.totalLength;

   //Point to the very first field of the TBSCertList
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = x509ParseCrlVersion(data, length, &n, &tbsCertList->version);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Signature field
   error = x509ParseSignatureAlgo(data, length, &n,
      &tbsCertList->signatureAlgo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Issuer field
   error = x509ParseName(data, length, &n, &tbsCertList->issuer);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse ThisUpdate field
   error = x509ParseTime(data, length, &n, &tbsCertList->thisUpdate);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse NextUpdate field
   error = x509ParseTime(data, length, &n, &tbsCertList->nextUpdate);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse RevokedCertificates field
   error = x509ParseRevokedCertificates(data, length, &n, tbsCertList);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse CrlExtensions field
   error = x509ParseCrlExtensions(data, length, &n, &tbsCertList->crlExtensions);
   //Any parsing error?
   if(error)
      return error;

   //The CrlExtensions field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 2
      if(tbsCertList->version < X509_VERSION_2)
         return ERROR_INVALID_VERSION;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse Version field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] version Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Version...\r\n");

   //The Version field is optional
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);

   //The tag does not match the criteria?
   if(error)
   {
      //Assume X.509 version 1 format
      *version = X509_VERSION_1;
      //Skip the current field
      *totalLength = 0;

      //Exit immediately
      return NO_ERROR;
   }

   //Parse Version field
   error = asn1ReadInt32(data, length, &tag, &value);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the version
   *version = (X509Version) value;
   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RevokedCertificates field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsCertList Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRevokedCertificates(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509RevokedCertificate revokedCertificate;

   //Debug message
   TRACE_DEBUG("    Parsing RevokedCertificates...\r\n");

   //The RevokedCertificates is optional
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);

   //The tag does not match the criteria?
   if(error)
   {
      //Skip the current field
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   tbsCertList->revokedCerts = tag.value;
   tbsCertList->revokedCertsLen = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Loop through the list of revoked certificates
   while(length > 0)
   {
      //Parse current item
      error = x509ParseRevokedCertificate(data, length, &n, &revokedCertificate);
      //Any error to report?
      if(error)
         return error;

      //Next item
      data += n;
      length -= n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RevokedCertificate field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] revokedCertificate Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRevokedCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509RevokedCertificate *revokedCertificate)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RevokedCertificate...\r\n");

   //Clear the RevokedCertificate structure
   osMemset(revokedCertificate, 0, sizeof(X509RevokedCertificate));

   //The RevokedCertificate structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Parse UserCertificate field
   error = x509ParseSerialNumber(data, length, &n,
      &revokedCertificate->userCert);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse RevocationDate field
   error = x509ParseTime(data, length, &n,
      &revokedCertificate->revocationDate);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse CrlEntryExtensions field
   error = x509ParseCrlEntryExtensions(data, length, &n,
      &revokedCertificate->crlEntryExtensions);
   //Any parsing error?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CRL extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] crlExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CrlExtensions *crlExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //No more data to process?
   if(length == 0)
   {
      //The CrlExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Explicit tagging is used to encode the CrlExtensions field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
   {
      //The CrlExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Debug message
   TRACE_DEBUG("    Parsing CrlExtensions...\r\n");

   //This field is a sequence of one or more CRL extensions
   error = asn1ReadSequence(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   crlExtensions->rawData = tag.value;
   crlExtensions->rawDataLen = tag.length;

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

      //CRLNumber extension found?
      if(!oidComp(extension.oid, extension.oidLen,
         X509_CRL_NUMBER_OID, sizeof(X509_CRL_NUMBER_OID)))
      {
         //Parse CRLNumber extension
         error = x509ParseCrlNumber(extension.critical, extension.value,
            extension.valueLen, &crlExtensions->crlNumber);
      }
      //DeltaCRLIndicator extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_DELTA_CRL_INDICATOR_OID, sizeof(X509_DELTA_CRL_INDICATOR_OID)))
      {
         //Parse DeltaCRLIndicator extension
         error = x509ParseDeltaCrlIndicator(extension.critical, extension.value,
            extension.valueLen, &crlExtensions->deltaCrlIndicator);
      }
      //IssuingDistributionPoint extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_ISSUING_DISTR_POINT_OID, sizeof(X509_ISSUING_DISTR_POINT_OID)))
      {
         //Parse IssuingDistributionPoint extension
         error = x509ParseIssuingDistrPoint(extension.critical, extension.value,
            extension.valueLen, &crlExtensions->issuingDistrPoint);
      }
      //AuthorityKeyIdentifier extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_AUTHORITY_KEY_ID_OID, sizeof(X509_AUTHORITY_KEY_ID_OID)))
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthorityKeyId(extension.critical, extension.value,
            extension.valueLen, &crlExtensions->authKeyId);
      }
      //Unknown extension?
      else
      {
         //Check if the extension is marked as critical
         if(extension.critical)
         {
            //If a CRL contains a critical extension that the application cannot
            //process, then the application must not use that CRL to determine
            //the status of certificates (refer to RFC 5280, section 5.2)
            error = ERROR_UNSUPPORTED_EXTENSION;
         }
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


/**
 * @brief Parse CRLNumber extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] crlNumber Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlNumber(bool_t critical, const uint8_t *data,
   size_t length, X509CrlNumber *crlNumber)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing CRLNumber...\r\n");

   //An CRL extension can be marked as critical
   crlNumber->critical = critical;

   //Read CRLNumber structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the CRL number
   crlNumber->value = tag.value;
   crlNumber->length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DeltaCRLIndicator extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] deltaCrlIndicator Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDeltaCrlIndicator(bool_t critical, const uint8_t *data,
   size_t length, X509DeltaCrlIndicator *deltaCrlIndicator)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing DeltaCRLIndicator...\r\n");

   //An CRL extension can be marked as critical
   deltaCrlIndicator->critical = critical;

   //Read BaseCRLNumber structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the CRL number
   deltaCrlIndicator->baseCrlNumber = tag.value;
   deltaCrlIndicator->baseCrlNumberLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse IssuingDistributionPoint extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] issuingDistrPoint Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseIssuingDistrPoint(bool_t critical, const uint8_t *data,
   size_t length, X509IssuingDistrPoint *issuingDistrPoint)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing IssuingDistributionPoint...\r\n");

   //An CRL extension can be marked as critical
   issuingDistrPoint->critical = critical;

   //The IssuingDistributionPoint extension is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first subfield of the sequence
   data = tag.value;
   length = tag.length;

   //The issuing distribution point is a critical CRL extension that identifies
   //the CRL distribution point and scope for a particular CRL, and it indicates
   //whether the CRL covers revocation for end entity certificates only, CA
   //certificates only, attribute certificates only, or a limited set of reason
   //codes
   while(length > 0)
   {
      //Read current subfield
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Explicit tagging shall be used to encode each subfield
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //Check subfield type
      if(tag.objType == 0)
      {
         //Parse distributionPoint subfield
      }
      else if(tag.objType == 1)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsUserCerts subfield
         issuingDistrPoint->onlyContainsUserCerts = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 2)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsCACerts subfield
         issuingDistrPoint->onlyContainsCaCerts = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 3)
      {
         //Parse onlySomeReasons subfield
      }
      else if(tag.objType == 4)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the indirectCRL subfield
         issuingDistrPoint->indirectCrl = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 5)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsAttributeCerts subfield
         issuingDistrPoint->onlyContainsAttributeCerts = tag.value[0] ? TRUE : FALSE;
      }
      else
      {
         //Discard unknown subfields
      }

      //Next subfield
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CRL entry extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] crlEntryExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlEntryExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CrlEntryExtensions *crlEntryExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //No more data to process?
   if(length == 0)
   {
      //The CrlEntryExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Debug message
   TRACE_DEBUG("    Parsing CrlEntryExtensions...\r\n");

   //This field is a sequence of one or more CRL entry extensions
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the CrlEntryExtensions field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   crlEntryExtensions->rawData = tag.value;
   crlEntryExtensions->rawDataLen = tag.length;

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

      //ReasonCode extension found?
      if(!oidComp(extension.oid, extension.oidLen,
         X509_REASON_CODE_OID, sizeof(X509_REASON_CODE_OID)))
      {
         //Parse ReasonCode extension
         error = x509ParseReasonCode(extension.critical, extension.value,
            extension.valueLen, &crlEntryExtensions->reasonCode);
      }
      //InvalidityDate extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_INVALIDITY_DATE_OID, sizeof(X509_INVALIDITY_DATE_OID)))
      {
         //Parse InvalidityDate extension
         error = x509ParseInvalidityDate(extension.critical, extension.value,
            extension.valueLen, &crlEntryExtensions->invalidityDate);
      }
      //CertificateIssuer extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_CERTIFICATE_ISSUER_OID, sizeof(X509_CERTIFICATE_ISSUER_OID)))
      {
         //Parse CertificateIssuer extension
         error = x509ParseCertificateIssuer(extension.critical, extension.value,
            extension.valueLen, &crlEntryExtensions->certIssuer);
      }
      //Unknown extension?
      else
      {
         //Check if the extension is marked as critical
         if(extension.critical)
         {
            //If a CRL contains a critical CRL entry extension that the
            //application cannot process, then the application must not use
            //that CRL to determine the status of any certificates
            error = ERROR_UNSUPPORTED_EXTENSION;
         }
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


/**
 * @brief Parse ReasonCode entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] reasonCode Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseReasonCode(bool_t critical, const uint8_t *data,
   size_t length, X509CrlReason *reasonCode)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ReasonCode...\r\n");

   //An CRL entry extension can be marked as critical
   reasonCode->critical = critical;

   //Read ReasonCode field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_ENUMERATED);
   //Invalid tag?
   if(error)
      return error;

   //Check the length of the field
   if(tag.length != 1)
      return ERROR_INVALID_SYNTAX;

   //The ReasonCode is a non-critical CRL entry extension that identifies
   //the reason for the certificate revocation
   reasonCode->value = tag.value[0];

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse InvalidityDate entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] invalidityDate Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseInvalidityDate(bool_t critical, const uint8_t *data,
   size_t length, X509InvalidityDate *invalidityDate)
{
   error_t error;
   size_t n;

   //Debug message
   TRACE_DEBUG("      Parsing InvalidityDate...\r\n");

   //An CRL entry extension can be marked as critical
   invalidityDate->critical = critical;

   //Read InvalidityDate field
   error = x509ParseTime(data, length, &n, &invalidityDate->value);

   //Return status code
   return error;
}


/**
 * @brief Parse CertificateIssuer entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certificateIssuer Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCertificateIssuer(bool_t critical, const uint8_t *data,
   size_t length, X509CertificateIssuer *certificateIssuer)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509GeneralName generalName;

   //Debug message
   TRACE_DEBUG("      Parsing CertificateIssuer...\r\n");

   //An CRL entry extension can be marked as critical
   certificateIssuer->critical = critical;

   //The CertificateIssuer structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   certificateIssuer->rawData = tag.value;
   certificateIssuer->rawDataLen = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //This CRL entry extension identifies the certificate issuer associated
   //with an entry in an indirect CRL, that is, a CRL that has the indirectCRL
   //indicator set in its issuing distribution point extension
   for(i = 0; length > 0; i++)
   {
      //Parse GeneralName field
      error = x509ParseGeneralName(data, length, &n, &generalName);
      //Any error to report?
      if(error)
         return error;

      //Sanity check
      if(i < X509_MAX_CERT_ISSUER_NAMES)
      {
         //Save issuer alternative name
         certificateIssuer->generalNames[i] = generalName;
      }

      //Next item
      data += n;
      length -= n;
   }

   //When present, the certificate issuer CRL entry extension includes one or
   //more names (refer to RFC 5280, section 5.3.3)
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of issuer alternative names
   certificateIssuer->numGeneralNames = MIN(i, X509_MAX_CERT_ISSUER_NAMES);

   //Successful processing
   return NO_ERROR;
}

#endif
