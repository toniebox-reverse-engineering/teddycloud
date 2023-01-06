/**
 * @file x509_crl_validate.c
 * @brief CRL validation
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
#include "pkix/x509_crl_parse.h"
#include "pkix/x509_crl_validate.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_validate.h"
#include "pkix/x509_signature.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief CRL validation
 * @param[in] crlInfo Pointer to the CRL to be verified
 * @param[in] issuerCertInfo Issuer certificate
 * @return Error code
 **/

error_t x509ValidateCrl(const X509CrlInfo *crlInfo,
   const X509CertificateInfo *issuerCertInfo)
{
   error_t error;
   time_t currentTime;
   const X509Extensions *extensions;

   //Check parameters
   if(crlInfo == NULL || issuerCertInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      DateTime currentDate;

      //Convert Unix timestamp to date
      convertUnixTimeToDate(currentTime, &currentDate);

      //The thisUpdate field indicates the issue date of the CRL
      if(compareDateTime(&currentDate, &crlInfo->tbsCertList.thisUpdate) < 0)
      {
         //The CRL is not yet valid
         return ERROR_CERTIFICATE_EXPIRED;
      }

      //The nextUpdate field indicates the date by which the next CRL will
      //be issued
      if(compareDateTime(&currentDate, &crlInfo->tbsCertList.nextUpdate) > 0)
      {
         //The CRL has expired
         return ERROR_CERTIFICATE_EXPIRED;
      }
   }

   //Verify the issuer of the CRL
   if(!x509CompareName(crlInfo->tbsCertList.issuer.rawData,
      crlInfo->tbsCertList.issuer.rawDataLen,
      issuerCertInfo->tbsCert.subject.rawData,
      issuerCertInfo->tbsCert.subject.rawDataLen))
   {
      //Report an error
      return ERROR_BAD_CERTIFICATE;
   }

   //Point to the X.509 extensions of the issuer certificate
   extensions = &issuerCertInfo->tbsCert.extensions;

   //Check if the keyUsage extension is present
   if(extensions->keyUsage.bitmap != 0)
   {
      //If the keyUsage extension is present, then the subject public key
      //must not be used to verify signatures on CRLs unless the cRLSign bit
      //is set (refer to RFC 5280, section 4.2.1.3)
      if((extensions->keyUsage.bitmap & X509_KEY_USAGE_CRL_SIGN) == 0)
         return ERROR_BAD_CERTIFICATE;
   }

   //The ASN.1 DER-encoded TBSCertList is used as the input to the signature
   //function
   error = x509VerifySignature(crlInfo->tbsCertList.rawData,
      crlInfo->tbsCertList.rawDataLen, &crlInfo->signatureAlgo,
      &issuerCertInfo->tbsCert.subjectPublicKeyInfo, &crlInfo->signatureValue);

   //Return status code
   return error;
}


/**
 * @brief Check whether a certificate is revoked
 * @param[in] certInfo Pointer to the certificate to be verified
 * @param[in] crlInfo Pointer to the CRL
 * @return Error code
 **/

error_t x509CheckRevokedCertificate(const X509CertificateInfo *certInfo,
   const X509CrlInfo *crlInfo)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   const uint8_t *data;
   X509CertificateIssuer issuer;
   X509RevokedCertificate revokedCert;

   //Initialize status code
   error = NO_ERROR;

   //Initialize the certificate issuer
   osMemset(&issuer, 0, sizeof(X509CertificateIssuer));

   //If the CertificateIssuer extension is not present on the first entry in
   //an indirect CRL, the certificate issuer defaults to the CRL issuer
   issuer.numGeneralNames = 1;
   issuer.generalNames[0].type = X509_GENERAL_NAME_TYPE_DIRECTORY;
   issuer.generalNames[0].value = (char_t *) crlInfo->tbsCertList.issuer.rawData;
   issuer.generalNames[0].length = crlInfo->tbsCertList.issuer.rawDataLen;

   //Point to the first entry of the list
   data = crlInfo->tbsCertList.revokedCerts;
   length = crlInfo->tbsCertList.revokedCertsLen;

   //Loop through the list of revoked certificates
   while(length > 0)
   {
      //Parse current entry
      error = x509ParseRevokedCertificate(data, length, &n, &revokedCert);
      //Any error to report?
      if(error)
         break;

      //Indirect CRL?
      if(crlInfo->tbsCertList.crlExtensions.issuingDistrPoint.indirectCrl)
      {
         //Check whether the CertificateIssuer is present?
         if(revokedCert.crlEntryExtensions.certIssuer.numGeneralNames > 0)
         {
            //Save certificate issuer
            issuer = revokedCert.crlEntryExtensions.certIssuer;
         }
         else
         {
            //On subsequent entries in an indirect CRL, if this extension is not
            //present, the certificate issuer for the entry is the same as that
            //for the preceding entry (refer to RFC 5280, section 5.3.3)
         }
      }

      //Check whether the issuer of the certificate matches the current entry
      for(i = 0; i < issuer.numGeneralNames && i < X509_MAX_CERT_ISSUER_NAMES; i++)
      {
         //Distinguished name?
         if(issuer.generalNames[i].type == X509_GENERAL_NAME_TYPE_DIRECTORY)
         {
            //Compare distinguished names
            if(x509CompareName((uint8_t *) issuer.generalNames[i].value,
               issuer.generalNames[i].length, certInfo->tbsCert.issuer.rawData,
               certInfo->tbsCert.issuer.rawDataLen))
            {
               break;
            }
         }
      }

      //Matching certificate issuer?
      if(i < issuer.numGeneralNames && i < X509_MAX_CERT_ISSUER_NAMES)
      {
         //Check the length of the serial number
         if(certInfo->tbsCert.serialNumber.length == revokedCert.userCert.length)
         {
            //Compare serial numbers
            if(!osMemcmp(certInfo->tbsCert.serialNumber.data,
               revokedCert.userCert.data, revokedCert.userCert.length))
            {
               //The certificate has been revoked
               error = ERROR_CERTIFICATE_REVOKED;
               break;
            }
         }
      }

      //Next item
      data += n;
      length -= n;
   }

   //Return status code
   return error;
}

#endif
