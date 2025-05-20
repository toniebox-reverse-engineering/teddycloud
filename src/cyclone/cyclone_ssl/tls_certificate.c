/**
 * @file tls_certificate.c
 * @brief X.509 certificate handling
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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
 * @version 2.4.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_certificate.h"
#include "tls_sign_misc.h"
#include "tls_misc.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_validate.h"
#include "pkix/x509_key_parse.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Format certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the certificate chain
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCertificateList(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t m;
   size_t n;
   size_t certChainLen;
   const char_t *certChain;

   //Initialize status code
   error = NO_ERROR;

   //Length of the certificate list in bytes
   *written = 0;

   //Check whether a certificate is available
   if(context->cert != NULL)
   {
      //Point to the certificate chain
      certChain = context->cert->certChain;
      //Get the total length, in bytes, of the certificate chain
      certChainLen = context->cert->certChainLen;
   }
   else
   {
      //If no suitable certificate is available, the message contains an
      //empty certificate list
      certChain = NULL;
      certChainLen = 0;
   }

   //Parse the certificate chain
   while(certChainLen > 0)
   {
      //The first pass calculates the length of the DER-encoded certificate
      error = pemImportCertificate(certChain, certChainLen, NULL, &n, NULL);

      //End of file detected?
      if(error)
      {
         //Exit immediately
         error = NO_ERROR;
         break;
      }

      //Buffer overflow?
      if((*written + n + 3) > context->txBufferMaxLen)
      {
         //Report an error
         error = ERROR_MESSAGE_TOO_LONG;
         break;
      }

      //Each certificate is preceded by a 3-byte length field
      STORE24BE(n, p);

      //The second pass decodes the PEM certificate
      error = pemImportCertificate(certChain, certChainLen, p + 3, &n, &m);
      //Any error to report?
      if(error)
         break;

      //Advance read pointer
      certChain += m;
      certChainLen -= m;

      //Advance write pointer
      p += n + 3;
      *written += n + 3;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
      {
         //Format the list of extensions for the current CertificateEntry
         error = tls13FormatCertExtensions(p, &n);
         //Any error to report?
         if(error)
            break;

         //Advance write pointer
         p += n;
         *written += n;
      }
#endif
   }

   //Return status code
   return error;
}


/**
 * @brief Format raw public key
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the raw public key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatRawPublicKey(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Length of the certificate list in bytes
   *written = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check whether a certificate is available
   if(context->cert != NULL)
   {
      size_t n;
      uint8_t *derCert;
      size_t derCertLen;
      X509CertInfo *certInfo;

      //Initialize variables
      derCert = NULL;
      certInfo = NULL;

      //Start of exception handling block
      do
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(context->cert->certChain,
            context->cert->certChainLen, NULL, &derCertLen, NULL);
         //Any error to report?
         if(error)
            break;

         //Allocate a memory buffer to hold the DER-encoded certificate
         derCert = tlsAllocMem(derCertLen);
         //Failed to allocate memory?
         if(derCert == NULL)
         {
            error = ERROR_OUT_OF_MEMORY;
            break;
         }

         //The second pass decodes the PEM certificate
         error = pemImportCertificate(context->cert->certChain,
            context->cert->certChainLen, derCert, &derCertLen, NULL);
         //Any error to report?
         if(error)
            break;

         //Allocate a memory buffer to store X.509 certificate info
         certInfo = tlsAllocMem(sizeof(X509CertInfo));
         //Failed to allocate memory?
         if(certInfo == NULL)
         {
            error = ERROR_OUT_OF_MEMORY;
            break;
         }

         //Parse X.509 certificate
         error = x509ParseCertificate(derCert, derCertLen, certInfo);
         //Failed to parse the X.509 certificate?
         if(error)
            break;

         //Retrieve the length of the raw public key
         n = certInfo->tbsCert.subjectPublicKeyInfo.raw.length;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //TLS 1.3 currently selected?
         if(context->version == TLS_VERSION_1_3)
         {
            //The raw public key is preceded by a 3-byte length field
            STORE24BE(n, p);
            //Copy the raw public key
            osMemcpy(p + 3, certInfo->tbsCert.subjectPublicKeyInfo.raw.value, n);

            //Advance data pointer
            p += n + 3;
            //Adjust the length of the certificate list
            *written += n + 3;

            //Format the list of extensions for the current CertificateEntry
            error = tls13FormatCertExtensions(p, &n);
            //Any error to report?
            if(error)
               break;

            //Advance data pointer
            p += n;
            //Adjust the length of the certificate list
            *written += n;
         }
         else
#endif
         {
            //Copy the raw public key
            osMemcpy(p, certInfo->tbsCert.subjectPublicKeyInfo.raw.value, n);

            //Advance data pointer
            p += n;
            //Adjust the length of the certificate list
            *written += n;
         }

         //End of exception handling block
      } while(0);

      //Release previously allocated memory
      tlsFreeMem(derCert);
      tlsFreeMem(certInfo);
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the certificate chain
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

__weak_func error_t tlsParseCertificateList_override(TlsContext *context,
   const uint8_t *p, size_t length)
{
   error_t error;
   error_t certValidResult;
   uint_t i;
   size_t n;
   const char_t *subjectName;
   X509CertInfo *certInfo;
   X509CertInfo *issuerCertInfo;

   //Initialize X.509 certificates
   certInfo = NULL;
   issuerCertInfo = NULL;

   //Start of exception handling block
   do
   {
      //Allocate a memory buffer to store X.509 certificate info
      certInfo = tlsAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Allocate a memory buffer to store the parent certificate
      issuerCertInfo = tlsAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(issuerCertInfo == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //The end-user certificate is preceded by a 3-byte length field
      if(length < 3)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Get the size occupied by the certificate
      n = LOAD24BE(p);
      //Jump to the beginning of the DER-encoded certificate
      p += 3;
      length -= 3;

      //Malformed Certificate message?
      if(n == 0 || n > length)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Display ASN.1 structure
      error = asn1DumpObject(p, n, 0);
      //Any error to report?
      if(error)
         break;

      //Parse end-user certificate
      error = x509ParseCertificate(p, n, certInfo);
      //Failed to parse the X.509 certificate?
      if(error)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Check certificate key usage
      error = tlsCheckKeyUsage(certInfo, context->entity,
         context->keyExchMethod);
      //Any error to report?
      if(error)
         break;

      //Extract the public key from the end-user certificate
      error = tlsReadSubjectPublicKey(context,
         &certInfo->tbsCert.subjectPublicKeyInfo);
      //Any error to report?
      if(error)
         break;

#if (TLS_CLIENT_SUPPORT == ENABLED)
      //Client mode?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         TlsCertificateType certType;
         TlsNamedGroup namedCurve;

         //Retrieve the type of the X.509 certificate
         error = tlsGetCertificateType(certInfo, &certType, &namedCurve);
         //Unsupported certificate?
         if(error)
            break;

         //Version of TLS prior to TLS 1.3?
         if(context->version <= TLS_VERSION_1_2)
         {
            //ECDSA certificate?
            if(certType == TLS_CERT_ECDSA_SIGN)
            {
               //Make sure the elliptic curve is supported
               if(tlsGetCurveInfo(context, namedCurve) == NULL)
               {
                  error = ERROR_BAD_CERTIFICATE;
                  break;
               }
            }
         }

         //Point to the subject name
         subjectName = context->serverName;

         //Check the subject name in the server certificate against the actual
         //FQDN name that is being requested
         error = x509CheckSubjectName(certInfo, subjectName);
         //Any error to report?
         if(error)
         {
            //Debug message
            TRACE_WARNING("Server name mismatch!\r\n");

            //Report an error
            error = ERROR_BAD_CERTIFICATE;
            break;
         }
      }
      else
#endif
      //Server mode?
      {
         //Do not check name constraints
         subjectName = NULL;
      }

      //Check if the end-user certificate can be matched with a trusted CA
      certValidResult = tlsValidateCertificate(context, certInfo, 0,
         subjectName);

      //Check validation result
      if(certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
      {
         //The certificate is not valid
         error = certValidResult;
         break;
      }

      //Next certificate
      p += n;
      length -= n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
      {
         //Parse the list of extensions for the current CertificateEntry
         error = tls13ParseCertExtensions(p, length, &n);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         p += n;
         //Remaining bytes to process
         length -= n;
      }
#endif

      //PKIX path validation
      for(i = 0; length > 0; i++)
      {
         //Each intermediate certificate is preceded by a 3-byte length field
         if(length < 3)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Get the size occupied by the certificate
         n = LOAD24BE(p);
         //Jump to the beginning of the DER-encoded certificate
         p += 3;
         //Remaining bytes to process
         length -= 3;

         //Malformed Certificate message?
         if(n == 0 || n > length)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Display ASN.1 structure
         error = asn1DumpObject(p, n, 0);
         //Any error to report?
         if(error)
            break;

         //Parse intermediate certificate
         error = x509ParseCertificate(p, n, issuerCertInfo);
         //Failed to parse the X.509 certificate?
         if(error)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Certificate chain validation in progress?
         if(certValidResult == ERROR_UNKNOWN_CA)
         {
            //Validate current certificate
            error = x509ValidateCertificate(certInfo, issuerCertInfo, i);
            //Certificate validation failed?
            if(error)
               break;

            //Check name constraints
            error = x509CheckNameConstraints(subjectName, issuerCertInfo);
            //Should the application reject the certificate?
            if(error)
            {
               //Report an error
               error = ERROR_BAD_CERTIFICATE;
               break;
            }

            //Check the version of the certificate
            if(issuerCertInfo->tbsCert.version < X509_VERSION_3)
            {
               //Conforming implementations may choose to reject all version 1
               //and version 2 intermediate certificates (refer to RFC 5280,
               //section 6.1.4)
               error = ERROR_BAD_CERTIFICATE;
               break;
            }

            //Check if the intermediate certificate can be matched with a
            //trusted CA
            certValidResult = tlsValidateCertificate(context, issuerCertInfo,
               i, subjectName);

            //Check validation result
            if(certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
            {
               //The certificate is not valid
               error = certValidResult;
               break;
            }
         }

         //Keep track of the issuer certificate
         *certInfo = *issuerCertInfo;

         //Next certificate
         p += n;
         length -= n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //TLS 1.3 currently selected?
         if(context->version == TLS_VERSION_1_3)
         {
            //Parse the list of extensions for the current CertificateEntry
            error = tls13ParseCertExtensions(p, length, &n);
            //Any error to report?
            if(error)
               break;

            //Point to the next field
            p += n;
            //Remaining bytes to process
            length -= n;
         }
#endif
      }

      //Certificate chain validation failed?
      if(error == NO_ERROR && certValidResult != NO_ERROR)
      {
         //A valid certificate chain or partial chain was received, but the
         //certificate was not accepted because the CA certificate could not
         //be matched with a known, trusted CA
         error = ERROR_UNKNOWN_CA;
      }

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   tlsFreeMem(certInfo);
   tlsFreeMem(issuerCertInfo);

   //Return status code
   return error;
}


/**
 * @brief Parse raw public key
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the raw public key
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsParseRawPublicKey(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->rpkVerifyCallback != NULL)
   {
      size_t n;
      size_t rawPublicKeyLen;
      const uint8_t *rawPublicKey;
      X509SubjectPublicKeyInfo subjectPublicKeyInfo;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
      {
         //The raw public key is preceded by a 3-byte length field
         if(length < 3)
            return ERROR_DECODING_FAILED;

         //Get the size occupied by the raw public key
         rawPublicKeyLen = LOAD24BE(p);
         //Advance data pointer
         p += 3;
         //Remaining bytes to process
         length -= 3;

         //Malformed Certificate message?
         if(length < rawPublicKeyLen)
            return ERROR_DECODING_FAILED;
      }
      else
#endif
      {
         //The payload of the Certificate message contains a SubjectPublicKeyInfo
         //structure
         rawPublicKeyLen = length;
      }

      //Point to the raw public key
      rawPublicKey = p;

      //Decode the SubjectPublicKeyInfo structure
      error = x509ParseSubjectPublicKeyInfo(rawPublicKey, rawPublicKeyLen, &n,
         &subjectPublicKeyInfo);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += rawPublicKeyLen;
      //Remaining bytes to process
      length -= rawPublicKeyLen;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
      {
         //Parse the list of extensions for the current CertificateEntry
         error = tls13ParseCertExtensions(p, length, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;
      }
#endif

      //If the RawPublicKey certificate type was negotiated, the certificate
      //list must contain no more than one CertificateEntry (refer to RFC 8446,
      //section 4.4.2)
      if(length != 0)
         return ERROR_DECODING_FAILED;

      //Extract the public key from the SubjectPublicKeyInfo structure
      error = tlsReadSubjectPublicKey(context, &subjectPublicKeyInfo);
      //Any error to report?
      if(error)
         return error;

      //When raw public keys are used, authentication of the peer is supported
      //only through authentication of the received SubjectPublicKeyInfo via an
      //out-of-band method
      error = context->rpkVerifyCallback(context, rawPublicKey,
         rawPublicKeyLen);
   }
   else
#endif
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether a certificate is acceptable
 * @param[in] context Pointer to the TLS context
 * @param[in] cert End entity certificate
 * @param[in] certTypes List of supported certificate types
 * @param[in] numCertTypes Size of the list that contains the supported
 *   certificate types
 * @param[in] curveList List of supported elliptic curves
 * @param[in] certSignAlgoList List of signature algorithms that may be used
 *   in X.509 certificates
 * @param[in] certAuthorities List of trusted CA
 * @return TRUE if the specified certificate conforms to the requirements,
 *   else FALSE
 **/

bool_t tlsIsCertificateAcceptable(TlsContext *context,
   const TlsCertDesc *cert, const uint8_t *certTypes, size_t numCertTypes,
   const TlsSupportedGroupList *curveList,
   const TlsSignSchemeList *certSignAlgoList,
   const TlsCertAuthorities *certAuthorities)
{
   size_t i;
   size_t n;
   size_t length;
   bool_t acceptable;

   //Make sure that a valid certificate has been loaded
   if(cert->certChain == NULL || cert->certChainLen == 0)
      return FALSE;

   //This flag tells whether the certificate is acceptable
   acceptable = TRUE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Version of TLS prior to TLS 1.2?
   if(context->version <= TLS_VERSION_1_1)
   {
      //Server mode?
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         //The signing algorithm for the certificate must be the same as the
         //algorithm for the certificate key (refer to RFC 4346, section 7.4.2)
         if(cert->type == TLS_CERT_RSA_SIGN &&
            TLS_SIGN_ALGO(cert->signScheme) == TLS_SIGN_ALGO_RSA)
         {
            acceptable = TRUE;
         }
         else if(cert->type == TLS_CERT_DSS_SIGN &&
            TLS_SIGN_ALGO(cert->signScheme) == TLS_SIGN_ALGO_DSA)
         {
            acceptable = TRUE;
         }
         else if(cert->type == TLS_CERT_ECDSA_SIGN &&
            TLS_SIGN_ALGO(cert->signScheme) == TLS_SIGN_ALGO_ECDSA)
         {
            acceptable = TRUE;
         }
         else
         {
            acceptable = FALSE;
         }
      }
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Filter out certificates with unsupported type
      if(acceptable && certTypes != NULL)
      {
         //Loop through the list of supported certificate types
         for(i = 0, acceptable = FALSE; i < numCertTypes && !acceptable; i++)
         {
            //Check certificate type
            if(certTypes[i] == TLS_CERT_RSA_SIGN)
            {
               //The certificate must contain an RSA public key
               if(cert->type == TLS_CERT_RSA_SIGN ||
                  cert->type == TLS_CERT_RSA_PSS_SIGN)
               {
                  acceptable = TRUE;
               }
            }
            else if(certTypes[i] == TLS_CERT_DSS_SIGN)
            {
               //The certificate must contain a DSA public key
               if(cert->type == TLS_CERT_DSS_SIGN)
               {
                  acceptable = TRUE;
               }
            }
            else if(certTypes[i] == TLS_CERT_ECDSA_SIGN)
            {
               //The certificate must contain an ECDSA or EdDSA public key
               if(cert->type == TLS_CERT_ECDSA_SIGN ||
                  cert->type == TLS_CERT_ED25519_SIGN ||
                  cert->type == TLS_CERT_ED448_SIGN)
               {
                  acceptable = TRUE;
               }
            }
            else
            {
               //Unknown certificate type
            }
         }
      }

      //ECDSA certificate?
      if(cert->type == TLS_CERT_ECDSA_SIGN)
      {
         //In versions of TLS prior to TLS 1.3, the EllipticCurves extension is
         //used to negotiate ECDSA curves (refer to RFC 8446, section 4.2.7)
         if(acceptable && curveList != NULL)
         {
            //Retrieve the number of items in the list
            n = ntohs(curveList->length) / sizeof(uint16_t);

            //Loop through the list of supported elliptic curves
            for(i = 0, acceptable = FALSE; i < n && !acceptable; i++)
            {
               //Check whether the elliptic curve is supported
               if(ntohs(curveList->value[i]) == cert->namedCurve)
               {
                  acceptable = TRUE;
               }
            }
         }
      }
   }
#endif

#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
   //SM2 certificate?
   if(cert->type == TLS_CERT_SM2_SIGN)
   {
      //The signature algorithm used by the CA to sign the current certificate
      //must be sm2sig_sm3 (refer to RFC 8998, section 3.3.3)
      if(cert->signScheme != TLS_SIGN_SCHEME_SM2SIG_SM3)
      {
         acceptable = FALSE;
      }
   }
#endif

   //Filter out certificates that are signed with an unsupported algorithm
   if(acceptable && certSignAlgoList != NULL)
   {
      //Retrieve the number of items in the list
      n = ntohs(certSignAlgoList->length) / sizeof(uint16_t);

      //Loop through the list of supported signature algorithms
      for(i = 0, acceptable = FALSE; i < n && !acceptable; i++)
      {
         //The certificate must be signed using a valid algorithm
         if(ntohs(certSignAlgoList->value[i]) == cert->signScheme)
         {
            acceptable = TRUE;
         }
      }
   }

   //Filter out certificates that are issued by a non trusted CA
   if(acceptable && certAuthorities != NULL)
   {
      //Retrieve the length of the list
      length = ntohs(certAuthorities->length);

      //If the certificate authorities list is empty, then the client
      //may send any certificate of the appropriate type
      if(length > 0)
      {
         error_t error;
         size_t pemCertLen;
         const char_t *certChain;
         size_t certChainLen;
         uint8_t *derCert;
         size_t derCertLen;
         X509CertInfo *certInfo;

         //The list of acceptable certificate authorities describes the
         //known roots CA
         acceptable = FALSE;

         //Point to the end entity certificate
         certChain = cert->certChain;
         //Get the total length, in bytes, of the certificate chain
         certChainLen = cert->certChainLen;

         //Allocate a memory buffer to store X.509 certificate info
         certInfo = tlsAllocMem(sizeof(X509CertInfo));

         //Successful memory allocation?
         if(certInfo != NULL)
         {
            //Parse the certificate chain
            while(certChainLen > 0 && !acceptable)
            {
               //The first pass calculates the length of the DER-encoded
               //certificate
               error = pemImportCertificate(certChain, certChainLen, NULL,
                  &derCertLen, &pemCertLen);

               //Check status code
               if(!error)
               {
                  //Allocate a memory buffer to hold the DER-encoded certificate
                  derCert = tlsAllocMem(derCertLen);

                  //Successful memory allocation?
                  if(derCert != NULL)
                  {
                     //The second pass decodes the PEM certificate
                     error = pemImportCertificate(certChain, certChainLen,
                        derCert, &derCertLen, NULL);

                     //Check status code
                     if(!error)
                     {
                        //Parse X.509 certificate
                        error = x509ParseCertificate(derCert, derCertLen,
                           certInfo);
                     }

                     //Check status code
                     if(!error)
                     {
                        //Parse each distinguished name of the list
                        for(i = 0; i < length; i += n + 2)
                        {
                           //Sanity check
                           if((i + 2) > length)
                              break;

                           //Each distinguished name is preceded by a 2-byte
                           //length field
                           n = LOAD16BE(certAuthorities->value + i);

                           //Make sure the length field is valid
                           if((i + n + 2) > length)
                              break;

                           //Check if the distinguished name matches the root CA
                           if(x509CompareName(certAuthorities->value + i + 2, n,
                              certInfo->tbsCert.issuer.raw.value,
                              certInfo->tbsCert.issuer.raw.length))
                           {
                              acceptable = TRUE;
                              break;
                           }
                        }
                     }

                     //Free previously allocated memory
                     tlsFreeMem(derCert);
                  }

                  //Advance read pointer
                  certChain += pemCertLen;
                  certChainLen -= pemCertLen;
               }
               else
               {
                  //No more CA certificates in the list
                  break;
               }
            }

            //Free previously allocated memory
            tlsFreeMem(certInfo);
         }
      }
   }

   //The return value specifies whether all the criteria were matched
   return acceptable;
}


/**
 * @brief Verify certificate against root CAs
 * @param[in] context Pointer to the TLS context
 * @param[in] certInfo X.509 certificate to be verified
 * @param[in] pathLen Certificate path length
 * @param[in] subjectName Subject name (optional parameter)
 * @return Error code
 **/

error_t tlsValidateCertificate(TlsContext *context,
   const X509CertInfo *certInfo, uint_t pathLen, const char_t *subjectName)
{
   error_t error;
   size_t pemCertLen;
   const char_t *trustedCaList;
   size_t trustedCaListLen;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *caCertInfo;

   //Initialize status code
   error = ERROR_UNKNOWN_CA;

   //Any registered callback?
   if(context->certVerifyCallback != NULL)
   {
      //Invoke user callback function
      error = context->certVerifyCallback(context, certInfo, pathLen,
         context->certVerifyParam);
   }

   //Check status code
   if(error == NO_ERROR)
   {
      //The certificate is valid
   }
   else if(error == ERROR_UNKNOWN_CA)
   {
      //Check whether the certificate should be checked against root CAs
      if(context->trustedCaListLen > 0)
      {
         //Point to the first trusted CA certificate
         trustedCaList = context->trustedCaList;
         //Get the total length, in bytes, of the trusted CA list
         trustedCaListLen = context->trustedCaListLen;

         //Allocate a memory buffer to store X.509 certificate info
         caCertInfo = tlsAllocMem(sizeof(X509CertInfo));

         //Successful memory allocation?
         if(caCertInfo != NULL)
         {
            //Loop through the list of trusted CA certificates
            while(trustedCaListLen > 0 && error == ERROR_UNKNOWN_CA)
            {
               //The first pass calculates the length of the DER-encoded
               //certificate
               error = pemImportCertificate(trustedCaList, trustedCaListLen,
                  NULL, &derCertLen, &pemCertLen);

               //Check status code
               if(!error)
               {
                  //Allocate a memory buffer to hold the DER-encoded certificate
                  derCert = tlsAllocMem(derCertLen);

                  //Successful memory allocation?
                  if(derCert != NULL)
                  {
                     //The second pass decodes the PEM certificate
                     error = pemImportCertificate(trustedCaList,
                        trustedCaListLen, derCert, &derCertLen, NULL);

                     //Check status code
                     if(!error)
                     {
                        //Parse X.509 certificate
                        error = x509ParseCertificate(derCert, derCertLen,
                           caCertInfo);
                     }

                     //Check status code
                     if(!error)
                     {
                        //Validate the certificate with the current CA
                        error = x509ValidateCertificate(certInfo, caCertInfo,
                           pathLen);
                     }

                     //Check status code
                     if(!error)
                     {
                        //Check name constraints
                        error = x509CheckNameConstraints(subjectName, caCertInfo);
                     }

                     //Check status code
                     if(!error)
                     {
                        //The certificate is issued by a trusted CA
                        error = NO_ERROR;
                     }
                     else
                     {
                        //The certificate cannot be matched with the current CA
                        error = ERROR_UNKNOWN_CA;
                     }

                     //Free previously allocated memory
                     tlsFreeMem(derCert);
                  }
                  else
                  {
                     //Failed to allocate memory
                     error = ERROR_OUT_OF_MEMORY;
                  }

                  //Advance read pointer
                  trustedCaList += pemCertLen;
                  trustedCaListLen -= pemCertLen;
               }
               else
               {
                  //No more CA certificates in the list
                  trustedCaListLen = 0;
                  error = ERROR_UNKNOWN_CA;
               }
            }

            //Free previously allocated memory
            tlsFreeMem(caCertInfo);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else
      {
         //Do not check the certificate against root CAs
         error = NO_ERROR;
      }
   }
   else if(error == ERROR_BAD_CERTIFICATE ||
      error == ERROR_UNSUPPORTED_CERTIFICATE ||
      error == ERROR_UNKNOWN_CERTIFICATE ||
      error == ERROR_CERTIFICATE_REVOKED ||
      error == ERROR_CERTIFICATE_EXPIRED ||
      error == ERROR_HANDSHAKE_FAILED)
   {
      //The certificate is not valid
   }
   else
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Retrieve the certificate type
 * @param[in] certInfo X.509 certificate
 * @param[out] certType Certificate type
 * @param[out] namedCurve Elliptic curve (only for ECDSA certificates)
 * @return Error code
 **/

error_t tlsGetCertificateType(const X509CertInfo *certInfo,
   TlsCertificateType *certType, TlsNamedGroup *namedCurve)
{
   size_t oidLen;
   const uint8_t *oid;

   //Check parameters
   if(certInfo == NULL || certType == NULL || namedCurve == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the public key identifier
   oid = certInfo->tbsCert.subjectPublicKeyInfo.oid.value;
   oidLen = certInfo->tbsCert.subjectPublicKeyInfo.oid.length;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_RSA_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA-PSS public key?
   if(!oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_RSA_PSS_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA public key?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_DSS_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_SM2_SIGN_SUPPORT == ENABLED)
   //EC public key?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      const X509EcParameters *params;

      //Point to the EC parameters
      params = &certInfo->tbsCert.subjectPublicKeyInfo.ecParams;

      //SM2 elliptic curve?
      if(!oidComp(params->namedCurve.value, params->namedCurve.length,
         SM2_OID, sizeof(SM2_OID)))
      {
         //Save certificate type
         *certType = TLS_CERT_SM2_SIGN;

         //The only valid elliptic curve for the SM2 signature algorithm is
         //curveSM2 (refer to RFC 8446, section 3.2.1)
         *namedCurve = TLS_GROUP_CURVE_SM2;
      }
      else
      {
         //Save certificate type
         *certType = TLS_CERT_ECDSA_SIGN;

         //Retrieve the named curve that has been used to generate the EC
         //public key
         *namedCurve = tlsGetNamedCurve(params->namedCurve.value,
            params->namedCurve.length);
      }
   }
   else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 public key?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_ED25519_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 public key?
   if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_ED448_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      return ERROR_BAD_CERTIFICATE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve the signature algorithm used to sign the certificate
 * @param[in] certInfo X.509 certificate
 * @param[out] signScheme Signature scheme
 * @return Error code
 **/

error_t tlsGetCertificateSignAlgo(const X509CertInfo *certInfo,
   TlsSignatureScheme *signScheme)
{
   size_t oidLen;
   const uint8_t *oid;

   //Check parameters
   if(certInfo == NULL || signScheme == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the signature algorithm
   oid = certInfo->signatureAlgo.oid.value;
   oidLen = certInfo->signatureAlgo.oid.length;

#if (RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(!oidComp(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID,
      sizeof(MD5_WITH_RSA_ENCRYPTION_OID)))
   {
      //RSA with MD5 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_MD5);
   }
   else if(!oidComp(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA1_WITH_RSA_ENCRYPTION_OID)))
   {
      //RSA with SHA-1 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_SHA1);
   }
   else if(!oidComp(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA256_WITH_RSA_ENCRYPTION_OID)))
   {
      //RSA with SHA-256 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_SHA256);
   }
   else if(!oidComp(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA384_WITH_RSA_ENCRYPTION_OID)))
   {
      //RSA with SHA-384 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_SHA384);
   }
   else if(!oidComp(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA512_WITH_RSA_ENCRYPTION_OID)))
   {
      //RSA with SHA-512 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_SHA512);
   }
   else
#endif
#if (RSA_SUPPORT == ENABLED && X509_RSA_PSS_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm?
   if(!oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Get the OID of the hash algorithm
      oid = certInfo->signatureAlgo.rsaPssParams.hashAlgo.value;
      oidLen = certInfo->signatureAlgo.rsaPssParams.hashAlgo.length;

#if (SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA256_OID, sizeof(SHA256_OID)))
      {
         //RSA-PSS with SHA-256 signature algorithm
         *signScheme = TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256;
      }
      else
#endif
#if (SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA384_OID, sizeof(SHA384_OID)))
      {
         //RSA-PSS with SHA-384 signature algorithm
         *signScheme = TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384;
      }
      else
#endif
#if (SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA512_OID, sizeof(SHA512_OID)))
      {
         //RSA-PSS with SHA-512 signature algorithm
         *signScheme = TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512;
      }
      else
#endif
      //Unknown hash algorithm identifier?
      {
         //The signature algorithm is not supported
         return ERROR_BAD_CERTIFICATE;
      }
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA1_OID,
      sizeof(DSA_WITH_SHA1_OID)))
   {
      //DSA with SHA-1 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA1);
   }
   else if(!oidComp(oid, oidLen, DSA_WITH_SHA224_OID,
      sizeof(DSA_WITH_SHA224_OID)))
   {
      //DSA with SHA-224 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA224);
   }
   else if(!oidComp(oid, oidLen, DSA_WITH_SHA256_OID,
      sizeof(DSA_WITH_SHA256_OID)))
   {
      //DSA with SHA-256 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA256);
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA1_OID,
      sizeof(ECDSA_WITH_SHA1_OID)))
   {
      //ECDSA with SHA-1 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA1);
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA224_OID,
      sizeof(ECDSA_WITH_SHA224_OID)))
   {
      //ECDSA with SHA-224 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA224);
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA256_OID,
      sizeof(ECDSA_WITH_SHA256_OID)))
   {
      //ECDSA with SHA-256 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA256);
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA384_OID,
      sizeof(ECDSA_WITH_SHA384_OID)))
   {
      //ECDSA with SHA-384 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA384);
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA512_OID,
      sizeof(ECDSA_WITH_SHA512_OID)))
   {
      //ECDSA with SHA-512 signature algorithm
      *signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA512);
   }
   else
#endif
#if (SM2_SUPPORT == ENABLED)
   //SM2 signature algorithm?
   if(!oidComp(oid, oidLen, SM2_WITH_SM3_OID, sizeof(SM2_WITH_SM3_OID)))
   {
      //SM2 with SM3 signature algorithm
      *signScheme = TLS_SIGN_SCHEME_SM2SIG_SM3;
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Ed25519 signature algorithm
      *signScheme = TLS_SIGN_SCHEME_ED25519;
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Ed448 signature algorithm
      *signScheme = TLS_SIGN_SCHEME_ED448;
   }
   else
#endif
   //Unknown signature algorithm?
   {
      //The signature algorithm is not supported
      return ERROR_BAD_CERTIFICATE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract the subject public key from the received certificate
 * @param[in] context Pointer to the TLS context
 * @param[in] subjectPublicKeyInfo Pointer to the subject's public key
 * @return Error code
 **/

error_t tlsReadSubjectPublicKey(TlsContext *context,
   const X509SubjectPublicKeyInfo *subjectPublicKeyInfo)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Retrieve public key identifier
   oid = subjectPublicKeyInfo->oid.value;
   oidLen = subjectPublicKeyInfo->oid.length;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) ||
      !oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      uint_t k;

      //Import the RSA public key
      error = x509ImportRsaPublicKey(subjectPublicKeyInfo,
         &context->peerRsaPublicKey);

      //Check status code
      if(!error)
      {
         //Get the length of the modulus, in bits
         k = mpiGetBitLength(&context->peerRsaPublicKey.n);

         //Applications should also enforce minimum and maximum key sizes (refer
         //to RFC 8446, appendix C.2)
         if(k < TLS_MIN_RSA_MODULUS_SIZE || k > TLS_MAX_RSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //RSA or RSA-PSS certificate?
         if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
         {
            //The certificate contains a valid RSA public key
            context->peerCertType = TLS_CERT_RSA_SIGN;
         }
         else if(!oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
         {
            //The certificate contains a valid RSA-PSS public key
            context->peerCertType = TLS_CERT_RSA_PSS_SIGN;
         }
         else
         {
            //Just for sanity
            error = ERROR_BAD_CERTIFICATE;
         }
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA public key?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      uint_t k;

      //Import the DSA public key
      error = x509ImportDsaPublicKey(subjectPublicKeyInfo,
         &context->peerDsaPublicKey);

      //Check status code
      if(!error)
      {
         //Get the length of the prime modulus, in bits
         k = mpiGetBitLength(&context->peerDsaPublicKey.params.p);

         //Make sure the prime modulus is acceptable
         if(k < TLS_MIN_DSA_MODULUS_SIZE || k > TLS_MAX_DSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //The certificate contains a valid DSA public key
         context->peerCertType = TLS_CERT_DSS_SIGN;
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_SM2_SIGN_SUPPORT == ENABLED)
   //EC public key?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      const EcCurveInfo *curveInfo;

      //Retrieve EC domain parameters
      curveInfo = x509GetCurveInfo(subjectPublicKeyInfo->ecParams.namedCurve.value,
         subjectPublicKeyInfo->ecParams.namedCurve.length);

      //Make sure the specified elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->peerEcParams, curveInfo);

         //Check status code
         if(!error)
         {
            //Retrieve the EC public key
            error = ecImport(&context->peerEcParams, &context->peerEcPublicKey.q,
               subjectPublicKeyInfo->ecPublicKey.q.value,
               subjectPublicKeyInfo->ecPublicKey.q.length);
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_BAD_CERTIFICATE;
      }

      //Check status code
      if(!error)
      {
         //SM2 elliptic curve?
         if(!oidComp(subjectPublicKeyInfo->ecParams.namedCurve.value,
            subjectPublicKeyInfo->ecParams.namedCurve.length, SM2_OID,
            sizeof(SM2_OID)))
         {
            //The certificate contains a valid SM2 public key
            context->peerCertType = TLS_CERT_SM2_SIGN;
         }
         else
         {
            //The certificate contains a valid EC public key
            context->peerCertType = TLS_CERT_ECDSA_SIGN;
         }
      }
   }
   else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED || TLS_ED448_SIGN_SUPPORT == ENABLED)
   //Ed25519 or Ed448 public key?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      const EcCurveInfo *curveInfo;

      //Retrieve EC domain parameters
      curveInfo = x509GetCurveInfo(oid, oidLen);

      //Make sure the specified elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->peerEcParams, curveInfo);

         //Check status code
         if(!error)
         {
            //Retrieve the EC public key
            error = ecImport(&context->peerEcParams, &context->peerEcPublicKey.q,
               subjectPublicKeyInfo->ecPublicKey.q.value,
               subjectPublicKeyInfo->ecPublicKey.q.length);
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_BAD_CERTIFICATE;
      }

      //Check status code
      if(!error)
      {
         //Ed25519 or Ed448 certificate?
         if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
         {
            //The certificate contains a valid Ed25519 public key
            context->peerCertType = TLS_CERT_ED25519_SIGN;
         }
         else if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
         {
            //The certificate contains a valid Ed448 public key
            context->peerCertType = TLS_CERT_ED448_SIGN;
         }
         else
         {
            //Just for sanity
            error = ERROR_BAD_CERTIFICATE;
         }
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      error = ERROR_UNSUPPORTED_CERTIFICATE;
   }

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Client mode?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Check key exchange method
         if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
         {
            //The client expects a valid RSA certificate whenever the agreed-
            //upon key exchange method uses RSA certificates for authentication
            if(context->peerCertType != TLS_CERT_RSA_SIGN &&
               context->peerCertType != TLS_CERT_RSA_PSS_SIGN)
            {
               error = ERROR_UNSUPPORTED_CERTIFICATE;
            }
         }
         else if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
         {
            //The client expects a valid DSA certificate whenever the agreed-
            //upon key exchange method uses DSA certificates for authentication
            if(context->peerCertType != TLS_CERT_DSS_SIGN)
            {
               error = ERROR_UNSUPPORTED_CERTIFICATE;
            }
         }
         else if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
         {
            //The client expects a valid ECDSA certificate whenever the agreed-
            //upon key exchange method uses ECDSA certificates for authentication
            if(context->peerCertType != TLS_CERT_ECDSA_SIGN &&
               context->peerCertType != TLS_CERT_ED25519_SIGN &&
               context->peerCertType != TLS_CERT_ED448_SIGN)
            {
               error = ERROR_UNSUPPORTED_CERTIFICATE;
            }
         }
         else if(context->keyExchMethod == TLS13_KEY_EXCH_DHE ||
            context->keyExchMethod == TLS13_KEY_EXCH_ECDHE ||
            context->keyExchMethod == TLS13_KEY_EXCH_HYBRID)
         {
            //TLS 1.3 removes support for DSA certificates
            if(context->peerCertType != TLS_CERT_RSA_SIGN &&
               context->peerCertType != TLS_CERT_RSA_PSS_SIGN &&
               context->peerCertType != TLS_CERT_ECDSA_SIGN &&
               context->peerCertType != TLS_CERT_SM2_SIGN &&
               context->peerCertType != TLS_CERT_ED25519_SIGN &&
               context->peerCertType != TLS_CERT_ED448_SIGN)
            {
               error = ERROR_UNSUPPORTED_CERTIFICATE;
            }
         }
         else
         {
            //Just for sanity
            error = ERROR_UNSUPPORTED_CERTIFICATE;
         }
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Check certificate key usage
 * @param[in] certInfo Pointer to the X.509 certificate
 * @param[in] entity Specifies whether this entity is considered a client or a server
 * @param[in] keyExchMethod TLS key exchange method
 * @return Error code
 **/

error_t tlsCheckKeyUsage(const X509CertInfo *certInfo,
   TlsConnectionEnd entity, TlsKeyExchMethod keyExchMethod)
{
#if (TLS_CERT_KEY_USAGE_SUPPORT == ENABLED)
   error_t error;
   const X509KeyUsage *keyUsage;
   const X509ExtendedKeyUsage *extKeyUsage;

   //Initialize status code
   error = NO_ERROR;

   //Point to the KeyUsage extension
   keyUsage = &certInfo->tbsCert.extensions.keyUsage;

   //Check if the KeyUsage extension is present
   if(keyUsage->bitmap != 0)
   {
      //Check whether TLS operates as a client or a server
      if(entity == TLS_CONNECTION_END_CLIENT)
      {
         //Check key exchange method
         if(keyExchMethod == TLS_KEY_EXCH_RSA ||
            keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
         {
            //The keyEncipherment bit must be asserted when the subject public
            //key is used for enciphering private or secret keys
            if((keyUsage->bitmap & X509_KEY_USAGE_KEY_ENCIPHERMENT) == 0)
            {
               error = ERROR_BAD_CERTIFICATE;
            }
         }
         else if(keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
            keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
            keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
            keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
            keyExchMethod == TLS13_KEY_EXCH_DHE ||
            keyExchMethod == TLS13_KEY_EXCH_ECDHE ||
            keyExchMethod == TLS13_KEY_EXCH_HYBRID)
         {
            //The digitalSignature bit must be asserted when the subject public
            //key is used for verifying digital signatures, other than signatures
            //on certificates and CRLs
            if((keyUsage->bitmap & X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0)
            {
               error = ERROR_BAD_CERTIFICATE;
            }
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //The digitalSignature bit must be asserted when the subject public
         //key is used for verifying digital signatures, other than signatures
         //on certificates and CRLs
         if((keyUsage->bitmap & X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0)
         {
            error = ERROR_BAD_CERTIFICATE;
         }
      }
   }

   //Point to the ExtendedKeyUsage extension
   extKeyUsage = &certInfo->tbsCert.extensions.extKeyUsage;

   //Check if the ExtendedKeyUsage extension is present
   if(extKeyUsage->bitmap != 0)
   {
      //Check whether TLS operates as a client or a server
      if(entity == TLS_CONNECTION_END_CLIENT)
      {
         //Make sure the certificate can be used for server authentication
         if((extKeyUsage->bitmap & X509_EXT_KEY_USAGE_SERVER_AUTH) == 0)
         {
            error = ERROR_BAD_CERTIFICATE;
         }
      }
      else
      {
         //Make sure the certificate can be used for client authentication
         if((extKeyUsage->bitmap & X509_EXT_KEY_USAGE_CLIENT_AUTH) == 0)
         {
            error = ERROR_BAD_CERTIFICATE;
         }
      }
   }

   //Return status code
   return error;
#else
   //Do not check key usage
   return NO_ERROR;
#endif
}

#endif
