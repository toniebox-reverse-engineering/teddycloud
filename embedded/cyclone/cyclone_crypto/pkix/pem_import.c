/**
 * @file pem_import.c
 * @brief PEM file import functions
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
#include "pkix/pem_import.h"
#include "pkix/pkcs8_key_parse.h"
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "encoding/base64.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Decode a PEM file containing a certificate
 * @param[in] input Pointer to the PEM encoding
 * @param[in] inputLen Length of the PEM structure
 * @param[out] output Pointer to the DER-encoded certificate
 * @param[out] outputLen Length of the DER-encoded certificate, in bytes
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 * @return Error code
 **/

error_t pemImportCertificate(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen, size_t *consumed)
{
   error_t error;

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;
   if(outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //X.509 certificates are encoded using the "CERTIFICATE" label
   error = pemDecodeFile(input, inputLen, "CERTIFICATE", output, outputLen,
      consumed);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing a certificate revocation list
 * @param[in] input Pointer to the PEM encoding
 * @param[in] inputLen Length of the PEM structure
 * @param[out] output Pointer to the DER-encoded CRL
 * @param[out] outputLen Length of the DER-encoded CRL, in bytes
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 * @return Error code
 **/

error_t pemImportCrl(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen, size_t *consumed)
{
   error_t error;

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;
   if(outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //CRLs are encoded using the "X509 CRL" label
   error = pemDecodeFile(input, inputLen, "X509 CRL", output, outputLen,
      consumed);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing a certification signing request
 * @param[in] input Pointer to the PEM encoding
 * @param[in] inputLen Length of the PEM structure
 * @param[out] output Pointer to the DER-encoded CSR
 * @param[out] outputLen Length of the DER-encoded CSR, in bytes
 * @return Error code
 **/

error_t pemImportCsr(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;
   if(outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //CSRs are encoded using the "CERTIFICATE REQUEST" label
   error = pemDecodeFile(input, inputLen, "CERTIFICATE REQUEST", output,
      outputLen, NULL);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing Diffie-Hellman parameters
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] params Diffie-Hellman parameters resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDhParameters(const char_t *input, size_t length,
   DhParameters *params)
{
#if (DH_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   const uint8_t *p;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   p = NULL;
   n = 0;

   //Diffie-Hellman parameters are encoded using the "DH PARAMETERS" label
   error = pemDecodeFile(input, length, "DH PARAMETERS", NULL, &n, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "DH PARAMETERS", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The Diffie-Hellman parameters are encapsulated within a sequence
            error = asn1ReadSequence(buffer, n, &tag);
         }

         //Check status code
         if(!error)
         {
            //Point to the first field of the sequence
            p = tag.value;
            n = tag.length;

            //Read the prime modulus
            error = asn1ReadMpi(p, n, &tag, &params->p);
         }

         //Check status code
         if(!error)
         {
            //Point to the next field
            p += tag.totalLength;
            n -= tag.totalLength;

            //Read the generator
            error = asn1ReadMpi(p, n, &tag, &params->g);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("Diffie-Hellman parameters:\r\n");
            TRACE_DEBUG("  Prime modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &params->p);
            TRACE_DEBUG("  Generator:\r\n");
            TRACE_DEBUG_MPI("    ", &params->g);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      mpiFree(&params->p);
      mpiFree(&params->g);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an RSA public key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] publicKey RSA public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportRsaPublicKey(const char_t *input, size_t length,
   RsaPublicKey *publicKey)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "RSA PUBLIC KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "RSA PUBLIC KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Read RSAPublicKey structure
            error = x509ParseRsaPublicKey(buffer, n, &publicKeyInfo.rsaPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Set public key algorithm identifier
            publicKeyInfo.oid = RSA_ENCRYPTION_OID;
            publicKeyInfo.oidLen = sizeof(RSA_ENCRYPTION_OID);

            //Import the RSA public key
            error = x509ImportRsaPublicKey(&publicKeyInfo, publicKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the RSA public key
            error = x509ImportRsaPublicKey(&publicKeyInfo, publicKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid RSA public key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an RSA private key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] privateKey RSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportRsaPrivateKey(const char_t *input, size_t length,
   RsaPrivateKey *privateKey)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "RSA PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "RSA PRIVATE KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Read RSAPrivateKey structure
            error = pkcs8ParseRsaPrivateKey(buffer, n,
               &privateKeyInfo.rsaPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Set private key algorithm identifier
            privateKeyInfo.oid = RSA_ENCRYPTION_OID;
            privateKeyInfo.oidLen = sizeof(RSA_ENCRYPTION_OID);

            //Import the RSA private key
            error = pkcs8ImportRsaPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the RSA private key
            error = pkcs8ImportRsaPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid RSA private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a DSA public key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] publicKey DSA public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDsaPublicKey(const char_t *input, size_t length,
   DsaPublicKey *publicKey)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the DSA public key
            error = x509ImportDsaPublicKey(&publicKeyInfo, publicKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a DSA private key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] privateKey DSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDsaPrivateKey(const char_t *input, size_t length,
   DsaPrivateKey *privateKey)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "DSA PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "DSA PRIVATE KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Read DSAPrivateKey structure
            error = pkcs8ParseDsaPrivateKey(buffer, n, &privateKeyInfo.dsaParams,
               &privateKeyInfo.dsaPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Set private key algorithm identifier
            privateKeyInfo.oid = DSA_OID;
            privateKeyInfo.oidLen = sizeof(DSA_OID);

            //Import the DSA private key
            error = pkcs8ImportDsaPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the DSA private key
            error = pkcs8ImportDsaPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid DSA private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing EC domain parameters
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] params EC domain parameters
 * @return Error code
 **/

error_t pemImportEcParameters(const char_t *input, size_t length,
   EcDomainParameters *params)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "EC PARAMETERS", NULL, &n, NULL) == NO_ERROR)
   {
      X509EcParameters ecParams;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "EC PARAMETERS", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Parse ECParameters structure
            error = x509ParseEcParameters(buffer, n, &ecParams);
         }

         //Check status code
         if(!error)
         {
            //Import the EC domain parameters
            error = x509ImportEcParameters(&ecParams, params);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "EC PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      Pkcs8PrivateKeyInfo privateKeyInfo;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "EC PRIVATE KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Read ECPrivateKey structure
            error = pkcs8ParseEcPrivateKey(buffer, n, &privateKeyInfo.ecParams,
               &privateKeyInfo.ecPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Import the EC domain parameters
            error = x509ImportEcParameters(&privateKeyInfo.ecParams, params);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      Pkcs8PrivateKeyInfo privateKeyInfo;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC domain parameters
            error = x509ImportEcParameters(&privateKeyInfo.ecParams, params);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL) == NO_ERROR)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC domain parameters
            error = x509ImportEcParameters(&publicKeyInfo.ecParams, params);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain valid EC domain parameters
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreeDomainParameters(params);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an EC public key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] publicKey EC public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEcPublicKey(const char_t *input, size_t length,
   EcPublicKey *publicKey)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC public key
            error = x509ImportEcPublicKey(&publicKeyInfo, publicKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an EC private key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] privateKey EC private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEcPrivateKey(const char_t *input, size_t length,
   EcPrivateKey *privateKey)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "EC PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "EC PRIVATE KEY", buffer, &n,
            NULL);

         //Check status code
         if(!error)
         {
            //Read ECPrivateKey structure
            error = pkcs8ParseEcPrivateKey(buffer, n, &privateKeyInfo.ecParams,
               &privateKeyInfo.ecPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Set public key algorithm identifier
            privateKeyInfo.oid = EC_PUBLIC_KEY_OID;
            privateKeyInfo.oidLen = sizeof(EC_PUBLIC_KEY_OID);

            //Import the EC private key
            error = pkcs8ImportEcPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC private key
            error = pkcs8ImportEcPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid EC private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a EdDSA public key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] publicKey EdDSA public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEddsaPublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EdDSA public key
            error = x509ImportEddsaPublicKey(&publicKeyInfo, publicKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a EdDSA private key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] privateKey EdDSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEddsaPrivateKey(const char_t *input, size_t length,
   EddsaPrivateKey *privateKey)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EdDSA private key
            error = pkcs8ImportEddsaPrivateKey(&privateKeyInfo, privateKey);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Retrieve the type of a PEM-encoded public key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] keyType Public key type
 * @return Error code
 **/

error_t pemGetPublicKeyType(const char_t *input, size_t length,
   X509KeyType *keyType)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(keyType == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Default public key type
   *keyType = X509_KEY_TYPE_UNKNOWN;

#if (RSA_SUPPORT == ENABLED)
   //PEM container with "RSA PUBLIC KEY" label?
   if(pemDecodeFile(input, length, "RSA PUBLIC KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //The PEM file contains an RSA public key (PKCS #1 format)
      *keyType = X509_KEY_TYPE_RSA;
   }
   else
#endif
   //PEM container with "PUBLIC KEY" label?
   if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Check public key algorithm identifier
            *keyType = x509GetPublicKeyType(publicKeyInfo.oid,
               publicKeyInfo.oidLen);

            //Unknown algorithm identifier?
            if(*keyType == X509_KEY_TYPE_UNKNOWN)
            {
               //Report an error
               error = ERROR_WRONG_IDENTIFIER;
            }
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid public key
      error = ERROR_END_OF_FILE;
   }

   //Return status code
   return error;
}


/**
 * @brief Retrieve the type of a PEM-encoded private key
 * @param[in] input Pointer to the PEM encoding
 * @param[in] length Length of the PEM encoding
 * @param[out] keyType Private key type
 * @return Error code
 **/

error_t pemGetPrivateKeyType(const char_t *input, size_t length,
   X509KeyType *keyType)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(keyType == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Default private key type
   *keyType = X509_KEY_TYPE_UNKNOWN;

#if (RSA_SUPPORT == ENABLED)
   //PEM container with "RSA PRIVATE KEY" label?
   if(pemDecodeFile(input, length, "RSA PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //The PEM file contains an RSA private key (PKCS #1 format)
      *keyType = X509_KEY_TYPE_RSA;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //PEM container with "DSA PRIVATE KEY" label?
   if(pemDecodeFile(input, length, "DSA PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //The PEM file contains a DSA private key
      *keyType = X509_KEY_TYPE_DSA;
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //PEM container with "EC PRIVATE KEY" label?
   if(pemDecodeFile(input, length, "EC PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //The PEM file contains an EC private key
      *keyType = X509_KEY_TYPE_EC;
   }
   else
#endif
   //PEM container with "PRIVATE KEY" label?
   if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Check private key algorithm identifier
            *keyType = x509GetPublicKeyType(privateKeyInfo.oid,
               privateKeyInfo.oidLen);

            //Unknown algorithm identifier?
            if(*keyType == X509_KEY_TYPE_UNKNOWN)
            {
               //Report an error
               error = ERROR_WRONG_IDENTIFIER;
            }
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Return status code
   return error;
}


/**
 * @brief Convert PEM container to ASN.1 format
 * @param[in] input PEM container to decode
 * @param[in] inputLen Length of the PEM container to decode
 * @param[in] label Label indicating the type of data
 * @param[out] output ASN.1 data (optional parameter)
 * @param[out] outputLen Length of the ASN.1 data
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 **/

error_t pemDecodeFile(const char_t *input, size_t inputLen, const char_t *label,
   uint8_t *output, size_t *outputLen, size_t *consumed)
{
   error_t error;
   int_t i;
   int_t j;

   //The PEM container begins with a "-----BEGIN " line
   i = pemFindTag(input, inputLen, "-----BEGIN ", label, "-----");
   //Encapsulation boundary not found?
   if(i < 0)
      return ERROR_END_OF_FILE;

   //Skip the encapsulation boundary
   i += osStrlen("-----BEGIN -----") + osStrlen(label);

   //The PEM container ends with a "-----END " line
   j = pemFindTag(input + i, inputLen - i, "-----END ", label, "-----");
   //Encapsulation boundary not found?
   if(j < 0)
      return ERROR_INVALID_SYNTAX;

   //The contents of the PEM file is Base64-encoded
   error = base64Decode(input + i, j, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting ASN.1 data without copying any data
   if(output != NULL)
   {
      //Display ASN.1 structure
      error = asn1DumpObject(output, *outputLen, 0);
      //Any error to report?
      if(error)
         return error;
   }

   //The last parameter is optional
   if(consumed != NULL)
   {
      //Total number of characters that have been consumed
      *consumed = i + j + osStrlen("-----END -----") + osStrlen(label);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search a string for a given tag
 * @param[in] input String to search
 * @param[in] inputLen Length of the string to search
 * @param[in] tag1 First part of the tag (NULL-terminated string)
 * @param[in] tag2 Second part of the tag (NULL-terminated string)
 * @param[in] tag3 Third part of the tag (NULL-terminated string)
 * @return The index of the first occurrence of the tag in the string,
 *   or -1 if the tag does not appear in the string
 **/

int_t pemFindTag(const char_t *input, size_t inputLen, const char_t *tag1,
   const char_t *tag2, const char_t *tag3)
{
   size_t i;
   size_t j;
   size_t n1;
   size_t n2;
   size_t n3;
   int_t index;

   //Initialize index
   index = -1;

   //Calculate the length of the tag
   n1 = osStrlen(tag1);
   n2 = osStrlen(tag2);
   n3 = osStrlen(tag3);

   //Parse input string
   for(i = 0; (i + n1 + n2 + n3) <= inputLen; i++)
   {
      //Compare current substring with the given tag
      for(j = 0; j < (n1 + n2 + n3); j++)
      {
         if(j < n1)
         {
            if(input[i + j] != tag1[j])
               break;
         }
         else if(j < (n1 + n2))
         {
            if(input[i + j] != tag2[j - n1])
               break;
         }
         else
         {
            if(input[i + j] != tag3[j - n1 - n2])
               break;
         }
      }

      //Check whether the tag has been found
      if(j == (n1 + n2 + n3))
      {
         index = i;
         break;
      }
   }

   //Return the index of the first occurrence of the tag in the string
   return index;
}

#endif
