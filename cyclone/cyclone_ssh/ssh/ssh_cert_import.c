/**
 * @file ssh_cert_import.c
 * @brief SSH certificate import functions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_cert_import.h"
#include "ssh/ssh_misc.h"
#include "encoding/base64.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)


/**
 * @brief List of supported certificate types
 **/

static const char_t *const sshCertTypes[] =
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   "ssh-rsa-cert-v01@openssh.com",
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   "ssh-dss-cert-v01@openssh.com",
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP256_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp256-cert-v01@openssh.com",
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp384-cert-v01@openssh.com",
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp521-cert-v01@openssh.com",
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   "ssh-ed25519-cert-v01@openssh.com",
#endif
};


/**
 * @brief Import SSH certificate (OpenSSH format)
 * @param[in] input SSH certificate file to decode
 * @param[in] inputLen Length of the SSH certificate file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 * @return Error code
 **/

error_t sshImportCertificate(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   size_t i;
   size_t j;
   const char_t *certType;

   //Retrieve certificate type
   certType = sshGetCertType(input, inputLen);
   //Unrecognized certificate type?
   if(certType == NULL)
      return ERROR_INVALID_SYNTAX;

   //Get the length of the identifier string
   i = osStrlen(certType);

   //The identifier must be followed by a whitespace character
   if(input[i] != ' ' && input[i] != '\t')
      return ERROR_INVALID_SYNTAX;

   //Skip whitespace characters
   while(i < inputLen && (input[i] == ' ' || input[i] == '\t'))
   {
      i++;
   }

   //Point to the certificate
   j = i;

   //The certificate may be followed by a whitespace character and a comment
   while(j < inputLen && (input[j] != ' ' && input[j] != '\t'))
   {
      j++;
   }

   //The certificate is Base64-encoded
   error = base64Decode(input + i, j - i, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import an RSA public key from a certificate
 * @param[in] cert Pointer to the certificate structure
 * @param[out] publicKey Pointer to the RSA public key
 * @return Error code
 **/

error_t sshImportRsaCertPublicKey(const SshCertificate *cert,
   RsaPublicKey *publicKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;

   //Unexpected key format identifier?
   if(!sshCompareString(&cert->keyFormatId, "ssh-rsa-cert-v01@openssh.com"))
      return ERROR_WRONG_IDENTIFIER;

   //Import RSA public exponent
   error = mpiImport(&publicKey->e, cert->publicKey.rsaPublicKey.e.value,
      cert->publicKey.rsaPublicKey.e.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import RSA modulus
   error = mpiImport(&publicKey->n, cert->publicKey.rsaPublicKey.n.value,
      cert->publicKey.rsaPublicKey.n.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->n);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_RSA_MODULUS_SIZE || k > SSH_MAX_RSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a DSA public key from a certificate
 * @param[in] cert Pointer to the certificate structure
 * @param[out] publicKey Pointer to the DSA public key
 * @return Error code
 **/

error_t sshImportDsaCertPublicKey(const SshCertificate *cert,
   DsaPublicKey *publicKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t k;

   //Unexpected key format identifier?
   if(!sshCompareString(&cert->keyFormatId, "ssh-dss-cert-v01@openssh.com"))
      return ERROR_WRONG_IDENTIFIER;

   //Import DSA prime modulus
   error = mpiImport(&publicKey->params.p, cert->publicKey.dsaPublicKey.p.value,
      cert->publicKey.dsaPublicKey.p.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group order
   error = mpiImport(&publicKey->params.q, cert->publicKey.dsaPublicKey.q.value,
      cert->publicKey.dsaPublicKey.q.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group generator
   error = mpiImport(&publicKey->params.g, cert->publicKey.dsaPublicKey.g.value,
      cert->publicKey.dsaPublicKey.g.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA public key value
   error = mpiImport(&publicKey->y, cert->publicKey.dsaPublicKey.y.value,
      cert->publicKey.dsaPublicKey.y.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->params.p);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_DSA_MODULUS_SIZE || k > SSH_MAX_DSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an ECDSA public key from a certificate
 * @param[in] cert Pointer to the certificate structure
 * @param[out] params EC domain parameters
 * @param[out] publicKey Pointer to the ECDSA public key
 * @return Error code
 **/

error_t sshImportEcdsaCertPublicKey(const SshCertificate *cert,
   EcDomainParameters *params, EcPublicKey *publicKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   const EcCurveInfo *curveInfo;

   //Check key format identifier
   if(sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp256-cert-v01@openssh.com") ||
      sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp384-cert-v01@openssh.com") ||
      sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp521-cert-v01@openssh.com"))
   {
      //Retrieve the elliptic curve that matches the specified key format
      //identifier
      curveInfo = sshGetCurveInfo(&cert->keyFormatId,
         &cert->publicKey.ecdsaPublicKey.curveName);

      //Make sure the key format identifier is acceptable
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(params, curveInfo);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_IDENTIFIER;
      }

      //Check status code
      if(!error)
      {
         //Import EC public key value
         error = ecImport(params, &publicKey->q, cert->publicKey.ecdsaPublicKey.q.value,
            cert->publicKey.ecdsaPublicKey.q.length);
      }
   }
   else
   {
      //Unexpected key format identifier
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an Ed25519 public key from a certificate
 * @param[in] cert Pointer to the certificate structure
 * @param[out] publicKey Pointer to the RSA public key
 * @return Error code
 **/

error_t sshImportEd25519CertPublicKey(const SshCertificate *cert,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Check key format identifier
   if(sshCompareString(&cert->keyFormatId, "ssh-ed25519-cert-v01@openssh.com"))
   {
      //Import Ed25519 public key value
      error = mpiImport(&publicKey->q, cert->publicKey.ed25519PublicKey.q.value,
         cert->publicKey.ed25519PublicKey.q.length, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Unexpected key format identifier
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get SSH certificate type
 * @param[in] input SSH certificate file
 * @param[in] length Length of the SSH certificate file
 * @return SSH certificate type
 **/

const char_t *sshGetCertType(const char_t *input, size_t length)
{
   uint_t i;
   size_t n;
   const char_t *certType;

   //Initialize certificate type
   certType = NULL;

   //Loop through the list of identifiers
   for(i = 0; i < arraysize(sshCertTypes); i++)
   {
      //Get the length of the identifier
      n = osStrlen(sshCertTypes[i]);

      //Matching identifier?
      if(length > n && !osMemcmp(input, sshCertTypes[i], n))
      {
         //The identifier must be followed by a whitespace character
         if(input[n] == ' ' || input[n] == '\t')
         {
            certType = sshCertTypes[i];
            break;
         }
      }
   }

   //Return certificate type
   return certType;
}

#endif
