/**
 * @file ssh_cert_parse.c
 * @brief SSH certificate parsing
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
#include "ssh/ssh_cert_parse.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)


/**
 * @brief Parse SSH certificate
 * @param[in] data Pointer to the certificate
 * @param[in] length Length of the certificate, in bytes
 * @param[out] cert Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseCertificate(const uint8_t *data, size_t length,
   SshCertificate *cert)
{
   error_t error;
   size_t n;

   //Clear the certificate information structure
   osMemset(cert, 0, sizeof(SshCertificate));

   //Decode key format identifier
   error = sshParseString(data, length, &cert->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->keyFormatId.length;
   length -= sizeof(uint32_t) + cert->keyFormatId.length;

   //Parse 'nonce' field
   error = sshParseBinaryString(data, length, &cert->nonce);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->nonce.length;
   length -= sizeof(uint32_t) + cert->nonce.length;

#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(sshCompareString(&cert->keyFormatId, "ssh-rsa-cert-v01@openssh.com"))
   {
      //Parse RSA public key
      error = sshParseRsaCertPublicKey(data, length, &n,
         &cert->publicKey.rsaPublicKey);
   }
   else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(sshCompareString(&cert->keyFormatId, "ssh-dss-cert-v01@openssh.com"))
   {
      //Parse DSA public key
      error = sshParseDsaCertPublicKey(data, length, &n,
         &cert->publicKey.dsaPublicKey);
   }
   else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp256-cert-v01@openssh.com") ||
      sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp384-cert-v01@openssh.com") ||
      sshCompareString(&cert->keyFormatId, "ecdsa-sha2-nistp521-cert-v01@openssh.com"))
   {
      //Parse ECDSA public key
      error = sshParseEcdsaCertPublicKey(data, length, &n,
         &cert->publicKey.ecdsaPublicKey);
   }
   else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 certificate?
   if(sshCompareString(&cert->keyFormatId, "ssh-ed25519-cert-v01@openssh.com"))
   {
      //Parse Ed25519 public key
      error = sshParseEd25519CertPublicKey(data, length, &n,
         &cert->publicKey.ed25519PublicKey);
   }
   else
#endif
   //Unknown certificate type?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Malformed certificate?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Parse 'serial' field
   cert->serial = LOAD64BE(data);

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Malformed certificate?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //Parse 'type' field
   cert->type = LOAD32BE(data);

   //Check certificate type
   if(cert->type != SSH_CERT_TYPE_USER && cert->type != SSH_CERT_TYPE_HOST)
      return ERROR_WRONG_TYPE;

   //Point to the next field
   data += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse 'key id' field
   error = sshParseString(data, length, &cert->keyId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->keyId.length;
   length -= sizeof(uint32_t) + cert->keyId.length;

   //Parse 'valid principals' field
   error = sshParseValidPrincipals(data, length, &cert->validPrincipals);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->validPrincipals.length;
   length -= sizeof(uint32_t) + cert->validPrincipals.length;

   //Malformed certificate?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Parse 'valid after' field
   cert->validAfter = LOAD64BE(data);

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Malformed certificate?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_SYNTAX;

   //Parse 'valid before' field
   cert->validBefore = LOAD64BE(data);

   //Point to the next field
   data += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Parse 'critical options' field
   error = sshParseCriticalOptions(data, length, &cert->criticalOptions);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->criticalOptions.length;
   length -= sizeof(uint32_t) + cert->criticalOptions.length;

   //Parse 'extensions' field
   error = sshParseExtensions(data, length, &cert->extensions);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->extensions.length;
   length -= sizeof(uint32_t) + cert->extensions.length;

   //Parse 'reserved' field
   error = sshParseBinaryString(data, length, &cert->reserved);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->reserved.length;
   length -= sizeof(uint32_t) + cert->reserved.length;

   //Parse 'signature key' field
   error = sshParseBinaryString(data, length, &cert->signatureKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->signatureKey.length;
   length -= sizeof(uint32_t) + cert->signatureKey.length;

   //Parse 'signature' field
   error = sshParseBinaryString(data, length, &cert->signature);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + cert->signature.length;
   length -= sizeof(uint32_t) + cert->signature.length;

   //Malformed certificate?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Parse an RSA public key
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[in] consumed Number of bytes that have been consumed
 * @param[out] publicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseRsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshRsaCertPublicKey *publicKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Total number of bytes that have been consumed
   *consumed = 0;

   //Parse RSA public exponent
   error = sshParseBinaryString(data, length, &publicKey->e);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->e.length;
   length -= sizeof(uint32_t) + publicKey->e.length;
   *consumed += sizeof(uint32_t) + publicKey->e.length;

   //Parse RSA modulus
   error = sshParseBinaryString(data, length, &publicKey->n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->n.length;
   length -= sizeof(uint32_t) + publicKey->n.length;
   *consumed += sizeof(uint32_t) + publicKey->n.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse a DSA public key
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[in] consumed Number of bytes that have been consumed
 * @param[out] publicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseDsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshDsaCertPublicKey *publicKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Total number of bytes that have been consumed
   *consumed = 0;

   //Parse DSA prime modulus
   error = sshParseBinaryString(data, length, &publicKey->p);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->p.length;
   length -= sizeof(uint32_t) + publicKey->p.length;
   *consumed += sizeof(uint32_t) + publicKey->p.length;

   //Parse DSA group order
   error = sshParseBinaryString(data, length, &publicKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->q.length;
   length -= sizeof(uint32_t) + publicKey->q.length;
   *consumed += sizeof(uint32_t) + publicKey->q.length;

   //Parse DSA group generator
   error = sshParseBinaryString(data, length, &publicKey->g);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->g.length;
   length -= sizeof(uint32_t) + publicKey->g.length;
   *consumed += sizeof(uint32_t) + publicKey->g.length;

   //Parse DSA public key value
   error = sshParseBinaryString(data, length, &publicKey->y);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->y.length;
   length -= sizeof(uint32_t) + publicKey->y.length;
   *consumed += sizeof(uint32_t) + publicKey->y.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an ECDSA public key
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[in] consumed Number of bytes that have been consumed
 * @param[out] publicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEcdsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshEcdsaCertPublicKey *publicKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Total number of bytes that have been consumed
   *consumed = 0;

   //Parse curve name
   error = sshParseString(data, length, &publicKey->curveName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->curveName.length;
   length -= sizeof(uint32_t) + publicKey->curveName.length;
   *consumed += sizeof(uint32_t) + publicKey->curveName.length;

   //Parse EC public key
   error = sshParseBinaryString(data, length, &publicKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->q.length;
   length -= sizeof(uint32_t) + publicKey->q.length;
   *consumed += sizeof(uint32_t) + publicKey->q.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an Ed25519 public key
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[in] consumed Number of bytes that have been consumed
 * @param[out] publicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEd25519CertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshEd25519CertPublicKey *publicKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Total number of bytes that have been consumed
   *consumed = 0;

   //Parse Ed25519 public key value
   error = sshParseBinaryString(data, length, &publicKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + publicKey->q.length;
   length -= sizeof(uint32_t) + publicKey->q.length;
   *consumed += sizeof(uint32_t) + publicKey->q.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse 'valid principals' field
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[out] validPrincipals Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseValidPrincipals(const uint8_t *data, size_t length,
   SshBinaryString *validPrincipals)
{
   error_t error;
   SshString name;

   //'valid principals' is a string containing zero or more principals as
   //strings packed inside it
   error = sshParseBinaryString(data, length, validPrincipals);

   //Check status code
   if(!error)
   {
      //Check the length of the string
      if(validPrincipals->length > 0)
      {
         //Point to the first item of the list
         data = validPrincipals->value;
         length = validPrincipals->length;

         //These principals list the names for which this certificate is
         //valid; hostnames for SSH_CERT_TYPE_HOST certificates and usernames
         //for SSH_CERT_TYPE_USER certificates
         while(length > 0)
         {
            //Decode current name
            error = sshParseString(data, length, &name);
            //Any error to report?
            if(error)
               break;

            //Point to the next field
            data += sizeof(uint32_t) + name.length;
            length -= sizeof(uint32_t) + name.length;
         }
      }
      else
      {
         //As a special case, a zero-length 'valid principals' field means the
         //certificate is valid for any principal of the specified type
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse 'critical options' field
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[out] criticalOptions Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseCriticalOptions(const uint8_t *data, size_t length,
   SshBinaryString *criticalOptions)
{
   error_t error;
   SshString optionName;
   SshString optionData;

   //'critical options' is a set of zero or more key options. All such options
   //are critical in the sense that an implementation must refuse to authorize
   //a key that has an unrecognized option
   error = sshParseBinaryString(data, length, criticalOptions);

   //Check status code
   if(!error)
   {
      //Point to the first item of the list
      data = criticalOptions->value;
      length = criticalOptions->length;

      //Loop through critical options
      while(length > 0)
      {
         //The name field identifies the option
         error = sshParseString(data, length, &optionName);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += sizeof(uint32_t) + optionName.length;
         length -= sizeof(uint32_t) + optionName.length;

         //The data field encodes option-specific information
         error = sshParseString(data, length, &optionData);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += sizeof(uint32_t) + optionData.length;
         length -= sizeof(uint32_t) + optionData.length;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse 'extensions' field
 * @param[in] data Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[out] extensions Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseExtensions(const uint8_t *data, size_t length,
   SshBinaryString *extensions)
{
   error_t error;
   SshString extensionName;
   SshString extensionData;

   //'extensions' is a set of zero or more optional extensions. These extensions
   //are not critical, and an implementation that encounters one that it does
   //not recognize may safely ignore it
   error = sshParseBinaryString(data, length, extensions);

   //Check status code
   if(!error)
   {
      //Point to the first item of the list
      data = extensions->value;
      length = extensions->length;

      //Loop through extensions
      while(length > 0)
      {
         //The name field identifies the extension
         error = sshParseString(data, length, &extensionName);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += sizeof(uint32_t) + extensionName.length;
         length -= sizeof(uint32_t) + extensionName.length;

         //The data field encodes extension-specific information
         error = sshParseString(data, length, &extensionData);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += sizeof(uint32_t) + extensionData.length;
         length -= sizeof(uint32_t) + extensionData.length;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Extract the principal name at specified index
 * @param[in] cert Pointer to the SSH certificate
 * @param[in] index Zero-based index of the element to get
 * @param[out] name Principal name
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetValidPrincipal(const SshCertificate *cert, uint_t index,
   SshString *name)
{
   error_t error;
   uint_t i;
   size_t length;
   const uint8_t *p;

   //Point to the first item of the list
   p = cert->validPrincipals.value;
   length = cert->validPrincipals.length;

   //Loop through principals
   for(i = 0; length > 0; i++)
   {
      //Decode current name
      error = sshParseString(p, length, name);
      //Any error to report?
      if(error)
         return FALSE;

      //Point to the next field
      p += sizeof(uint32_t) + name->length;
      length -= sizeof(uint32_t) + name->length;

      //Matching index?
      if(i == index)
         return TRUE;
   }

   //The index is out of range
   return FALSE;
}


/**
 * @brief Extract the critical option at specified index
 * @param[in] cert Pointer to the SSH certificate
 * @param[in] index Zero-based index of the element to get
 * @param[out] name Option name
 * @param[out] data Option value
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetCriticalOption(const SshCertificate *cert, uint_t index,
   SshString *name, SshBinaryString *data)
{
   error_t error;
   uint_t i;
   size_t length;
   const uint8_t *p;

   //Point to the first item of the list
   p = cert->criticalOptions.value;
   length = cert->criticalOptions.length;

   //Loop through critical options
   for(i = 0; length > 0; i++)
   {
      //The name field identifies the option
      error = sshParseString(p, length, name);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      p += sizeof(uint32_t) + name->length;
      length -= sizeof(uint32_t) + name->length;

      //The data field encodes option-specific information
      error = sshParseBinaryString(p, length, data);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      p += sizeof(uint32_t) + data->length;
      length -= sizeof(uint32_t) + data->length;

      //Matching index?
      if(i == index)
         return TRUE;
   }

   //The index is out of range
   return FALSE;
}


/**
 * @brief Extract the extension at specified index
 * @param[in] cert Pointer to the SSH certificate
 * @param[in] index Zero-based index of the element to get
 * @param[out] name Extension name
 * @param[out] data Extension value
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetExtension(const SshCertificate *cert, uint_t index,
   SshString *name, SshBinaryString *data)
{
   error_t error;
   uint_t i;
   size_t length;
   const uint8_t *p;

   //Point to the first item of the list
   p = cert->extensions.value;
   length = cert->extensions.length;

   //Loop through extensions
   for(i = 0; length > 0; i++)
   {
      //The name field identifies the extension
      error = sshParseString(p, length, name);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      p += sizeof(uint32_t) + name->length;
      length -= sizeof(uint32_t) + name->length;

      //The data field encodes extension-specific information
      error = sshParseBinaryString(p, length, data);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      p += sizeof(uint32_t) + data->length;
      length -= sizeof(uint32_t) + data->length;

      //Matching index?
      if(i == index)
         return TRUE;
   }

   //The index is out of range
   return FALSE;
}

#endif
