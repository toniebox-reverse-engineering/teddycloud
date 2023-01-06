/**
 * @file ssh_cert_verify.c
 * @brief SSH certificate verification
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
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_signature.h"
#include "ssh/ssh_cert_parse.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "date_time.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)


/**
 * @brief Verify client's certificate
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Client's certified host key
 * @param[in] flag This flag specifies whether the signature is present in
 *   the SSH_MSG_USERAUTH_REQUEST message
 * @return Error code
 **/

error_t sshVerifyClientCertificate(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey,
   bool_t flag)
{
   error_t error;
   SshCertificate cert;
   SshContext *context;
   const char_t *expectedKeyFormatId;

   //Point to the SSH context
   context = connection->context;

   //Parse client's certified host key
   error = sshParseCertificate(hostKey->value, hostKey->length, &cert);
   //Any error to report?
   if(error)
      return error;

   //Each host key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Check whether the supplied key is consistent with the host key algorithm
   if(!sshCompareString(&cert.keyFormatId, expectedKeyFormatId))
      return ERROR_BAD_CERTIFICATE;

   //Check certificate type
   if(cert.type != SSH_CERT_TYPE_USER)
      return ERROR_BAD_CERTIFICATE;

   //Check whether the certificate is valid for the current user name
   error = sshVerifyPrincipal(&cert, connection->user);
   //Any error to report?
   if(error)
      return error;

   //Check the validity period of the certificate
   error = sshVerifyValidity(&cert);
   //Any error to report?
   if(error)
      return error;

   //Check critical options
   error = sshVerifyCriticalOptions(connection, &cert);
   //Any error to report?
   if(error)
      return error;

   //Invoke user-defined callback, if any
   if(context->caPublicKeyVerifyCallback != NULL)
   {
      //Verify CA public key
      error = context->caPublicKeyVerifyCallback(connection,
         cert.signatureKey.value, cert.signatureKey.length);
   }
   else
   {
      //The CA public key cannot be verified
      error = ERROR_UNKNOWN_CA;
   }

   //Failed to verify CA public key?
   if(error)
      return ERROR_UNKNOWN_CA;

   //The client may send an SSH_MSG_USERAUTH_REQUEST message without signature
   //to check whether the provided certificate is acceptable for authentication
   if(flag)
   {
      //Verify certificate signature
      error = sshVerifyCertSignature(connection, &cert);
      //Any error to report?
      if(error)
         return error;

      //Invoke user-defined callback, if any
      if(context->certAuthCallback != NULL)
      {
         //Verify client's certificate
         error = context->certAuthCallback(connection, connection->user, &cert);
      }
      else
      {
         //The client's certificate cannot be verified
         error = ERROR_BAD_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify server's certificate
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Server's certified host key
 * @return Error code
 **/

error_t sshVerifyServerCertificate(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey)
{
   error_t error;
   SshCertificate cert;
   SshContext *context;
   const char_t *expectedKeyFormatId;

   //Point to the SSH context
   context = connection->context;

   //Parse server's certified host key
   error = sshParseCertificate(hostKey->value, hostKey->length, &cert);
   //Any error to report?
   if(error)
      return error;

   //Each host key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Check whether the supplied key is consistent with the host key algorithm
   if(!sshCompareString(&cert.keyFormatId, expectedKeyFormatId))
      return ERROR_BAD_CERTIFICATE;

   //Check certificate type
   if(cert.type != SSH_CERT_TYPE_HOST)
      return ERROR_BAD_CERTIFICATE;

   //Check the validity period of the certificate
   error = sshVerifyValidity(&cert);
   //Any error to report?
   if(error)
      return error;

   //No critical options are defined for host certificates at present
   if(cert.criticalOptions.length > 0)
      return ERROR_INVALID_OPTION;

   //Invoke user-defined callback, if any
   if(context->caPublicKeyVerifyCallback != NULL)
   {
      //Verify CA public key
      error = context->caPublicKeyVerifyCallback(connection,
         cert.signatureKey.value, cert.signatureKey.length);
   }
   else
   {
      //The CA public key cannot be verified
      error = ERROR_UNKNOWN_CA;
   }

   //Failed to verify CA public key?
   if(error)
      return ERROR_UNKNOWN_CA;

   //Verify certificate signature
   error = sshVerifyCertSignature(connection, &cert);
   //Any error to report?
   if(error)
      return error;

   //Invoke user-defined callback, if any
   if(context->certVerifyCallback != NULL)
   {
      //Verify server's certificate
      error = context->certVerifyCallback(connection, &cert);
   }
   else
   {
      //The server's certificate cannot be verified
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Verify principal name
 * @param[in] cert Pointer to the SSH certificate
 * @param[in] name NULL-terminated string containing a user name or host name
 * @return Error code
 **/

error_t sshVerifyPrincipal(const SshCertificate *cert, const char_t *name)
{
   error_t error;
   uint_t i;
   SshString principal;

   //Check the length of the 'valid principals' field
   if(cert->validPrincipals.length > 0)
   {
      //These principals list the names for which this certificate is valid
      for(i = 0; ; i++)
      {
         //Extract principal name
         if(sshGetValidPrincipal(cert, i, &principal))
         {
            //Check principal name
            if(sshCompareString(&principal, name))
            {
               //The certificate is valid for the specified name
               error = NO_ERROR;
               break;
            }
         }
         else
         {
            //The end of the list was reached
            error = ERROR_UNKNOWN_USER_NAME;
            break;
         }
      }
   }
   else
   {
      //As a special case, a zero-length 'valid principals' field means the
      //certificate is valid for any principal of the specified type
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Verify validity period
 * @param[in] cert Pointer to the SSH certificate
 * @return Error code
 **/

error_t sshVerifyValidity(const SshCertificate *cert)
{
   error_t error;
   uint64_t currentTime;

   //Initialize status code
   error = NO_ERROR;

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      //Check the validity period
      if(currentTime < cert->validAfter || currentTime > cert->validBefore)
      {
         //The certificate has expired or is not yet valid
         return ERROR_CERTIFICATE_EXPIRED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify critical options
 * @param[in] connection Pointer to the SSH connection
 * @param[in] cert Pointer to the SSH certificate
 * @return Error code
 **/

error_t sshVerifyCriticalOptions(SshConnection *connection,
   const SshCertificate *cert)
{
   error_t error;
   uint_t i;
   SshString optionName;
   SshBinaryString optionData;

   //Initialize status code
   error = NO_ERROR;

   //'critical options' is a set of zero or more key options. All such options
   //are critical in the sense that an implementation must refuse to authorize
   //a key that has an unrecognized option
   for(i = 0; !error; i++)
   {
      //Extract critical option
      if(sshGetCriticalOption(cert, i, &optionName, &optionData))
      {
         //Compare option name
         if(sshCompareString(&optionName, "source-address"))
         {
            //Parse "source-address" option
            error = sshVerifySrcAddrOption(connection, &optionData);
         }
         else
         {
            //If an implementation does not recognize an option, then the
            //validating party should refuse to accept the certificate
            error = ERROR_INVALID_OPTION;
         }
      }
      else
      {
         //The end of the list was reached
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify "source-address" option
 * @param[in] connection Pointer to the SSH connection
 * @param[in] optionData Option-specific information
 * @return Error code
 **/

error_t sshVerifySrcAddrOption(SshConnection *connection,
   const SshBinaryString *optionData)
{
   error_t error;
   char_t *p;
   uint_t i;
   uint_t prefixLen;
   SshString name;
   SshNameList nameList;
   IpAddr ipAddr;
   IpAddr clientIpAddr;
   uint16_t clientPort;
   char_t buffer[44];

   //The option contains a comma-separated list of source addresses from
   //which this certificate is accepted for authentication
   error = sshParseNameList(optionData->value, optionData->length,
      &nameList);

   //Check status code
   if(!error)
   {
      //Retrieve the IP address of the client
      error = socketGetRemoteAddr(connection->socket, &clientIpAddr,
         &clientPort);
   }

   //Check status code
   if(!error)
   {
      //Loop through the list of source addresses
      for(i = 0; !error; i++)
      {
         //Source addresses are separated by commas
         if(sshGetName(&nameList, i, &name))
         {
            //Check the length of the string
            if(name.length < sizeof(buffer))
            {
               //Copy the string representation of the IP address
               osMemcpy(buffer, name.value, name.length);
               //Properly terminate the string with a NULL character
               buffer[name.length] = '\0';

               //Addresses are specified in CIDR format
               p = osStrchr(buffer, '/');

               //Separator character found?
               if(p != NULL)
               {
                  //Split the CIDR representation
                  *p = '\0';

                  //Convert the prefix from string representation
                  error = ipStringToAddr(buffer, &ipAddr);
                  //Malformed CIDR representation?
                  if(error)
                     break;

                  //Convert the CIDR prefix length
                  prefixLen = osStrtoul(p + 1, &p, 10);
                  //Malformed CIDR representation?
                  if(*p != '\0')
                  {
                     error = ERROR_INVALID_SYNTAX;
                     break;
                  }

                  //Compare IP address prefixes
                  if(ipCompPrefix(&clientIpAddr, &ipAddr, prefixLen))
                  {
                     //The client's IP address is acceptable
                     break;
                  }
               }
               else
               {
                  //Convert the IP address from string representation
                  error = ipStringToAddr(buffer, &ipAddr);
                  //Malformed IP address?
                  if(error)
                     break;

                  //Compare IP addresses
                  if(ipCompAddr(&clientIpAddr, &ipAddr))
                  {
                     //The client's IP address is acceptable
                     break;
                  }
               }
            }
         }
         else
         {
            //The end of the list was reached
            error = ERROR_INVALID_ADDRESS;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify certificate signature
 * @param[in] connection Pointer to the SSH connection
 * @param[in] cert Pointer to the SSH certificate
 * @return Error code
 **/

error_t sshVerifyCertSignature(SshConnection *connection,
   const SshCertificate *cert)
{
   error_t error;
   SshString signFormatId;
   SshBinaryString tbsData;

   //Extract signature format identifier
   error = sshParseString(cert->signature.value, cert->signature.length,
      &signFormatId);

   //Check status code
   if(!error)
   {
      //Point to the first byte of the certificate
      tbsData.value = (const uint8_t *) cert->keyFormatId.value -
         sizeof(uint32_t);

      //The certificate's signature is computed over all preceding fields from
      //the initial string up to, and including the signature key
      tbsData.length = cert->signatureKey.value + cert->signatureKey.length -
         tbsData.value;

      //Verify certificate signature
      error = sshVerifySignature(connection, &signFormatId, &cert->signatureKey,
         NULL, &tbsData, &cert->signature);
   }

   //Return status code
   return error;
}

#endif
