/**
 * @file ssh_key_verify.c
 * @brief SSH host key verification
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
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Check if a host key is trusted
 * @param[in] hostKey Host key to be checked
 * @param[in] hostKeyLen Length of the host key, in bytes
 * @param[in] trustedKey Trusted host key (SSH2 or OpenSSH format)
 * @param[in] trustedKeyLen Length of the trusted host key
 * @return Error code
 **/

error_t sshVerifyHostKey(const uint8_t *hostKey, size_t hostKeyLen,
   const char_t *trustedKey, size_t trustedKeyLen)
{
   error_t error;
   size_t n;
   uint8_t *buffer;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(trustedKey, trustedKeyLen, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(trustedKey, trustedKeyLen, buffer, &n);

         //Check status code
         if(!error)
         {
            //Compare host keys
            if(hostKeyLen == n && !osMemcmp(hostKey, buffer, n))
            {
               //The host key is trusted
               error = NO_ERROR;
            }
            else
            {
               //The host key is unknown
               error = ERROR_INVALID_KEY;
            }
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify client's host key
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Client's host key
 * @return Error code
 **/

error_t sshVerifyClientHostKey(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey)
{
   error_t error;
   SshString keyFormatId;
   SshContext *context;
   const char_t *expectedKeyFormatId;

   //Point to the SSH context
   context = connection->context;

   //Parse client's host key
   error = sshParseHostKey(hostKey->value, hostKey->length, &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Each host key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Check whether the supplied key is consistent with the host key algorithm
   if(!sshCompareString(&keyFormatId, expectedKeyFormatId))
      return ERROR_INVALID_KEY;

   //Invoke user-defined callback, if any
   if(context->publicKeyAuthCallback != NULL)
   {
      //Check the host key against the server's database
      error = context->publicKeyAuthCallback(connection, connection->user,
         hostKey->value, hostKey->length);
   }
   else
   {
      //The server's host key cannot be verified
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
}


/**
 * @brief Verify server's host key
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Server's host key
 * @return Error code
 **/

error_t sshVerifyServerHostKey(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey)
{
   error_t error;
   SshString keyFormatId;
   SshContext *context;
   const char_t *expectedKeyFormatId;

   //Point to the SSH context
   context = connection->context;

   //Parse server's host key
   error = sshParseHostKey(hostKey->value, hostKey->length, &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Each host key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Check whether the supplied key is consistent with the host key algorithm
   if(!sshCompareString(&keyFormatId, expectedKeyFormatId))
      return ERROR_INVALID_KEY;

   //Invoke user-defined callback, if any
   if(context->hostKeyVerifyCallback != NULL)
   {
      //It is recommended that the client verify that the host key sent is the
      //server's host key (for example, using a local database)
      error = context->hostKeyVerifyCallback(connection, hostKey->value,
         hostKey->length);
   }
   else
   {
      //The client may accept the host key without verification, but doing so
      //will render the protocol insecure against active attacks
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
}

#endif
