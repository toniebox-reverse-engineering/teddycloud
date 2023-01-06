/**
 * @file ssh_auth_public_key.c
 * @brief Public key authentication method
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
#include "ssh/ssh_transport.h"
#include "ssh/ssh_auth.h"
#include "ssh/ssh_auth_public_key.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_signature.h"
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_cert_parse.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_USERAUTH_PK_OK message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm name
 * @param[in] publicKey Public key blob from the authentication request
 * @return Error code
 **/

error_t sshSendUserAuthPkOk(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_PK_OK message
   error = sshFormatUserAuthPkOk(connection, publicKeyAlgo, publicKey, message,
      &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_PK_OK message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format "publickey" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to the message to be signed
 * @param[out] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the method specific fields
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatPublicKeyAuthParams(SshConnection *connection,
   const uint8_t *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   SshHostKey *hostKey;
   SshBinaryString sessionId;
   SshBinaryString tbsData;

   //Total number of bytes that have been written
   *written = 0;

   //Format method name
   error = sshFormatString("publickey", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the first method-specific field
   p += n;
   *written += n;

   //Format flag
   p[0] = connection->publicKeyOk ? TRUE : FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *written += sizeof(uint8_t);

   //Get the currently selected host key
   hostKey = sshGetHostKey(connection);
   //Invalid host key?
   if(hostKey == NULL)
      return ERROR_INVALID_KEY;

   //Make sure the public key algorithm is valid
   if(hostKey->publicKeyAlgo == NULL)
      return ERROR_INVALID_KEY;

   //Format public key algorithm name
   error = sshFormatString(hostKey->publicKeyAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   p += n;
   *written += n;

   //Format public key blob
   error = sshFormatHostKey(connection, p + sizeof(uint32_t), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   *written += sizeof(uint32_t) + n;

   //If the host key is acceptable, then the client can send a signature
   //generated using the private key
   if(connection->publicKeyOk)
   {
      //Point to the session identifier
      sessionId.value = connection->sessionId;
      sessionId.length = connection->sessionIdLen;

      //Point to the message to be signed
      tbsData.value = message;
      tbsData.length = messageLen + *written;

      //Compute the signature using the private key
      error = sshGenerateSignature(connection, hostKey->publicKeyAlgo,
         hostKey, &sessionId, &tbsData, p + sizeof(uint32_t), &n);
      //Any error to report?
      if(error)
         return error;

      //The octet string value is preceded by a uint32 containing its length
      STORE32BE(n, p);

      //Total length of the method specific fields
      *written += sizeof(uint32_t) + n;
   }

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_USERAUTH_PK_OK message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm name
 * @param[in] publicKey Public key blob from the authentication request
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthPkOk(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey,
   uint8_t *p, size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_USERAUTH_PK_OK;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //The public key algorithm name is copied from the request
   error = sshFormatBinaryString(publicKeyAlgo->value, publicKeyAlgo->length,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //The public key blob is copied from the request
   error = sshFormatBinaryString(publicKey->value, publicKey->length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse "publickey" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[in] userName Pointer to the user name
 * @param[in] message Pointer to the SSH_MSG_USERAUTH_REQUEST message
 * @param[in] p Pointer to method specific fields
 * @param[in] length Length of the method specific fields, in bytes
 * @return Error code
 **/

error_t sshParsePublicKeyAuthParams(SshConnection *connection,
   const SshString *userName, const uint8_t *message, const uint8_t *p,
   size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   SshBoolean flag;
   SshString publicKeyAlgo;
   SshBinaryString publicKey;
   SshBinaryString sessionId;
   SshBinaryString tbsData;
   SshBinaryString signature;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode flag
   flag = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Decode public key algorithm name
   error = sshParseString(p, length, &publicKeyAlgo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + publicKeyAlgo.length;
   length -= sizeof(uint32_t) + publicKeyAlgo.length;

   //Decode public key blob
   error = sshParseBinaryString(p, length, &publicKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + publicKey.length;
   length -= sizeof(uint32_t) + publicKey.length;

   //Point to the message whose signature is to be verified
   tbsData.value = message;
   tbsData.length = p - message;

   //Check the value of the flag
   if(flag)
   {
      //Decode signature
      error = sshParseBinaryString(p, length, &signature);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + signature.length;
      length -= sizeof(uint32_t) + signature.length;
   }
   else
   {
      //The signature field is not present
      signature.value = NULL;
      signature.length = 0;
   }

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //When the server receives this message, it must check whether the supplied
   //key is acceptable for authentication (refer to RFC 4252, section 7)
   if(userName->length <= SSH_MAX_USERNAME_LEN)
   {
      //Save user name
      osMemcpy(connection->user, userName->value, userName->length);
      //Properly terminate the command line with a NULL character
      connection->user[userName->length] = '\0';

#if (SSH_CERT_SUPPORT == ENABLED)
      //Certificate-based authentication?
      if(sshIsCertPublicKeyAlgo(&publicKeyAlgo))
      {
         //Verify client's certificate
         error = sshVerifyClientCertificate(connection, &publicKeyAlgo,
            &publicKey, flag);
      }
      else
#endif
      {
         //Verify client's host key
         error = sshVerifyClientHostKey(connection, &publicKeyAlgo,
            &publicKey);
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Valid host key?
   if(!error)
   {
      //Check whether the signature is present
      if(flag)
      {
         //Point to the session identifier
         sessionId.value = connection->sessionId;
         sessionId.length = connection->sessionIdLen;

         //If the supplied key is acceptable for authentication, the server
         //must check whether the signature is correct
         error = sshVerifySignature(connection, &publicKeyAlgo, &publicKey,
            &sessionId, &tbsData, &signature);
      }
   }

   //Check status code
   if(!error)
   {
      //Check whether the signature is present
      if(flag)
      {
         //When the server accepts authentication, it must respond with a
         //SSH_MSG_USERAUTH_SUCCESS message
         error = sshAcceptAuthRequest(connection);
      }
      else
      {
         //Limit the number of authentication attempts
         if(connection->authAttempts <= SSH_MAX_AUTH_ATTEMPTS)
         {
            //The supplied key is acceptable for authentication
            error = sshSendUserAuthPkOk(connection, &publicKeyAlgo, &publicKey);
         }
         else
         {
            //If the threshold is exceeded, the server should disconnect (refer
            //to RFC 4252, section 4)
            error = sshSendDisconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
               "Too many authentication attempts");
         }
      }
   }
   else
   {
      //If the server rejects the authentication request, it must respond with
      //an SSH_MSG_USERAUTH_FAILURE message
      error = sshRejectAuthRequest(connection);
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_USERAUTH_PK_OK message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthPkOk(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString publicKeyAlgo;
   SshBinaryString publicKey;

   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_PK_OK message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_SERVER_EXT_INFO_2 &&
      connection->state != SSH_CONN_STATE_USER_AUTH_REPLY)
   {
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode public key algorithm name
   error = sshParseString(p, length, &publicKeyAlgo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + publicKeyAlgo.length;
   length -= sizeof(uint32_t) + publicKeyAlgo.length;

   //Decode public key blob
   error = sshParseBinaryString(p, length, &publicKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + publicKey.length;
   length -= sizeof(uint32_t) + publicKey.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Sanity check
   if(connection->publicKeyOk)
      return ERROR_UNEXPECTED_MESSAGE;

#if (SSH_CERT_SUPPORT == ENABLED)
   //Certificate-based authentication?
   if(sshIsCertPublicKeyAlgo(&publicKeyAlgo))
   {
      SshCertificate cert;

      //Check the syntax of the certificate structure
      error = sshParseCertificate(publicKey.value, publicKey.length, &cert);
   }
   else
#endif
   {
      SshString keyFormatId;

      //Check the syntax of the host key structure
      error = sshParseHostKey(publicKey.value, publicKey.length, &keyFormatId);
   }

   //Any error to report?
   if(error)
      return error;

   //The provided host key is acceptable
   connection->publicKeyOk = TRUE;

   //Now that the public key is acceptable, the client can perform the signing
   //operation by sending an SSH_MSG_USERAUTH_REQUEST message to the server
   connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}

#endif
