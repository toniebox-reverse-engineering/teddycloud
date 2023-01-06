/**
 * @file ssh_auth.c
 * @brief SSH user authentication protocol
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
#include "ssh/ssh_transport.h"
#include "ssh/ssh_auth.h"
#include "ssh/ssh_auth_password.h"
#include "ssh/ssh_auth_public_key.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)

//Supported authentication methods
static const char_t *const sshSupportedAuthMethods[] =
{
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   "publickey",
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   "password",
#endif
   "none"
};


/**
 * @brief Send SSH_MSG_USERAUTH_BANNER message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] banner NULL-terminated string containing the banner message
 * @return Error code
 **/

error_t sshSendUserAuthBanner(SshConnection *connection,
   const char_t *banner)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_BANNER message
   error = sshFormatUserAuthBanner(connection, banner, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_BANNER message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Wait for an SSH_MSG_USERAUTH_REQUEST message
      connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_USERAUTH_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendUserAuthRequest(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   //Public key authentication?
   if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PUBLIC_KEY)
   {
      //First authentication request?
      if(connection->hostKeyIndex < 0)
      {
         //Select the first host key to use
         sshSelectNextHostKey(connection);
         //The client first verifies whether the key is acceptable
         connection->publicKeyOk = FALSE;
      }
   }
#endif

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_REQUEST message
   error = sshFormatUserAuthRequest(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Increment the number of authentication attempts
      connection->authAttempts++;

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
      //The server may send the SSH_MSG_EXT_INFO message immediately preceding
      //the server's SSH_MSG_USERAUTH_SUCCESS message
      connection->state = SSH_CONN_STATE_SERVER_EXT_INFO_2;
#else
      //Wait for an SSH_MSG_USERAUTH_SUCCESS or SSH_MSG_USERAUTH_FAILURE
      //message
      connection->state = SSH_CONN_STATE_USER_AUTH_REPLY;
#endif
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_USERAUTH_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendUserAuthSuccess(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_SUCCESS message
   error = sshFormatUserAuthSuccess(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_SUCCESS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Either party may later initiate a key re-exchange by sending a
      //SSH_MSG_KEXINIT message
      connection->kexInitSent = FALSE;
      connection->kexInitReceived = FALSE;

      //Any non-authentication messages sent by the client after the request
      //that resulted in SSH_MSG_USERAUTH_SUCCESS being sent must be passed
      //to the service being run on top of this protocol
      connection->state = SSH_CONN_STATE_OPEN;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_USERAUTH_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendUserAuthFailure(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_FAILURE message
   error = sshFormatUserAuthFailure(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The client may send several authentication requests without waiting
      //for responses from previous requests. The server must process each
      //request completely and acknowledge any failed requests with a
      //SSH_MSG_USERAUTH_FAILURE message before processing the next request
      connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Accept client's authentication request
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshAcceptAuthRequest(SshConnection *connection)
{
#if (SSH_EXT_INFO_SUPPORT == ENABLED)
   //If the server receives an "ext-info-c", it may send an SSH_MSG_EXT_INFO
   //message (refer to RFC 8308, section 2.1)
   if(connection->extInfoReceived)
   {
      //The server may send the SSH_MSG_EXT_INFO message immediately preceding
      //the server's SSH_MSG_USERAUTH_SUCCESS message
      connection->state = SSH_CONN_STATE_SERVER_EXT_INFO_2;
   }
   else
#endif
   {
      //When the server accepts authentication, it must respond with an
      //SSH_MSG_USERAUTH_SUCCESS message
      connection->state = SSH_CONN_STATE_USER_AUTH_SUCCESS;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Reject client's authentication request
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshRejectAuthRequest(SshConnection *connection)
{
   error_t error;

   //The implementation should limit the number of failed authentication
   //attempts a client may perform in a single session
   if(connection->authAttempts <= SSH_MAX_AUTH_ATTEMPTS)
   {
      //If the server rejects the authentication request, it must respond with
      //an SSH_MSG_USERAUTH_FAILURE message
      error = sshSendUserAuthFailure(connection);
   }
   else
   {
      //If the threshold is exceeded, the server should disconnect (refer to
      //RFC 4252, section 4)
      error = sshSendDisconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
         "Too many authentication attempts");
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_USERAUTH_BANNER message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] banner NULL-terminated string containing the banner message
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthBanner(SshConnection *connection,
   const char_t *banner, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_USERAUTH_BANNER;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //The message field contains the banner to be displayed before issuing
   //a login prompt
   error = sshFormatString(banner, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the language tag
   error = sshFormatString("en", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_USERAUTH_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] message Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthRequest(SshConnection *connection, uint8_t *message,
   size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *p;

   //Point to the buffer where to format the SSH message
   p = message;
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_USERAUTH_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format user name
   error = sshFormatString(connection->context->username, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format service name
   error = sshFormatString("ssh-connection", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   //Public key authentication?
   if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PUBLIC_KEY)
   {
      //Retrieve the length of the message to be signed
      n = *length;

      //Format "publickey" method specific fields
      error = sshFormatPublicKeyAuthParams(connection, message, n, p, &n);
   }
   else
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   //Password authentication?
   if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PASSWORD)
   {
      //Format "password" method specific fields
      error = sshFormatPasswordAuthParams(connection, p, &n);
   }
   else
#endif
   //No authentication?
   {
      //A client may request a list of authentication methods that may continue
      //by using the "none" authentication. If no authentication is needed for
      //the user, the server must return SSH_MSG_USERAUTH_SUCCESS. Otherwise,
      //the server must return SSH_MSG_USERAUTH_FAILURE
      error = sshFormatNoneAuthParams(connection, p, &n);
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format "none" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the method specific fields
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatNoneAuthParams(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   error_t error;

   //Format method name
   error = sshFormatString("none", p, written);
   //Any error to report?
   if(error)
      return error;

   //A "none" authentication request does not include any method specific fields
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_USERAUTH_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthSuccess(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //The SSH_MSG_USERAUTH_SUCCESS message consists of a single byte
   p[0] = SSH_MSG_USERAUTH_SUCCESS;

   //Total length of the message
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_USERAUTH_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthFailure(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_USERAUTH_FAILURE;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format the list of authentication methods that can continue
   error = sshFormatUserAuthMethods(connection, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //The value of partial success must be TRUE if the authentication request to
   //which this is a response was successful. It must be FALSE if the request
   //was not successfully processed
   p[0] = FALSE;

   //Total length of the message
   *length += sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of allowed authentication methods
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatUserAuthMethods(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   uint_t i;
   size_t n;
   bool_t acceptable;

   //A name-list is represented as a uint32 containing its length followed by
   //a comma-separated list of zero or more names
   n = sizeof(uint32_t);

   //Loop through the list of authentication methods
   for(i = 0; i < arraysize(sshSupportedAuthMethods); i++)
   {
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
      //Public key authentication method?
      if(sshCompareAlgo(sshSupportedAuthMethods[i], "publickey") &&
         connection->context->publicKeyAuthCallback != NULL)
      {
         //The "publickey" authentication method is supported by the server
         acceptable = TRUE;
      }
      else
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
      //Password authentication method?
      if(sshCompareAlgo(sshSupportedAuthMethods[i], "password") &&
         connection->context->passwordAuthCallback != NULL)
      {
         //The "password" authentication method is supported by the server
         acceptable = TRUE;
      }
      else
#endif
      //Unknown authentication method?
      {
         //The "none" method name must not be listed as supported by the server
         acceptable = FALSE;
      }

      //It is recommended that servers only include the method name values in
      //the name-list that are actually useful (refer to RFC 4252, section 5.1)
      if(acceptable)
      {
         //Method names are separated by commas
         if(n != sizeof(uint32_t))
         {
            p[n++] = ',';
         }

         //A name must have a non-zero length and it must not contain a comma
         osStrcpy((char_t *) p + n, sshSupportedAuthMethods[i]);

         //Update the length of the name list
         n += osStrlen(sshSupportedAuthMethods[i]);
      }
   }

   //The name list is preceded by a uint32 containing its length
   STORE32BE(n - sizeof(uint32_t), p);

   //Total number of bytes that have been written
   *written = n;

   //Successfull processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_USERAUTH_BANNER message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthBanner(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString banner;
   SshString languageTag;

   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_BANNER message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any time
   //after this authentication protocol starts and before authentication is
   //successful (refer to RFC 4252, section 5.4)
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

   //The message field contains the text to be displayed to the client user
   //before authentication is attempted
   error = sshParseString(p, length, &banner);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + banner.length;
   length -= sizeof(uint32_t) + banner.length;

   //Decode language tag
   error = sshParseString(p, length, &languageTag);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + languageTag.length;
   length -= sizeof(uint32_t) + languageTag.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_USERAUTH_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString userName;
   SshString serviceName;
   SshString methodName;

   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state == SSH_CONN_STATE_USER_AUTH_REQUEST)
   {
      //The client may send several authentication requests
   }
   else if(connection->state == SSH_CONN_STATE_OPEN)
   {
      //The SSH_MSG_USERAUTH_SUCCESS message must be sent only once. When
      //SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication
      //requests received after that should be silently ignored
      return NO_ERROR;
   }
   else
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode user name
   error = sshParseString(p, length, &userName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + userName.length;
   length -= sizeof(uint32_t) + userName.length;

   //Decode service name
   error = sshParseString(p, length, &serviceName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + serviceName.length;
   length -= sizeof(uint32_t) + serviceName.length;

   //Decode method name
   error = sshParseString(p, length, &methodName);
   //Any error to report?
   if(error)
      return error;

   //Point to the method specific fields
   p += sizeof(uint32_t) + methodName.length;
   length -= sizeof(uint32_t) + methodName.length;

   //Increment the number of authentication attempts
   connection->authAttempts++;

   //The service name specifies the service to start after authentication
   if(sshCompareString(&serviceName, "ssh-connection"))
   {
      //Empty authentication request?
      if(sshCompareString(&methodName, "none"))
      {
         //A client may request a list of authentication method name values
         //that may continue by using the "none" authentication method name
         error = sshParseNoneAuthParams(connection, &userName, p, length);
      }
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
      //Public key authentication request?
      else if(sshCompareString(&methodName, "publickey"))
      {
         //Parse "publickey" method specific fields
         error = sshParsePublicKeyAuthParams(connection, &userName, message,
            p, length);
      }
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
      //Password authentication request?
      else if(sshCompareString(&methodName, "password"))
      {
         //Parse "password" method specific fields
         error = sshParsePasswordAuthParams(connection, &userName, p, length);
      }
#endif
      //Unknown authentication request?
      else
      {
         //The server must return an SSH_MSG_USERAUTH_FAILURE message and may
         //return with it a list of authentication methods that may continue
         error = sshRejectAuthRequest(connection);
      }
   }
   else
   {
      //If the requested service is not available, the server may disconnect
      //immediately. Sending a proper SSH_MSG_DISCONNECT message is recommended.
      //In any case, if the service does not exist, authentication must not be
      //accepted (refer to RFC 4252, section 5)
      error = sshSendDisconnect(connection, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
         "Service not available");
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse "none" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[in] userName Pointer to the user name
 * @param[in] p Pointer to method specific fields
 * @param[in] length Length of the method specific fields, in bytes
 * @return Error code
 **/

error_t sshParseNoneAuthParams(SshConnection *connection,
   const SshString *userName, const uint8_t *p, size_t length)
{
   error_t error;
   SshAuthStatus status;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Check the length of the user name
   if(userName->length <= SSH_MAX_USERNAME_LEN)
   {
      //Save user name
      osMemcpy(connection->user, userName->value, userName->length);
      //Properly terminate the command line with a NULL character
      connection->user[userName->length] = '\0';

#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
      //The server must always reject this request, unless the client is to be
      //granted access without any authentication (refer to RFC 4552, section 4)
      if(context->passwordAuthCallback != NULL)
      {
         //Manage authentication policy
         status = context->passwordAuthCallback(connection, connection->user,
            "", 0);
      }
      else
#endif
      {
         //Access is denied
         status = SSH_AUTH_STATUS_FAILURE;
      }
   }
   else
   {
      //Access is denied
      status = SSH_AUTH_STATUS_FAILURE;
   }

   //Check whether access is granted to the user
   if(status == SSH_AUTH_STATUS_SUCCESS)
   {
      //If no authentication is needed for the user, the server must return
      //an SSH_MSG_USERAUTH_SUCCESS message
      error = sshAcceptAuthRequest(connection);
   }
   else
   {
      //Otherwise, the server must return an SSH_MSG_USERAUTH_FAILURE message
      //and may return with it a list of methods that may continue
      error = sshRejectAuthRequest(connection);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_USERAUTH_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthSuccess(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_SUCCESS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_SERVER_EXT_INFO_2 &&
      connection->state != SSH_CONN_STATE_USER_AUTH_REPLY &&
      connection->state != SSH_CONN_STATE_USER_AUTH_SUCCESS)
   {
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Malformed message?
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Either party may later initiate a key re-exchange by sending a
   //SSH_MSG_KEXINIT message
   connection->kexInitSent = FALSE;
   connection->kexInitReceived = FALSE;

   //Any non-authentication messages sent by the client after the request
   //that resulted in SSH_MSG_USERAUTH_SUCCESS being sent must be passed
   //to the service being run on top of this protocol
   connection->state = SSH_CONN_STATE_OPEN;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_USERAUTH_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshNameList authList;
   SshBoolean partialSuccess;

   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode the list of authentications
   error = sshParseNameList(p, length, &authList);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + authList.length;
   length -= sizeof(uint32_t) + authList.length;

   //Malformed message?
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //The value of partial success must be TRUE if the authentication request to
   //which this is a response was successful. It must be FALSE if the request
   //was not successfully processed
   partialSuccess = p[0];

   //The value of this field is not used
   (void) partialSuccess;

#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   //Public key authentication method?
   if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PUBLIC_KEY)
   {
      //Select the next host key to use
      sshSelectNextHostKey(connection);
      //The client first verifies whether the key is acceptable
      connection->publicKeyOk = FALSE;

      //The client may send several authentication requests
      connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;

      //Continue processing
      error = NO_ERROR;
   }
   else
#endif
   //Password authentication method?
   {
      //The server has rejected the authentication request
      error = ERROR_AUTHENTICATION_FAILED;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse authentication method specific method messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
      //Different authentication methods reuse the same message numbers
      if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PUBLIC_KEY)
      {
         //Check message type
         if(type == SSH_MSG_USERAUTH_PK_OK)
         {
            //The server must respond to the SSH_MSG_USERAUTH_REQUEST message
            //with either SSH_MSG_USERAUTH_FAILURE or SSH_MSG_USERAUTH_PK_OK
            error = sshParseUserAuthPkOk(connection, message, length);
         }
         else
         {
            //Unknown message type
            error = ERROR_INVALID_TYPE;
         }
      }
      else
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
      //Password authentication?
      if(sshGetAuthMethod(connection) == SSH_AUTH_METHOD_PASSWORD)
      {
         //Check message type
         if(type == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
         {
            //Normally, the server responds to the SSH_MSG_USERAUTH_REQUEST
            //message with success or failure. However, if the password has
            //expired, the server should indicate this by responding with
            //SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
            error = sshParseUserAuthPasswdChangeReq(connection, message,
               length);
         }
         else
         {
            //Unknown message type
            error = ERROR_INVALID_TYPE;
         }
      }
      else
#endif
      //No authentication?
      {
         //Unknown message type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
   {
      //Method-specific messages are only sent by the server
      error = ERROR_UNEXPECTED_MESSAGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Get current authentication method
 * @return Authentication method (password or public key authentication)
 **/

SshAuthMethod sshGetAuthMethod(SshConnection *connection)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   SshAuthMethod authMethod;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Public key or password authentication method?
   if(connection->hostKeyIndex < SSH_MAX_HOST_KEYS)
   {
      authMethod = SSH_AUTH_METHOD_PUBLIC_KEY;
   }
   else if(context->password[0] != '\0')
   {
      authMethod = SSH_AUTH_METHOD_PASSWORD;
   }
   else
   {
      authMethod = SSH_AUTH_METHOD_NONE;
   }

   //Return the current authentication method
   return authMethod;
#else
   //Client operation mode is not implemented
   return SSH_AUTH_METHOD_NONE;
#endif
}

#endif
