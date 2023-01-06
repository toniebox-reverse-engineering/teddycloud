/**
 * @file ssh_auth_password.c
 * @brief Password authentication method
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
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_PASSWORD_AUTH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] prompt  NULL-terminated string containing the prompt message
 * @return Error code
 **/

error_t sshSendUserAuthPasswdChangeReq(SshConnection *connection,
   const char_t *prompt)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message
   error = sshFormatUserAuthPasswdChangeReq(connection, prompt, message,
      &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message (%" PRIuSIZE " bytes)...\r\n", length);
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
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format "password" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the method specific fields
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatPasswordAuthParams(SshConnection *connection, uint8_t *p,
   size_t *written)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total number of bytes that have been written
   *written = 0;

   //Format method name
   error = sshFormatString("password", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the first method-specific field
   p += n;
   *written += n;

   //Format flag
   p[0] = FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *written += sizeof(uint8_t);

   //Format old password
   error = sshFormatString(connection->context->password, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the method specific fields
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] prompt  NULL-terminated string containing the prompt message
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUserAuthPasswdChangeReq(SshConnection *connection,
   const char_t *prompt, uint8_t *p, size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format prompt string
   error = sshFormatString(prompt, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format language tag
   error = sshFormatString("en", p, &n);
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
 * @brief Parse "password" method specific fields
 * @param[in] connection Pointer to the SSH connection
 * @param[in] userName Pointer to the user name
 * @param[in] p Pointer to method specific fields
 * @param[in] length Length of the method specific fields, in bytes
 * @return Error code
 **/

error_t sshParsePasswordAuthParams(SshConnection *connection,
   const SshString *userName, const uint8_t *p, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   SshBoolean flag;
   SshString oldPassword;
   SshString newPassword;
   SshAuthStatus status;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode flag
   flag = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Decode old password
   error = sshParseString(p, length, &oldPassword);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + oldPassword.length;
   length -= sizeof(uint32_t) + oldPassword.length;

   //Check the value of the flag
   if(flag)
   {
      //Decode new password
      error = sshParseString(p, length, &newPassword);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + newPassword.length;
      length -= sizeof(uint32_t) + newPassword.length;
   }
   else
   {
      //The new password field is not present
      newPassword.value = NULL;
      newPassword.length = 0;
   }

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

      //Invoke user-defined callback, if any
      if(context->passwordAuthCallback != NULL && !flag)
      {
         //The user requests password authentication
         status = context->passwordAuthCallback(connection, connection->user,
            oldPassword.value, oldPassword.length);
      }
      else if(context->passwordChangeCallback != NULL && flag)
      {
         //The user requests a password change
         status = context->passwordChangeCallback(connection,
            connection->user, oldPassword.value, oldPassword.length,
            newPassword.value, newPassword.length);
      }
      else
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

   //Successful authentication?
   if(status == SSH_AUTH_STATUS_SUCCESS)
   {
      //When the server accepts authentication, it must respond with an
      //SSH_MSG_USERAUTH_SUCCESS message
      error = sshAcceptAuthRequest(connection);
   }
   else if(status == SSH_AUTH_STATUS_PASSWORD_EXPIRED)
   {
      //Limit the number of authentication attempts
      if(connection->authAttempts <= SSH_MAX_AUTH_ATTEMPTS)
      {
         //If the password has expired, the server should respond with an
         //SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message
         error = sshSendUserAuthPasswdChangeReq(connection,
            connection->passwordChangePrompt);
      }
      else
      {
         //If the threshold is exceeded, the server should disconnect (refer
         //to RFC 4252, section 4)
         error = sshSendDisconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
            "Too many authentication attempts");
      }
   }
   else
   {
      //If the server rejects the authentication request, it must respond
      //with an SSH_MSG_USERAUTH_FAILURE message
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
 * @brief Parse SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUserAuthPasswdChangeReq(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString prompt;
   SshString languageTag;

   //Debug message
   TRACE_INFO("SSH_MSG_USERAUTH_PASSWD_CHANGEREQ message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode prompt string
   error = sshParseString(p, length, &prompt);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + prompt.length;
   length -= sizeof(uint32_t) + prompt.length;

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

   //The server sends an SSH_MSG_USERAUTH_PASSWD_CHANGEREQ to indicate that
   //the password has expired
   return ERROR_AUTHENTICATION_FAILED;
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}

#endif
