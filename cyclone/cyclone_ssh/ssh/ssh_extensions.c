/**
 * @file ssh_extensions.c
 * @brief SSH extension negotiation
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
#include "ssh/ssh_extensions.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_EXT_INFO_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_EXT_INFO message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendExtInfo(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_EXT_INFO message
   error = sshFormatExtInfo(connection, message, &length);

   //Check status code
   if(!error)
   {
      //The implementation may send an SSH_MSG_EXT_INFO message but is not
      //required to do so (refer to RFC 8308, section 2.2)
      if(length > SSH_MSG_EXT_INFO_MIN_SIZE)
      {
         //Debug message
         TRACE_INFO("Sending SSH_MSG_EXT_INFO message (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_VERBOSE_ARRAY("  ", message, length);

         //Send message
         error = sshSendPacket(connection, message, length);
      }
   }

   //Check status code
   if(!error)
   {
      //Check whether SSH operates as a client or a server
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //If a client sends SSH_MSG_EXT_INFO, it must send it as the next
         //packet following the client's first SSH_MSG_NEWKEYS message
         connection->state = SSH_CONN_STATE_SERVER_NEW_KEYS;
      }
      else
      {
         //Check connection state
         if(connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_1)
         {
            //The server may send the SSH_MSG_EXT_INFO message as the next
            //packet following the server's first SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_CLIENT_NEW_KEYS;
         }
         else if(connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_2)
         {
            //The server may send the SSH_MSG_EXT_INFO message immediately
            //preceding the server's SSH_MSG_USERAUTH_SUCCESS message
            connection->state = SSH_CONN_STATE_USER_AUTH_SUCCESS;
         }
         else
         {
            //Just for sanity
            error = ERROR_WRONG_STATE;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_EXT_INFO message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] message Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatExtInfo(SshConnection *connection, uint8_t *message,
   size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   uint32_t nrExtensions;

   //Point to the first byte of the message
   p = message;
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_EXT_INFO;

   //Skip the nr-extensions field
   p += sizeof(uint8_t) + sizeof(uint32_t);
   *length += sizeof(uint8_t) + sizeof(uint32_t);

   //Calculate the number of extensions
   nrExtensions = 0;

#if (SSH_SERVER_SIG_ALGS_EXT_SUPPORT == ENABLED)
   //Server operation mode?
   if(connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_1)
   {
      //This extension is sent by the server and contains a list of public key
      //algorithms that the server is able to process as part of a "publickey"
      //authentication request
      error = sshFormatServerSigAlgsExt(connection, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      *length += n;

      //The "server-sig-algs" extension is present
      nrExtensions++;
   }
#endif

#if (SSH_GLOBAL_REQ_OK_EXT_SUPPORT == ENABLED)
   //Client or server operation mode?
   if(connection->state == SSH_CONN_STATE_CLIENT_EXT_INFO ||
      connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_1)
   {
      //If a remote party includes this extension in its SSH_MSG_EXT_INFO, then
      //the remote will handle global requests properly
      error = sshFormatGlobalRequestsOkExt(connection, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      *length += n;

      //The "global-requests-ok" extension is present
      nrExtensions++;
   }
#endif

   //The nr-extensions field specifies the number of extensions
   STORE32BE(nrExtensions, message + 1);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "server-sig-algs" extension
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatServerSigAlgsExt(SshConnection *connection, uint8_t *p,
   size_t *written)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total number of bytes that have been written
   *written = 0;

   //Format extension name
   error = sshFormatString("server-sig-algs", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //In this extension, a server must enumerate all public key algorithms it
   //might accept during user authentication (refer to RFC 8308, section 3.1)
   error = sshFormatPublicKeyAlgoList(connection->context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the extension
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format "global-requests-ok" extension
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatGlobalRequestsOkExt(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t n;

   //Total number of bytes that have been written
   *written = 0;

   //Format extension name
   error = sshFormatString("global-requests-ok", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The sender must send an empty extension value
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the extension
   *written += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_EXT_INFO message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseExtInfo(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint32_t i;
   const uint8_t *p;
   uint32_t nrExtensions;
   SshString extensionName;
   SshString extensionValue;

   //Debug message
   TRACE_INFO("SSH_MSG_EXT_INFO message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_SERVER_EXT_INFO_1 &&
         connection->state != SSH_CONN_STATE_SERVER_EXT_INFO_2)
      {
         //Report an error
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_CLIENT_EXT_INFO)
      {
         //Report an error
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //The nr-extensions field specifies the number of extensions
   nrExtensions = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse extensions
   for(i = 0; i < nrExtensions; i++)
   {
      //Decode extension name
      error = sshParseString(p, length, &extensionName);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + extensionName.length;
      length -= sizeof(uint32_t) + extensionName.length;

      //Decode extension value
      error = sshParseString(p, length, &extensionValue);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + extensionValue.length;
      length -= sizeof(uint32_t) + extensionValue.length;

#if (SSH_SERVER_SIG_ALGS_EXT_SUPPORT == ENABLED)
      //"server-sig-algs" extension?
      if(sshCompareString(&extensionName, "server-sig-algs"))
      {
         //In this extension, a server must enumerate all public key algorithms
         //it might accept during user authentication (refer to RFC 8308,
         //section 3.1)
         error = sshParseServerSigAlgsExt(connection, extensionValue.value,
            extensionValue.length);
      }
      else
#endif
#if (SSH_GLOBAL_REQ_OK_EXT_SUPPORT == ENABLED)
      //"global-requests-ok" extension?
      if(sshCompareString(&extensionName, "global-requests-ok"))
      {
         //If a remote party includes this extension in its SSH_MSG_EXT_INFO,
         //then the remote will handle global requests properly
         error = sshParseGlobalRequestsOkExt(connection, extensionValue.value,
            extensionValue.length);
      }
      else
#endif
      //Unkown extension?
      {
         //Applications must ignore unrecognized extension names (refer to
         //RFC 8308, section 2.5)
         error = NO_ERROR;
      }

      //Failed to parse extension?
      if(error)
         return error;
   }

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check connection state
      if(connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_1)
      {
         //The server may send the SSH_MSG_EXT_INFO message as the next packet
         //following the server's first SSH_MSG_NEWKEYS message
         connection->state = SSH_CONN_STATE_SERVICE_ACCEPT;
      }
      else
      {
         //The server may send the SSH_MSG_EXT_INFO message immediately
         //preceding the server's SSH_MSG_USERAUTH_SUCCESS message
         connection->state = SSH_CONN_STATE_USER_AUTH_SUCCESS;
      }
   }
   else
   {
      //If a client sends SSH_MSG_EXT_INFO, it must send it as the next packet
      //following the client's first SSH_MSG_NEWKEYS message
      connection->state = SSH_CONN_STATE_SERVICE_REQUEST;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "server-sig-algs" extension
 * @param[in] connection Pointer to the SSH connection
 * @param[in] p Pointer to extension value
 * @param[in] length Length of the extension value, in bytes
 * @return Error code
 **/

error_t sshParseServerSigAlgsExt(SshConnection *connection, const char_t *p,
   size_t length)
{
   error_t error;

#if (SSH_CLIENT_SUPPORT == ENABLED)
   //The "server-sig-algs" extension is sent by the server
   if(connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_1 ||
      connection->state == SSH_CONN_STATE_SERVER_EXT_INFO_2)
   {
      uint_t i;
      SshContext *context;
      SshHostKey *hostKey;
      SshNameList publicKeyAlgoList;

      //Point to the SSH context
      context = connection->context;

      //In this extension, a server must enumerate all public key algorithms
      //it might accept during user authentication
      publicKeyAlgoList.value = p;
      publicKeyAlgoList.length = length;

      //Loop through the client's host keys
      for(i = 0; i < SSH_MAX_HOST_KEYS; i++)
      {
         //Point to the current host key
         hostKey = &context->hostKeys[i];

         //Valid host key?
         if(hostKey->keyFormatId != NULL)
         {
            //Select the appropriate public key algorithm to use during user
            //authentication, rather than resorting to trial and error
            hostKey->publicKeyAlgo = sshSelectPublicKeyAlgo(context,
               hostKey->keyFormatId, &publicKeyAlgoList);
         }
      }

      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
   {
      //If a client sends this extension, the server may ignore it and may
      //disconnect (refer to RFC 8308, section 3.1)
      error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
         "Unexpected extension");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse "global-requests-ok" extension
 * @param[in] connection Pointer to the SSH connection
 * @param[in] p Pointer to extension value
 * @param[in] length Length of the extension value, in bytes
 * @return Error code
 **/

error_t sshParseGlobalRequestsOkExt(SshConnection *connection, const char_t *p,
   size_t length)
{
   //A receiver must tolerate and ignore non-printable binary characters in the
   //extension value. Future specifications may define meanings for this value
   return NO_ERROR;
}

#endif
