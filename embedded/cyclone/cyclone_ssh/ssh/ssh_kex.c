/**
 * @file ssh_kex.c
 * @brief SSH key exchange
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
#include "ssh/ssh_kex.h"
#include "ssh/ssh_kex_rsa.h"
#include "ssh/ssh_kex_dh.h"
#include "ssh/ssh_kex_dh_gex.h"
#include "ssh/ssh_kex_ecdh.h"
#include "ssh/ssh_kex_hbr.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_key_material.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_KEXINIT message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexInit(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Check whether a key re-exchange has been initiated by the peer
   if(connection->kexInitReceived)
   {
      //A new random cookie has already been generated
      error = NO_ERROR;
   }
   else
   {
      //Generate a random cookie
      error = context->prngAlgo->read(context->prngContext, connection->cookie,
         SSH_COOKIE_SIZE);

      //Debug message
      TRACE_DEBUG("  cookie =\r\n");
      TRACE_DEBUG_ARRAY("    ", connection->cookie, SSH_COOKIE_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEXINIT message
      error = sshFormatKexInit(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEXINIT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);

      //Check status code
      if(!error)
      {
         //An SSH_MSG_KEXINIT message has been successfully sent
         connection->kexInitSent = TRUE;

         //Check whether a key re-exchange has been initiated by the peer
         if(connection->kexInitReceived)
         {
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
            //RSA key exchange algorithm?
            if(sshIsRsaKexAlgo(connection->kexAlgo))
            {
               //The server sends an SSH_MSG_KEXRSA_PUBKEY message
               connection->state = SSH_CONN_STATE_KEX_RSA_PUB_KEY;
            }
            else
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED)
            //Diffie-Hellman key exchange algorithm?
            if(sshIsDhKexAlgo(connection->kexAlgo))
            {
               //The client sends an SSH_MSG_KEX_DH_INIT message
               connection->state = SSH_CONN_STATE_KEX_DH_INIT;
            }
            else
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
            //DH GEX key exchange algorithm?
            if(sshIsDhGexKexAlgo(connection->kexAlgo))
            {
               //The client sends an SSH_MSG_KEY_DH_GEX_REQUEST message
               connection->state = SSH_CONN_STATE_KEX_DH_GEX_REQUEST;
            }
            else
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED)
            //ECDH key exchange algorithm?
            if(sshIsEcdhKexAlgo(connection->kexAlgo))
            {
               //The client sends an SSH_MSG_KEX_ECDH_INIT message
               connection->state = SSH_CONN_STATE_KEX_ECDH_INIT;
            }
            else
#endif
#if (SSH_HBR_KEX_SUPPORT == ENABLED)
            //Post-quantum hybrid key exchange algorithm?
            if(sshIsHbrKexAlgo(connection->kexAlgo))
            {
               //The client sends an SSH_MSG_HBR_INIT message
               connection->state = SSH_CONN_STATE_KEX_HBR_INIT;
            }
            else
#endif
            //Unknown key exchange algorithm?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
            }
         }
         else
         {
            //Check whether SSH operates as a client or a server
            if(context->mode == SSH_OPERATION_MODE_CLIENT)
            {
               //Wait for the server's KEXINIT message
               connection->state = SSH_CONN_STATE_SERVER_KEX_INIT;
            }
            else
            {
               //Wait for the client's KEXINIT message
               connection->state = SSH_CONN_STATE_CLIENT_KEX_INIT;
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_NEWKEYS message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendNewKeys(SshConnection *connection)
{
   error_t error;
   uint8_t x;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_NEWKEYS message
   error = sshFormatNewKeys(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_NEWKEYS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Check whether SSH operates as a client or a server
      x = (connection->context->mode == SSH_OPERATION_MODE_CLIENT) ? 'A' : 'B';

      //Release encryption engine
      sshFreeEncryptionEngine(&connection->encryptionEngine);

      //The key exchange method specifies how one-time session keys are
      //generated for encryption and for authentication
      error = sshInitEncryptionEngine(connection, &connection->encryptionEngine,
         connection->serverEncAlgo, connection->serverMacAlgo, x);
   }

   //Check status code
   if(!error)
   {
      //An SSH_MSG_NEWKEYS message has been successfully sent
      connection->newKeysSent = TRUE;

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
      //If a server receives an "ext-info-c", or a client receives an
      //"ext-info-s", it may send an SSH_MSG_EXT_INFO message (refer to
      //RFC 8308, section 2.1)
      if(!connection->newKeysReceived && connection->extInfoReceived)
      {
         //Check whether SSH operates as a client or a server
         if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
         {
            //If a client sends SSH_MSG_EXT_INFO, it must send it as the next
            //packet following the client's first SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_CLIENT_EXT_INFO;
         }
         else
         {
            //The server may send the SSH_MSG_EXT_INFO message as the next packet
            //following the server's first SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_SERVER_EXT_INFO_1;
         }
      }
      else
#endif
      {
         //Check whether SSH operates as a client or a server
         if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
         {
            //Wait for the server's SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_SERVER_NEW_KEYS;
         }
         else
         {
            //Wait for the client's SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_CLIENT_NEW_KEYS;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_KEXINIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexInit(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEXINIT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //The cookie is a random value generated by the sender
   osMemcpy(p, connection->cookie, SSH_COOKIE_SIZE);

   //Point to the next field
   p += SSH_COOKIE_SIZE;
   *length += SSH_COOKIE_SIZE;

   //Format the list of key exchange algorithms
   error = sshFormatKexAlgoList(connection, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of host key algorithms
   error = sshFormatHostKeyAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of encryption algorithms (client to server)
   error = sshFormatEncAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of encryption algorithms (server to client)
   error = sshFormatEncAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of MAC algorithms (client to server)
   error = sshFormatMacAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of MAC algorithms (server to client)
   error = sshFormatMacAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of compression algorithms (client to server)
   error = sshFormatCompressionAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of compression algorithms (server to client)
   error = sshFormatCompressionAlgoList(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format the list of language tags (client to server)
   STORE32BE(0, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Format the list of language tags (server to client)
   STORE32BE(0, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //The first_kex_packet_follows field indicates whether a guessed key
   //exchange packet follows. If no guessed packet will be sent, this must
   //be FALSE (refer to RFC 4253, section 7.1)
   p[0] = FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //This field is reserved for future extension
   STORE32BE(0, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_NEWKEYS message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatNewKeys(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //The SSH_MSG_NEWKEYS message consists of a single byte
   p[0] = SSH_MSG_NEWKEYS;

   //Total length of the message
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_KEXINIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexInit(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   SshNameList nameList;
   SshNameList kexAlgoList;
   SshNameList hostKeyAlgoList;
   SshBoolean firstKexPacketFollows;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_KEXINIT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_SERVER_KEX_INIT &&
         connection->state != SSH_CONN_STATE_OPEN)
      {
         //Report an error
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_CLIENT_KEX_INIT &&
         connection->state != SSH_CONN_STATE_OPEN)
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
   n = length - sizeof(uint8_t);

   //Maformed message?
   if(length < SSH_COOKIE_SIZE)
      return ERROR_INVALID_MESSAGE;

   //Debug message
   TRACE_DEBUG("  cookie =\r\n");
   TRACE_DEBUG_ARRAY("    ", p, SSH_COOKIE_SIZE);

   //Point to the next field
   p += SSH_COOKIE_SIZE;
   n -= SSH_COOKIE_SIZE;

   //Decode the kex_algorithms field
   error = sshParseNameList(p, n, &kexAlgoList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  kex_algorithms =\r\n");
   TRACE_DEBUG("%s\r\n\r\n", kexAlgoList.value);

   //Select key exchange algorithm
   connection->kexAlgo = sshSelectKexAlgo(connection, &kexAlgoList);
   //No matching algorithm found?
   if(connection->kexAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   p += sizeof(uint32_t) + kexAlgoList.length;
   n -= sizeof(uint32_t) + kexAlgoList.length;

   //Decode the server_host_key_algorithms field
   error = sshParseNameList(p, n, &hostKeyAlgoList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  server_host_key_algorithms =\r\n");
   TRACE_DEBUG("%s\r\n\r\n", hostKeyAlgoList.value);

   //Select host key algorithm
   connection->serverHostKeyAlgo = sshSelectHostKeyAlgo(context,
      &hostKeyAlgoList);
   //No matching algorithm found?
   if(connection->serverHostKeyAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Server operation mode?
   if(context->mode == SSH_OPERATION_MODE_SERVER)
   {
      //Select the host key to use
      connection->hostKeyIndex = sshSelectHostKey(context,
         connection->serverHostKeyAlgo);

      //No matching host key found?
      if(connection->hostKeyIndex < 0)
         return ERROR_UNSUPPORTED_ALGO;
   }

   //Point to the next field
   p += sizeof(uint32_t) + hostKeyAlgoList.length;
   n -= sizeof(uint32_t) + hostKeyAlgoList.length;

   //Decode the encryption_algorithms_client_to_server field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  encryption_algorithms_client_to_server =\r\n");
   TRACE_DEBUG("%s\r\n\r\n", nameList.value);

   //Select encryption algorithm (client to server)
   connection->clientEncAlgo = sshSelectEncAlgo(context, &nameList);
   //No matching algorithm found?
   if(connection->clientEncAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the encryption_algorithms_server_to_client field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  encryption_algorithms_server_to_client =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Select encryption algorithm (server to client)
   connection->serverEncAlgo = sshSelectEncAlgo(context, &nameList);
   //No matching algorithm found?
   if(connection->serverEncAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the mac_algorithms_client_to_server field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  mac_algorithms_client_to_server =\r\n");
   TRACE_DEBUG("%s\r\n\r\n", nameList.value);

   //Select MAC algorithm (client to server)
   connection->clientMacAlgo = sshSelectMacAlgo(context,
      connection->clientEncAlgo, &nameList);
   //No matching algorithm found?
   if(connection->clientMacAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

#if (SSH_RFC5647_SUPPORT == ENABLED)
   //If AES-GCM is selected as the MAC algorithm, it must also be selected as
   //the encryption algorithm (refer to RFC 5647, section 5.1)
   if(sshCompareAlgo(connection->clientMacAlgo, "AEAD_AES_128_GCM") ||
      sshCompareAlgo(connection->clientMacAlgo, "AEAD_AES_256_GCM") ||
      sshCompareAlgo(connection->clientMacAlgo, "AEAD_CAMELLIA_128_GCM") ||
      sshCompareAlgo(connection->clientMacAlgo, "AEAD_CAMELLIA_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      connection->clientEncAlgo = connection->clientMacAlgo;
   }
#endif

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the mac_algorithms_server_to_client field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  mac_algorithms_server_to_client =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Select MAC algorithm (server to client)
   connection->serverMacAlgo = sshSelectMacAlgo(context,
      connection->serverEncAlgo, &nameList);
   //No matching algorithm found?
   if(connection->serverMacAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

#if (SSH_RFC5647_SUPPORT == ENABLED)
   //If AES-GCM is selected as the MAC algorithm, it must also be selected as
   //the encryption algorithm (refer to RFC 5647, section 5.1)
   if(sshCompareAlgo(connection->serverMacAlgo, "AEAD_AES_128_GCM") ||
      sshCompareAlgo(connection->serverMacAlgo, "AEAD_AES_256_GCM") ||
      sshCompareAlgo(connection->serverMacAlgo, "AEAD_CAMELLIA_128_GCM") ||
      sshCompareAlgo(connection->serverMacAlgo, "AEAD_CAMELLIA_256_GCM"))
   {
      //AEAD algorithms offer both encryption and authentication
      connection->serverEncAlgo = connection->serverMacAlgo;
   }
#endif

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the compression_algorithms_client_to_server field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  compression_algorithms_client_to_server =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Select compression algorithm (client to server)
   connection->clientCompressAlgo = sshSelectCompressionAlgo(context,
      &nameList);
   //No matching algorithm found?
   if(connection->clientCompressAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the compression_algorithms_server_to_client field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  compression_algorithms_server_to_client =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Select compression algorithm (server to client)
   connection->serverCompressAlgo = sshSelectCompressionAlgo(context,
      &nameList);
   //No matching algorithm found?
   if(connection->serverCompressAlgo == NULL)
      return ERROR_UNSUPPORTED_ALGO;

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the languages_client_to_server field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  languages_client_to_server =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Decode the languages_server_to_client field
   error = sshParseNameList(p, n, &nameList);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_VERBOSE("  languages_server_to_client =\r\n");
   TRACE_VERBOSE("%s\r\n\r\n", nameList.value);

   //Point to the next field
   p += sizeof(uint32_t) + nameList.length;
   n -= sizeof(uint32_t) + nameList.length;

   //Malformed message?
   if(n < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Retrieve the value of the first_kex_packet_follows field
   firstKexPacketFollows = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   n -= sizeof(uint8_t);

   //Malformed message?
   if(n < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Ignore the reserved field
   p += sizeof(uint32_t);
   n -= sizeof(uint32_t);

   //Malformed message?
   if(n != 0)
      return ERROR_INVALID_MESSAGE;

   //An SSH_MSG_KEXINIT message has been successfully received
   connection->kexInitReceived = TRUE;

   //Debug message
   TRACE_INFO("  Selected kex algo = %s\r\n", connection->kexAlgo);
   TRACE_INFO("  Selected server host key algo = %s\r\n", connection->serverHostKeyAlgo);
   TRACE_INFO("  Selected client enc algo = %s\r\n", connection->clientEncAlgo);
   TRACE_INFO("  Selected client mac algo = %s\r\n", connection->clientMacAlgo);
   TRACE_INFO("  Selected server enc algo = %s\r\n", connection->serverEncAlgo);
   TRACE_INFO("  Selected server mac algo = %s\r\n", connection->serverMacAlgo);

   //The first_kex_packet_follows field indicates whether a guessed key
   //exchange packet follows
   if(firstKexPacketFollows)
   {
      //The guess is considered wrong if the key exchange algorithm or the host
      //key algorithm is guessed wrong (refer to RFC 4253, section 7)
      if(!sshIsGuessCorrect(context, &kexAlgoList, &hostKeyAlgoList))
      {
         //If the other party's guess was wrong, the next packet must be
         //silently ignored, and both sides must then act as determined by
         //the negotiated key exchange method
         connection->wrongGuess = TRUE;
      }
      else
      {
         //If the guess was right, key exchange must continue using the guessed
         //packet
         connection->wrongGuess = FALSE;
      }
   }
   else
   {
      //No guessed packet will be sent
      connection->wrongGuess = FALSE;
   }

   //Initialize exchange hash H
   error = sshInitExchangeHash(connection);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with V_C (client's identification string)
   error = sshUpdateExchangeHash(connection, connection->clientId,
      osStrlen(connection->clientId));
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with V_S (server's identification string)
   error = sshUpdateExchangeHash(connection, connection->serverId,
      osStrlen(connection->serverId));
   //Any error to report?
   if(error)
      return error;

   //Check whether a key re-exchange has been initiated by the peer
   if(!connection->kexInitSent)
   {
      //Generate a random cookie
      error = context->prngAlgo->read(context->prngContext, connection->cookie,
         SSH_COOKIE_SIZE);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("  cookie =\r\n");
      TRACE_DEBUG_ARRAY("    ", connection->cookie, SSH_COOKIE_SIZE);
   }

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Update exchange hash H with I_C (payload of the client's SSH_MSG_KEXINIT)
      error = sshDigestClientKexInit(connection);
      //Any error to report?
      if(error)
         return error;

      //Update exchange hash H with I_S (payload of the server's SSH_MSG_KEXINIT)
      error = sshUpdateExchangeHash(connection, message, length);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //Update exchange hash H with I_C (payload of the client's SSH_MSG_KEXINIT)
      error = sshUpdateExchangeHash(connection, message, length);
      //Any error to report?
      if(error)
         return error;

      //Format SSH_MSG_KEXINIT message
      error = sshFormatKexInit(connection, connection->buffer, &n);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_VERBOSE_ARRAY("I_S = ", connection->buffer, n);

      //Update exchange hash H with I_S (payload of the server's SSH_MSG_KEXINIT)
      error = sshUpdateExchangeHash(connection, connection->buffer, n);
      //Any error to report?
      if(error)
         return error;

      //Format server's public host key
      error = sshFormatHostKey(connection, connection->buffer, &n);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_VERBOSE_ARRAY("K_S = ", connection->buffer, n);

      //Update exchange hash H with K_S (server's public host key)
      error = sshUpdateExchangeHash(connection, connection->buffer, n);
      //Any error to report?
      if(error)
         return error;
   }

   //Check whether a key re-exchange has been initiated by the peer
   if(!connection->kexInitSent)
   {
      //Either party may initiate the re-exchange by sending an SSH_MSG_KEXINIT
      //message. When this message is received, a party must respond with its
      //own SSH_MSG_KEXINIT message (refer to RFC 4253, section 9)
      if(context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //The client responds with a KEXINIT message
         connection->state = SSH_CONN_STATE_CLIENT_KEX_INIT;
      }
      else
      {
         //The server responds with a KEXINIT message
         connection->state = SSH_CONN_STATE_SERVER_KEX_INIT;
      }
   }
   else
   {
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
      //RSA key exchange algorithm?
      if(sshIsRsaKexAlgo(connection->kexAlgo))
      {
         //The server sends an SSH_MSG_KEXRSA_PUBKEY message
         connection->state = SSH_CONN_STATE_KEX_RSA_PUB_KEY;
      }
      else
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED)
      //Diffie-Hellman key exchange algorithm?
      if(sshIsDhKexAlgo(connection->kexAlgo))
      {
         //The client sends an SSH_MSG_KEX_DH_INIT message
         connection->state = SSH_CONN_STATE_KEX_DH_INIT;
      }
      else
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
      //DH GEX key exchange algorithm?
      if(sshIsDhGexKexAlgo(connection->kexAlgo))
      {
         //The client sends an SSH_MSG_KEY_DH_GEX_REQUEST message
         connection->state = SSH_CONN_STATE_KEX_DH_GEX_REQUEST;
      }
      else
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED)
      //ECDH key exchange algorithm?
      if(sshIsEcdhKexAlgo(connection->kexAlgo))
      {
         //The client sends an SSH_MSG_KEX_ECDH_INIT message
         connection->state = SSH_CONN_STATE_KEX_ECDH_INIT;
      }
      else
#endif
#if (SSH_HBR_KEX_SUPPORT == ENABLED)
      //Post-quantum hybrid key exchange algorithm?
      if(sshIsHbrKexAlgo(connection->kexAlgo))
      {
         //The client sends an SSH_MSG_HBR_INIT message
         connection->state = SSH_CONN_STATE_KEX_HBR_INIT;
      }
      else
#endif
      //Unknown key exchange algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_NEWKEYS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseNewKeys(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint8_t x;

   //Debug message
   TRACE_INFO("SSH_MSG_NEWKEYS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_SERVER_NEW_KEYS)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Check connection state
      if(connection->state != SSH_CONN_STATE_CLIENT_NEW_KEYS)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //The SSH_MSG_NEWKEYS message consists of a single byte
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Check whether SSH operates as a client or a server
   x = (connection->context->mode == SSH_OPERATION_MODE_CLIENT) ? 'B' : 'A';

   //Release decryption engine
   sshFreeEncryptionEngine(&connection->decryptionEngine);

   //The key exchange method specifies how one-time session keys are generated
   //for encryption and for authentication
   error = sshInitEncryptionEngine(connection, &connection->decryptionEngine,
      connection->clientEncAlgo, connection->clientMacAlgo, x);

   //Check status code
   if(!error)
   {
      //Key re-exchange?
      if(connection->newKeysReceived)
      {
         //Either party may later initiate a key re-exchange by sending a
         //SSH_MSG_KEXINIT message
         connection->kexInitSent = FALSE;
         connection->kexInitReceived = FALSE;

         //The SSH_MSG_USERAUTH_SUCCESS message must be sent only once. When
         //SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication
         //requests received after that should be silently ignored
         connection->state = SSH_CONN_STATE_OPEN;
      }
      else
      {
         //An SSH_MSG_NEWKEYS message has been successfully received
         connection->newKeysReceived = TRUE;

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
         //Server operation mode?
         if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
         {
            //If a client sends SSH_MSG_EXT_INFO, it must send it as the next
            //packet following the client's first SSH_MSG_NEWKEYS message
            connection->state = SSH_CONN_STATE_CLIENT_EXT_INFO;
         }
         else
#endif
         {
            //After the key exchange, the client requests a service
            connection->state = SSH_CONN_STATE_SERVICE_REQUEST;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse key exchange method-specific messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

   //Check if the other party's guess was wrong
   if(connection->wrongGuess)
   {
      //Debug message
      TRACE_INFO("Discarding wrong guessed packet(%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //If the guess was wrong, the packet must be silently ignored and both
      //sides must then act as determined by the negotiated key exchange method
      connection->wrongGuess = FALSE;

      //Continue processing
      error = NO_ERROR;
   }
   else
   {
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
      //RSA key exchange algorithm?
      if(sshIsRsaKexAlgo(connection->kexAlgo))
      {
         //Parse RSA specific messages
         error = sshParseKexRsaMessage(connection, type, message, length);
      }
      else
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED)
      //Diffie-Hellman key exchange algorithm?
      if(sshIsDhKexAlgo(connection->kexAlgo))
      {
         //Parse Diffie-Hellman specific messages
         error = sshParseKexDhMessage(connection, type, message, length);
      }
      else
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
      //DH GEX key exchange algorithm?
      if(sshIsDhGexKexAlgo(connection->kexAlgo))
      {
         //Parse Diffie-Hellman Group Exchange specific messages
         error = sshParseKexDhGexMessage(connection, type, message, length);
      }
      else
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED)
      //ECDH key exchange algorithm?
      if(sshIsEcdhKexAlgo(connection->kexAlgo))
      {
         //Parse ECDH specific messages
         error = sshParseKexEcdhMessage(connection, type, message, length);
      }
      else
#endif
#if (SSH_HBR_KEX_SUPPORT == ENABLED)
      //Post-quantum hybrid key exchange algorithm?
      if(sshIsHbrKexAlgo(connection->kexAlgo))
      {
         //Parse PQ-hybrid specific messages
         error = sshParseHbrMessage(connection, type, message, length);
      }
      else
#endif
      //Unknown key exchange algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Update exchange hash with client's SSH_MSG_KEXINIT message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshDigestClientKexInit(SshConnection *connection)
{
   error_t error;
   size_t n;
   uint8_t *buffer;

   //Allocate a temporary buffer
   buffer = sshAllocMem(SSH_BUFFER_SIZE);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Format SSH_MSG_KEXINIT message
      error = sshFormatKexInit(connection, buffer, &n);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_VERBOSE_ARRAY("I_C = ", buffer, n);

         //Update exchange hash H with I_C (payload of the client's
         //SSH_MSG_KEXINIT)
         error = sshUpdateExchangeHash(connection, buffer, n);
      }

      //Release previously allocated memory
      sshFreeMem(buffer);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}

#endif
