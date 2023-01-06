/**
 * @file ssh_kex_dh_gex.c
 * @brief DH GEX (Diffie-Hellman Group Exchange) key exchange
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
#include "ssh/ssh_kex.h"
#include "ssh/ssh_kex_dh_gex.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_DH_GEX_KEX_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_KEX_DH_GEX_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexDhGexRequest(SshConnection *connection)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_KEX_DH_GEX_REQUEST message
   error = sshFormatKexDhGexRequest(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_DH_GEX_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The server responds with an SSH_MSG_KEX_DH_GEX_GROUP message
      connection->state = SSH_CONN_STATE_KEX_DH_GEX_GROUP;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEX_DH_GEX_GROUP message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexDhGexGroup(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;
   SshContext *context;
   SshDhGexGroup *dhGexGroup;

   //Point to the SSH context
   context = connection->context;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Valid Diffie-Hellman group?
   if(connection->dhGexGroupIndex >= 0)
   {
      //Point to the selected group
      dhGexGroup = &context->dhGexGroups[connection->dhGexGroupIndex];

      //Decode the PEM structure that holds Diffie-Hellman parameters
      error = pemImportDhParameters(dhGexGroup->dhParams,
         dhGexGroup->dhParamsLen, &connection->dhContext.params);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_GROUP;
   }

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEX_DH_GEX_GROUP message
      error = sshFormatKexDhGexGroup(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_DH_GEX_GROUP message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The client responds with an SSH_MSG_KEX_DH_GEX_INIT message
      connection->state = SSH_CONN_STATE_KEX_DH_GEX_INIT;
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEX_DH_GEX_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexDhGexInit(SshConnection *connection)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Generate an ephemeral key pair
   error = dhGenerateKeyPair(&connection->dhContext, context->prngAlgo,
      context->prngContext);

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEX_DH_GEX_INIT message
      error = sshFormatKexDhGexInit(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_DH_GEX_INIT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The server responds with an SSH_MSG_KEX_DH_GEX_REPLY message
      connection->state = SSH_CONN_STATE_KEX_DH_GEX_REPLY;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEX_DH_GEX_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexDhGexReply(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Generate an ephemeral key pair
   error = dhGenerateKeyPair(&connection->dhContext, context->prngAlgo,
      context->prngContext);

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEX_DH_GEX_REPLY message
      error = sshFormatKexDhGexReply(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_DH_GEX_REPLY message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Key exchange ends by each side sending an SSH_MSG_NEWKEYS message
      connection->state = SSH_CONN_STATE_SERVER_NEW_KEYS;
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_DH_GEX_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexDhGexRequest(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_DH_GEX_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Minimal size in bits of an acceptable group (min)
   STORE32BE(SSH_MIN_DH_MODULUS_SIZE, p);
   //Preferred size in bits of the group the server will send (n)
   STORE32BE(SSH_PREFERRED_DH_MODULUS_SIZE, p + 4);
   //Maximal size in bits of an acceptable group (max)
   STORE32BE(SSH_MAX_DH_MODULUS_SIZE, p + 8);

   //Total length of the packet
   *length += 3 * sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_DH_GEX_GROUP message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexDhGexGroup(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_DH_GEX_GROUP;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format safe prime (p)
   error = sshFormatMpint(&connection->dhContext.params.p, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with p (safe prime)
   error = sshUpdateExchangeHashRaw(connection, p, n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format generator (g)
   error = sshFormatMpint(&connection->dhContext.params.g, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with g (generator for subgroup)
   error = sshUpdateExchangeHashRaw(connection, p, n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   *length += n;

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_DH_GEX_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexDhGexInit(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_DH_GEX_INIT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format client's ephemeral public key
   error = sshFormatMpint(&connection->dhContext.ya, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_DH_GEX_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexDhGexReply(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_DH_GEX_REPLY;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format server's public host key (K_S)
   error = sshFormatHostKey(connection, p + sizeof(uint32_t), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   *length += sizeof(uint32_t) + n;

   //Format server's ephemeral public key (f)
   error = sshFormatMpint(&connection->dhContext.ya, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with f (exchange value sent by the server)
   error = sshUpdateExchangeHashRaw(connection, p, n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Compute the shared secret K
   error = sshComputeDhGexSharedSecret(connection);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with K (shared secret)
   error = sshUpdateExchangeHashRaw(connection, connection->k,
      connection->kLen);
   //Any error to report?
   if(error)
      return error;

   //Compute the signature on the exchange hash
   error = sshGenerateExchangeHashSignature(connection, p + sizeof(uint32_t),
      &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + n;

   //The ephemeral private key shall be destroyed as soon as possible (refer
   //to RFC 9212, section 6)
   dhFree(&connection->dhContext);
   dhInit(&connection->dhContext);

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_DH_GEX_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   uint32_t minDhModulusSize;
   uint32_t preferredDhModulusSize;
   uint32_t maxDhModulusSize;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_DH_GEX_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_DH_GEX_REQUEST)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != (3 * sizeof(uint32_t)))
      return ERROR_INVALID_MESSAGE;

   //Minimal size in bits of an acceptable group
   minDhModulusSize = LOAD32BE(p);
   //Preferred size in bits of the group the server will send
   preferredDhModulusSize = LOAD32BE(p + 4);
   //Maximal size in bits of an acceptable group
   maxDhModulusSize = LOAD32BE(p + 8);

   //Debug message
   TRACE_DEBUG("  min = %" PRIu32 "\r\n", minDhModulusSize);
   TRACE_DEBUG("  n = %" PRIu32 "\r\n", preferredDhModulusSize);
   TRACE_DEBUG("  max = %" PRIu32 "\r\n", maxDhModulusSize);

   //The server finds a group that best matches the client's request (refer
   //to RFC 4419, section 3)
   connection->dhGexGroupIndex = sshSelectDhGexGroup(connection->context,
      minDhModulusSize, preferredDhModulusSize, maxDhModulusSize);

   //No Diffie-Hellman group found?
   if(connection->dhGexGroupIndex < 0)
      return ERROR_INVALID_GROUP;

   //Update exchange hash H with min, n and max
   error = sshUpdateExchangeHashRaw(connection, p, length);
   //Any error to report?
   if(error)
      return error;

   //The server responds with an SSH_MSG_KEX_DH_GEX_GROUP message
   return sshSendKexDhGexGroup(connection);
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_DH_GEX_REQUEST_OLD message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexRequestOld(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   uint32_t preferredDhModulusSize;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_DH_GEX_REQUEST_OLD message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_DH_GEX_REQUEST)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //SSH_MSG_KEX_DH_GEX_REQUEST_OLD is used for backward compatibility.
   //Instead of sending min, n and max, the client only sends n (refer to
   //RFC 4419, section 5)
   preferredDhModulusSize = LOAD32BE(p);

   //Debug message
   TRACE_DEBUG("  n = %" PRIu32 "\r\n", preferredDhModulusSize);

   //The server finds a group that best matches the client's request (refer
   //to RFC 4419, section 3)
   connection->dhGexGroupIndex = sshSelectDhGexGroup(connection->context,
      SSH_MIN_DH_MODULUS_SIZE, preferredDhModulusSize, SSH_MAX_DH_MODULUS_SIZE);

   //No Diffie-Hellman group found?
   if(connection->dhGexGroupIndex < 0)
      return ERROR_INVALID_GROUP;

   //The hash is calculated using only n instead of min, n and max (refer to
   //RFC 4419, section 5)
   error = sshUpdateExchangeHashRaw(connection, p, length);
   //Any error to report?
   if(error)
      return error;

   //The server responds with an SSH_MSG_KEX_DH_GEX_GROUP message
   return sshSendKexDhGexGroup(connection);
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_DH_GEX_GROUP message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexGroup(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   const uint8_t *p;
   SshBinaryString prime;
   SshBinaryString generator;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_DH_GEX_GROUP message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_DH_GEX_GROUP)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode safe prime (p)
   error = sshParseBinaryString(p, length, &prime);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + prime.length;
   length -= sizeof(uint32_t) + prime.length;

   //Decode generator (g)
   error = sshParseBinaryString(p, length, &generator);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + generator.length;
   length -= sizeof(uint32_t) + generator.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Convert the prime modulus to a multiple precision integer
   error = mpiImport(&connection->dhContext.params.p, prime.value,
      prime.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the prime modulus, in bits
   k = mpiGetBitLength(&connection->dhContext.params.p);

   //Make sure the prime modulus is acceptable
   if(k < SSH_MIN_DH_MODULUS_SIZE || k > SSH_MAX_DH_MODULUS_SIZE)
      return ERROR_INVALID_GROUP;

   //Convert the generator to a multiple precision integer
   error = mpiImport(&connection->dhContext.params.g, generator.value,
      generator.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The client responds with an SSH_MSG_KEX_DH_GEX_INIT message
   return sshSendKexDhGexInit(connection);
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_DH_GEX_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexInit(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshBinaryString publicKey;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_DH_GEX_INIT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_DH_GEX_INIT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode client's ephemeral public key (e)
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

   //Update exchange hash H with e (exchange value sent by the client)
   error = sshUpdateExchangeHash(connection, publicKey.value,
      publicKey.length);
   //Any error to report?
   if(error)
      return error;

   //Load client's ephemeral public key
   error = mpiImport(&connection->dhContext.yb, publicKey.value,
      publicKey.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Ensure the public key is acceptable
   error = dhCheckPublicKey(&connection->dhContext.params,
      &connection->dhContext.yb);
   //Any error to report?
   if(error)
      return error;

   //The server responds with an SSH_MSG_KEX_DH_GEX_REPLY message
   return sshSendKexDhGexReply(connection);
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_DH_GEX_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexReply(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString hostKeyAlgo;
   SshBinaryString hostKey;
   SshBinaryString publicKey;
   SshBinaryString signature;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_DH_GEX_REPLY message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_DH_GEX_REPLY)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode server's public host key (K_S)
   error = sshParseBinaryString(p, length, &hostKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + hostKey.length;
   length -= sizeof(uint32_t) + hostKey.length;

   //Decode server's ephemeral public key (f)
   error = sshParseBinaryString(p, length, &publicKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + publicKey.length;
   length -= sizeof(uint32_t) + publicKey.length;

   //Decode the signature field
   error = sshParseBinaryString(p, length, &signature);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signature.length;
   length -= sizeof(uint32_t) + signature.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Get the selected server's host key algorithm
   hostKeyAlgo.value = connection->serverHostKeyAlgo;
   hostKeyAlgo.length = osStrlen(connection->serverHostKeyAlgo);

#if (SSH_CERT_SUPPORT == ENABLED)
   //Certificate-based authentication?
   if(sshIsCertPublicKeyAlgo(&hostKeyAlgo))
   {
      //Verify server's certificate
      error = sshVerifyServerCertificate(connection, &hostKeyAlgo, &hostKey);
   }
   else
#endif
   {
      //Verify server's host key
      error = sshVerifyServerHostKey(connection, &hostKeyAlgo, &hostKey);
   }

   //If the client fails to verify the server's host key, it should disconnect
   //from the server by sending an SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE message
   if(error)
      return ERROR_INVALID_KEY;

   //Update exchange hash H with K_S (server's public host key)
   error = sshUpdateExchangeHash(connection, hostKey.value, hostKey.length);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with min, n, max, p, g and e
   error = sshDigestDhGexParams(connection);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with f (exchange value sent by the server)
   error = sshUpdateExchangeHash(connection, publicKey.value, publicKey.length);
   //Any error to report?
   if(error)
      return error;

   //Load server's ephemeral public key
   error = mpiImport(&connection->dhContext.yb, publicKey.value,
      publicKey.length, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Ensure the public key is acceptable
   error = dhCheckPublicKey(&connection->dhContext.params,
      &connection->dhContext.yb);
   //Any error to report?
   if(error)
      return error;

   //Compute the shared secret K
   error = sshComputeDhGexSharedSecret(connection);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with K (shared secret)
   error = sshUpdateExchangeHashRaw(connection, connection->k,
      connection->kLen);
   //Any error to report?
   if(error)
      return error;

   //Verify the signature on the exchange hash
   error = sshVerifyExchangeHashSignature(connection, &hostKey, &signature);
   //Any error to report?
   if(error)
      return error;

   //The ephemeral private key shall be destroyed as soon as possible (refer
   //to RFC 9212, section 6)
   dhFree(&connection->dhContext);
   dhInit(&connection->dhContext);

   //Key exchange ends by each side sending an SSH_MSG_NEWKEYS message
   return sshSendNewKeys(connection);
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse Diffie-Hellman Group Exchange specific messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexDhGexMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check message type
      if(type == SSH_MSG_KEX_DH_GEX_GROUP)
      {
         //Parse SSH_MSG_KEX_DH_GEX_GROUP message
         error = sshParseKexDhGexGroup(connection, message, length);
      }
      else if(type == SSH_MSG_KEX_DH_GEX_REPLY)
      {
         //Parse SSH_MSG_KEX_DH_GEX_REPLY message
         error = sshParseKexDhGexReply(connection, message, length);
      }
      else
      {
         //Unknown message type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
#endif
#if (SSH_SERVER_SUPPORT == ENABLED)
   //Server operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
   {
      //Check message type
      if(type == SSH_MSG_KEX_DH_GEX_REQUEST)
      {
         //Parse SSH_MSG_KEX_DH_GEX_REQUEST message
         error = sshParseKexDhGexRequest(connection, message, length);
      }
      else if(type == SSH_MSG_KEX_DH_GEX_REQUEST_OLD)
      {
         //Parse SSH_MSG_KEX_DH_GEX_REQUEST_OLD message
         error = sshParseKexDhGexRequestOld(connection, message, length);
      }
      else if(type == SSH_MSG_KEX_DH_GEX_INIT)
      {
         //Parse SSH_MSG_KEX_DH_GEX_INIT message
         error = sshParseKexDhGexInit(connection, message, length);
      }
      else
      {
         //Unknown message type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
#endif
   //Invalid operation mode?
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Select a Diffie-Hellman group that best matches client's request
 * @param[in] context Pointer to the SSH context
 * @param[in] minDhModulusSize Minimum acceptable size for Diffie-Hellman prime modulus
 * @param[in] preferredDhModulusSize Preferred size for Diffie-Hellman prime modulus
 * @param[in] maxDhModulusSize Maximum acceptable size for Diffie-Hellman prime modulus
 * @return Index of the selected Diffie-Hellman group, if any
 **/

int_t sshSelectDhGexGroup(SshContext *context, uint32_t minDhModulusSize,
   uint32_t preferredDhModulusSize, uint32_t maxDhModulusSize)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   uint_t i;
   uint32_t a;
   uint32_t b;
   int_t bestIndex;
   const SshDhGexGroup *group;
   const SshDhGexGroup *bestGroup;

   //Initialize index
   bestIndex = -1;
   bestGroup = NULL;

   //Loop through the Diffie-Hellman groups
   for(i = 0; i < SSH_MAX_DH_GEX_GROUPS; i++)
   {
      //Point to the current group
      group = &context->dhGexGroups[i];

      //Valid prime modulus?
      if(group->dhModulusSize >= SSH_MIN_DH_MODULUS_SIZE &&
         group->dhModulusSize <= SSH_MAX_DH_MODULUS_SIZE)
      {
         //Check whether the current group is acceptable
         if(group->dhModulusSize >= minDhModulusSize &&
            group->dhModulusSize <= maxDhModulusSize)
         {
            //Select the group that best matches client's request
            if(bestIndex < 0 || bestGroup == NULL)
            {
               bestIndex = i;
               bestGroup = group;
            }
            else
            {
               //The client indicates the preferred size
               if(group->dhModulusSize > preferredDhModulusSize)
               {
                  a = group->dhModulusSize - preferredDhModulusSize;
               }
               else
               {
                  a = preferredDhModulusSize - group->dhModulusSize;
               }

               if(bestGroup->dhModulusSize > preferredDhModulusSize)
               {
                  b = bestGroup->dhModulusSize - preferredDhModulusSize;
               }
               else
               {
                  b = preferredDhModulusSize - bestGroup->dhModulusSize;
               }

               if(a < b)
               {
                  bestIndex = i;
                  bestGroup = group;
               }
            }
         }
      }
   }

   //Return the index of the Diffie-Hellman group
   return bestIndex;
#else
   //Server operation mode is not implemented
   return NULL;
#endif
}


/**
 * @brief Diffie-Hellman shared secret calculation
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshComputeDhGexSharedSecret(SshConnection *connection)
{
   error_t error;

   //Compute the shared secret K
   error = dhComputeSharedSecret(&connection->dhContext, connection->k,
      SSH_MAX_SHARED_SECRET_LEN - SSH_MAX_MPINT_OVERHEAD, &connection->kLen);

   //Check status code
   if(!error)
   {
      //Convert the shared secret K to mpint representation
      error = sshConvertArrayToMpint(connection->k, connection->kLen,
         connection->k, &connection->kLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Update exchange hash with min, n, max, p, g and e
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshDigestDhGexParams(SshConnection *connection)
{
   error_t error;
   size_t n;
   uint8_t *buffer;

   //Allocate a temporary buffer
   buffer = sshAllocMem(SSH_BUFFER_SIZE);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Minimal size in bits of an acceptable group (min)
      STORE32BE(SSH_MIN_DH_MODULUS_SIZE, buffer);
      //Preferred size in bits of the group the server will send (n)
      STORE32BE(SSH_PREFERRED_DH_MODULUS_SIZE, buffer + 4);
      //Maximal size in bits of an acceptable group (max)
      STORE32BE(SSH_MAX_DH_MODULUS_SIZE, buffer + 8);

      //Update exchange hash H with min, n and max
      error = sshUpdateExchangeHashRaw(connection, buffer, 3 * sizeof(uint32_t));

      //Check status code
      if(!error)
      {
         //Format Diffie-Hellman prime modulus
         error = sshFormatMpint(&connection->dhContext.params.p, buffer, &n);
      }

      //Check status code
      if(!error)
      {
         //Update exchange hash H with p (safe prime)
         error = sshUpdateExchangeHashRaw(connection, buffer, n);
      }

      //Check status code
      if(!error)
      {
         //Format Diffie-Hellman generator
         error = sshFormatMpint(&connection->dhContext.params.g, buffer, &n);
      }

      //Check status code
      if(!error)
      {
         //Update exchange hash H with g (generator for subgroup)
         error = sshUpdateExchangeHashRaw(connection, buffer, n);
      }

      //Check status code
      if(!error)
      {
         //Format client's ephemeral public key
         error = sshFormatMpint(&connection->dhContext.ya, buffer, &n);
      }

      //Check status code
      if(!error)
      {
         //Update exchange hash H with e (exchange value sent by the client)
         error = sshUpdateExchangeHashRaw(connection, buffer, n);
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
