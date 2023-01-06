/**
 * @file ssh_kex_rsa.c
 * @brief RSA key exchange
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
#include "ssh/ssh_kex_rsa.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_format.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_RSA_KEX_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_KEXRSA_PUBKEY message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexRsaPubKey(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Select a transient RSA key (K_T) that matches MINKLEN requirement
   connection->rsaKeyIndex = sshSelectTransientRsaKey(connection->context,
      connection->kexAlgo);

   //Acceptable RSA key found?
   if(connection->rsaKeyIndex >= 0)
   {
      //Format SSH_MSG_KEXRSA_PUBKEY message
      error = sshFormatKexRsaPubKey(connection, message, &length);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEXRSA_PUBKEY message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The client responds with an SSH_MSG_KEXRSA_SECRET message
      connection->state = SSH_CONN_STATE_KEX_RSA_SECRET;
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEXRSA_SECRET message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] transientRsaPublicKey Transient RSA public key (K_T)
 * @return Error code
 **/

error_t sshSendKexRsaSecret(SshConnection *connection,
   const SshBinaryString *transientRsaPublicKey)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_KEXRSA_SECRET message
   error = sshFormatKexRsaSecret(connection, transientRsaPublicKey,
      message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEXRSA_SECRET message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The server responds with an SSH_MSG_KEXRSA_DONE message
      connection->state = SSH_CONN_STATE_KEX_RSA_DONE;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEXRSA_DONE message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexRsaDone(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_KEXRSA_DONE message
   error = sshFormatKexRsaDone(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEXRSA_DONE message (%" PRIuSIZE " bytes)...\r\n", length);
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
 * @brief Format SSH_MSG_KEXRSA_PUBKEY message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexRsaPubKey(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEXRSA_PUBKEY;

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

   //Format transient RSA public key (K_T)
   error = sshFormatTransientRsaPublicKey(connection, p + sizeof(uint32_t), &n);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with K_T (transient RSA public key)
   error = sshUpdateExchangeHash(connection, p + sizeof(uint32_t), n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEXRSA_SECRET message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] transientRsaPublicKey Transient RSA public key (K_T)
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexRsaSecret(SshConnection *connection,
   const SshBinaryString *transientRsaPublicKey, uint8_t *p, size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEXRSA_SECRET;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //The client uses K_T to encrypt K using RSAES-OAEP
   error = sshEncryptSharedSecret(connection, transientRsaPublicKey,
      p + sizeof(uint32_t), &n);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with the encrypted secret
   error = sshUpdateExchangeHash(connection, p + sizeof(uint32_t), n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEXRSA_DONE message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexRsaDone(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEXRSA_DONE;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

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

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_KEXRSA_PUBKEY message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexRsaPubKey(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString hostKeyAlgo;
   SshBinaryString hostKey;
   SshBinaryString transientRsaPublicKey;

   //Debug message
   TRACE_INFO("SSH_MSG_KEXRSA_PUBKEY message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_RSA_PUB_KEY)
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

   //Decode transient RSA public key (K_T)
   error = sshParseBinaryString(p, length, &transientRsaPublicKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + transientRsaPublicKey.length;
   length -= sizeof(uint32_t) + transientRsaPublicKey.length;

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
   //from the server by sending an SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
   //message
   if(error)
      return ERROR_INVALID_KEY;

   //Allocate a buffer to store the server's host key
   connection->serverHostKey = sshAllocMem(hostKey.length);
   //Failed to allocate memory?
   if(connection->serverHostKey == NULL)
      return ERROR_OUT_OF_MEMORY;

   //The server's host key will be used to verify the signature in the
   //SSH_MSG_KEXRSA_DONE message
   osMemcpy(connection->serverHostKey, hostKey.value, hostKey.length);
   connection->serverHostKeyLen = hostKey.length;

   //Update exchange hash H with K_S (server's public host key)
   error = sshUpdateExchangeHash(connection, hostKey.value, hostKey.length);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with K_T (transient RSA public key)
   error = sshUpdateExchangeHash(connection, transientRsaPublicKey.value,
      transientRsaPublicKey.length);
   //Any error to report?
   if(error)
      return error;

   //The client responds with an SSH_MSG_KEXRSA_SECRET message
   return sshSendKexRsaSecret(connection, &transientRsaPublicKey);
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEXRSA_SECRET message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexRsaSecret(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshBinaryString encryptedSecret;

   //Debug message
   TRACE_INFO("SSH_MSG_KEXRSA_SECRET message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_RSA_SECRET)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode encrypted secret
   error = sshParseBinaryString(p, length, &encryptedSecret);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + encryptedSecret.length;
   length -= sizeof(uint32_t) + encryptedSecret.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Update exchange hash H with the encrypted secret
   error = sshUpdateExchangeHash(connection, encryptedSecret.value,
      encryptedSecret.length);
   //Any error to report?
   if(error)
      return error;

   //The server decrypts K using RSAES-OAEP
   error = sshDecryptSharedSecret(connection, encryptedSecret.value,
      encryptedSecret.length);

   //Any decryption error?
   if(error)
   {
      //The server should send SSH_MESSAGE_DISCONNECT with a reason code of
      //SSH_DISCONNECT_KEY_EXCHANGE_FAILED and must disconnect (refer to
      //RFC 4432, section 4)
      error = sshSendDisconnect(connection, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
         "Key exchanged failed");
   }
   else
   {
      //Otherwise, the server responds with an SSH_MSG_KEXRSA_DONE message
      error = sshSendKexRsaDone(connection);
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEXRSA_DONE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexRsaDone(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshBinaryString hostKey;
   SshBinaryString signature;

   //Debug message
   TRACE_INFO("SSH_MSG_KEXRSA_DONE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_RSA_DONE)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

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

   //Update exchange hash H with K (shared secret)
   error = sshUpdateExchangeHashRaw(connection, connection->k,
      connection->kLen);
   //Any error to report?
   if(error)
      return error;

   //Get server's host key
   hostKey.value = connection->serverHostKey;
   hostKey.length = connection->serverHostKeyLen;

   //Verify the signature on the exchange hash
   error = sshVerifyExchangeHashSignature(connection, &hostKey, &signature);
   //Any error to report?
   if(error)
      return error;

   //Release server's host key
   sshFreeMem(connection->serverHostKey);
   connection->serverHostKey = NULL;
   connection->serverHostKeyLen = 0;

   //Key exchange ends by each side sending an SSH_MSG_NEWKEYS message
   return sshSendNewKeys(connection);
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse Diffie-Hellman specific messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexRsaMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check message type
      if(type == SSH_MSG_KEXRSA_PUBKEY)
      {
         //Parse SSH_MSG_KEXRSA_PUBKEY message
         error = sshParseKexRsaPubKey(connection, message, length);
      }
      else if(type == SSH_MSG_KEXRSA_DONE)
      {
         //Parse SSH_MSG_KEXRSA_DONE message
         error = sshParseKexRsaDone(connection, message, length);
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
      if(type == SSH_MSG_KEXRSA_SECRET)
      {
         //Parse SSH_MSG_KEXRSA_SECRET message
         error = sshParseKexRsaSecret(connection, message, length);
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
 * @brief Select a transient RSA key
 * @param[in] context Pointer to the SSH context
 * @param[in] kexAlgo Key exchange algorithm name
 * @return Index of the selected transient RSA key, if any
 **/

int_t sshSelectTransientRsaKey(SshContext *context, const char_t *kexAlgo)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   uint_t i;
   int_t index;
   const SshRsaKey *key;

   //Initialize index
   index = -1;

   //Loop through the transient RSA keys
   for(i = 0; i < SSH_MAX_RSA_KEYS && index < 0; i++)
   {
      //Point to the current RSA key
      key = &context->rsaKeys[i];

      //Valid RSA modulus?
      if(key->modulusSize >= SSH_MIN_RSA_MODULUS_SIZE &&
         key->modulusSize <= SSH_MAX_RSA_MODULUS_SIZE)
      {
         //The modulus of K_T must be at least MINKLEN bits long
         if(sshCompareAlgo(kexAlgo, "rsa1024-sha1") &&
            key->modulusSize >= 1024)
         {
            //The "rsa1024-sha1" method specifies a minimum RSA modulus length
            //of 1024 bits (refer to RFC 4432, section 5)
            index = i;
         }
         else if(sshCompareAlgo(kexAlgo, "rsa2048-sha256") &&
            key->modulusSize >= 2048)
         {
            //The "rsa2048-sha256" method specifies a minimum RSA modulus length
            //of 2048 bits (refer to RFC 4432, section 6)
            index = i;
         }
         else
         {
            //Just for sanity
         }
      }
   }

   //Return the index of the transient RSA key
   return index;
#else
   //Server operation mode is not implemented
   return NULL;
#endif
}


/**
 * @brief Format transient RSA public key
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the RSA public key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatTransientRsaPublicKey(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   error_t error;
   int_t i;
   SshContext *context;
   RsaPublicKey rsaPublicKey;

   //Point to the SSH context
   context = connection->context;

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

   //The RSA public key may be a transient key generated solely for this
   //SSH connection, or it may be re-used for several connections (refer to
   //RFC 4432, section3)
   i = connection->rsaKeyIndex;

   //Valid index?
   if(i >= 0 && i < SSH_MAX_RSA_KEYS)
   {
      //Load the transient RSA public key
      error = sshImportRsaPublicKey(context->rsaKeys[i].publicKey,
         context->rsaKeys[i].publicKeyLen, &rsaPublicKey);

      //Check status code
      if(!error)
      {
         //The key K_T is encoded according to the "ssh-rsa" scheme (refer to
         //RFC 4432, section 4)
         error = sshFormatRsaPublicKey(&rsaPublicKey, p, written);
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Free previously allocated resources
   rsaFreePublicKey(&rsaPublicKey);

   //Return status code
   return error;
}


/**
 * @brief Encrypt shared secret using RSAES-OAEP
 * @param[in] connection Pointer to the SSH connection
 * @param[in] transientRsaPublicKey Transient RSA public key (K_T)
 * @param[out] encryptedSecret Ciphertext resulting from the encryption
 *   operation
 * @param[out] encryptedSecretLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t sshEncryptSharedSecret(SshConnection *connection,
   const SshBinaryString *transientRsaPublicKey, uint8_t *encryptedSecret,
   size_t *encryptedSecretLen)
{
   error_t error;
   uint8_t n;
   uint_t kLen;
   SshContext *context;
   SshRsaHostKey rsaHostKey;
   RsaPublicKey rsaPublicKey;

   //Point to the SSH context
   context = connection->context;

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

   //The key K_T is encoded according to the "ssh-rsa" scheme (refer to
   //RFC 4432, section 4)
   error = sshParseRsaHostKey(transientRsaPublicKey->value,
      transientRsaPublicKey->length, &rsaHostKey);

   //Check status code
   if(!error)
   {
      //Load the transient RSA public key
      error = sshImportRsaHostKey(&rsaHostKey, &rsaPublicKey);
   }

   //Check status code
   if(!error)
   {
      //Let KLEN be the length of the modulus of K_T, in bits
      kLen = mpiGetBitLength(&rsaPublicKey.n);

      //Make sure the length of the RSA modulus is acceptable
      if(kLen >= SSH_MIN_RSA_MODULUS_SIZE && kLen <= SSH_MAX_RSA_MODULUS_SIZE)
      {
         //Determine the length of the shared secret
         connection->kLen = (kLen + 7) / 8;
         connection->kLen -= (2 * connection->hashAlgo->digestSize) + 6;

         //Generate a random integer K
         error = context->prngAlgo->read(context->prngContext, connection->k,
            connection->kLen);

         //Check status code
         if(!error)
         {
            //The mpint encoding of K requires a leading zero bit and padding
            //to a whole number of bytes
            n = (kLen + 7) % 8;

            //Ensure K is in the range 0 <= K < 2^(KLEN-2*HLEN-49)
            if(n != 0)
            {
               connection->k[0] &= (1 << n) - 1;
            }

            //Convert the shared secret K to mpint representation
            error = sshConvertArrayToMpint(connection->k, connection->kLen,
               connection->k, &connection->kLen);
         }

         //Check status code
         if(!error)
         {
            //Perform RSAES-OAEP encryption
            error  = rsaesOaepEncrypt(context->prngAlgo, context->prngContext,
               &rsaPublicKey, connection->hashAlgo, "", connection->k,
               connection->kLen, encryptedSecret, encryptedSecretLen);
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Free previously allocated resources
   rsaFreePublicKey(&rsaPublicKey);

   //Return status code
   return error;
}


/**
 * @brief Decrypt shared secret using RSAES-OAEP
 * @param[in] connection Pointer to the SSH connection
 * @param[in] encryptedSecret Ciphertext to be decrypted
 * @param[in] encryptedSecretLen Length of the ciphertext to be decrypted
 * @return Error code
 **/

error_t sshDecryptSharedSecret(SshConnection *connection,
   const uint8_t *encryptedSecret, size_t encryptedSecretLen)
{
   error_t error;
   int_t i;
   SshBinaryString k;
   SshContext *context;
   RsaPrivateKey rsaPrivateKey;

   //Point to the SSH context
   context = connection->context;

   //Initialize RSA private key
   rsaInitPrivateKey(&rsaPrivateKey);

   //Index of the transient RSA private key
   i = connection->rsaKeyIndex;

   //Valid index?
   if(i >= 0 && i < SSH_MAX_RSA_KEYS)
   {
      //Load the transient RSA private key
      error = pemImportRsaPrivateKey(context->rsaKeys[i].privateKey,
         context->rsaKeys[i].privateKeyLen, &rsaPrivateKey);

      //Check status code
      if(!error)
      {
         //Perform RSAES-OAEP decryption
         error = rsaesOaepDecrypt(&rsaPrivateKey, connection->hashAlgo, "",
            encryptedSecret, encryptedSecretLen, connection->k,
            SSH_MAX_SHARED_SECRET_LEN, &connection->kLen);
      }

      //Check status code
      if(!error)
      {
         //The shared secret K must be encoded as a mpint
         error = sshParseBinaryString(connection->k, connection->kLen, &k);
      }

      //Check status code
      if(!error)
      {
         //Malformed shared secret?
         if(connection->kLen != (sizeof(uint32_t) + k.length))
         {
            //Report an error
            error = ERROR_DECRYPTION_FAILED;
         }
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Free previously allocated resources
   rsaFreePrivateKey(&rsaPrivateKey);

   //Return status code
   return error;
}

#endif
