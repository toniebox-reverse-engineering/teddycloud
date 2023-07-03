/**
 * @file ssh_packet.c
 * @brief SSH packet encryption/decryption
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
#include "ssh/ssh_extensions.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_auth.h"
#include "ssh/ssh_kex.h"
#include "ssh/ssh_connection.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_packet.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in] payload Pointer to the payload data
 * @param[in] payloadLen Length of the payload data, in bytes
 * @return Error code
 **/

error_t sshSendPacket(SshConnection *connection, uint8_t *payload,
   size_t payloadLen)
{
   error_t error;
   size_t blockSize;
   size_t packetLen;
   size_t paddingLen;
   SshContext *context;
   SshEncryptionEngine *encryptionEngine;

   //Point to the SSH context
   context = connection->context;
   //Point to the encryption engine
   encryptionEngine = &connection->encryptionEngine;

   //Check whether an SSH_MSG_NEWKEYS message has been sent
   if(connection->newKeysSent)
   {
      //AEAD cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         //When using AES-GCM, the packet_length field is to be treated as
         //additional authenticated data, not as plaintext (refer to RFC 5647,
         //section 7.3)
         packetLen = payloadLen + sizeof(uint8_t);

         //The total length of the packet must be a multiple of the cipher block
         //size or 8, whichever is larger (refer to RFC 4253, section 6)
         blockSize = MAX(encryptionEngine->cipherAlgo->blockSize, 8);
      }
      else if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         //When using ChaCha20Poly1305, the packet_length field is to be
         //treated as additional authenticated data, not as plaintext
         packetLen = payloadLen + sizeof(uint8_t);

         //The total length of the packet must be a multiple of 8
         blockSize = 8;
      }
      else
      {
         //The payload is preceded by a 5-byte header
         packetLen = payloadLen + SSH_PACKET_HEADER_SIZE;

         //The total length of the packet must be a multiple of the cipher block
         //size or 8, whichever is larger (refer to RFC 4253, section 6)
         blockSize = MAX(encryptionEngine->cipherAlgo->blockSize, 8);
      }
   }
   else
   {
      //The payload is preceded by a 5-byte header
      packetLen = payloadLen + SSH_PACKET_HEADER_SIZE;
      //The total length of the packet must be a multiple of 8
      blockSize = 8;
   }

   //Calculate the length of the padding string
   if(encryptionEngine->etm)
   {
      paddingLen = blockSize - ((packetLen + blockSize - 4) % blockSize);
   }
   else
   {
      paddingLen = blockSize - (packetLen % blockSize);
   }

   //There must be at least four bytes of padding
   if(paddingLen < 4)
   {
      paddingLen += blockSize;
   }

   //The padding should consist of random bytes
   error = context->prngAlgo->read(context->prngContext, payload + payloadLen,
      paddingLen);

   //Check status code
   if(!error)
   {
      //The length of the packet does not include the packet_length field itself
      packetLen = payloadLen + paddingLen + sizeof(uint8_t);

      //Format SSH packet header
      STORE32BE(packetLen, connection->buffer);
      connection->buffer[4] = paddingLen;

      //Determine the total length of the packet
      connection->txBufferLen = packetLen + sizeof(uint32_t);
      connection->txBufferPos = 0;

      //Check whether an SSH_MSG_NEWKEYS message has been sent
      if(connection->newKeysSent)
      {
         //All messages sent after this message must use the new keys and
         //algorithms
         error = sshEncryptPacket(connection, connection->buffer,
            &connection->txBufferLen);
      }
   }

   //Check status code
   if(!error)
   {
      //The sequence number is initialized to zero for the first packet, and is
      //incremented after every packet (regardless of whether encryption or MAC
      //is in use)
      sshIncSequenceNumber(connection->encryptionEngine.seqNum);
   }

   //Return status code
   return error;
}


/**
 * @brief Receive SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshReceivePacket(SshConnection *connection)
{
   error_t error;
   size_t n;
   size_t blockSize;
   SshEncryptionEngine *decryptionEngine;

   //Initialize status code
   error = NO_ERROR;

   //Point to the decryption engine
   decryptionEngine = &connection->decryptionEngine;

   //Check the actual length of the packet
   if(connection->rxBufferLen < SSH_BUFFER_SIZE)
   {
      //Limit the number of bytes to read at a time
      n = SSH_BUFFER_SIZE - connection->rxBufferLen;

      //Check connection state
      if(connection->state == SSH_CONN_STATE_CLIENT_ID ||
         connection->state == SSH_CONN_STATE_SERVER_ID)
      {
         //The identification string is terminated by a CR and LF
         error = socketReceive(connection->socket, connection->buffer +
            connection->rxBufferLen, n, &n, SOCKET_FLAG_BREAK_CRLF);

         //Check status code
         if(!error)
         {
            //Adjust the length of the buffer
            connection->rxBufferLen += n;

            //Check whether the string is properly terminated
            if(connection->rxBufferLen > 0 &&
               connection->buffer[connection->rxBufferLen - 1] == '\n')
            {
               //Parse identification string
               error = sshParseIdString(connection, connection->buffer,
                  connection->rxBufferLen);

               //Flush receive buffer
               connection->rxBufferLen = 0;
               connection->rxBufferPos = 0;
            }
         }
      }
      else
      {
         //Check whether an SSH_MSG_NEWKEYS message has been received
         if(connection->newKeysReceived)
         {
            //Stream or AEAD cipher?
            if(decryptionEngine->cipherMode == CIPHER_MODE_STREAM ||
               decryptionEngine->cipherMode == CIPHER_MODE_GCM ||
               decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
            {
               //The packet_length field is to be treated as additional
               //authenticated data, not as plaintext
               blockSize = sizeof(uint32_t);
            }
            else
            {
               //Implementations should decrypt the length after receiving the
               //first 8 (or cipher block size, whichever is larger) bytes of
               //a packet
               blockSize = decryptionEngine->cipherAlgo->blockSize;
            }
         }
         else
         {
            //The packet_length field is not encrypted
            blockSize = sizeof(uint32_t);
         }

         //Receive an entire SSH packet
         if(connection->rxBufferPos < blockSize)
         {
            //Read the packet_length field of the SSH packet
            error = socketReceive(connection->socket, connection->buffer +
               connection->rxBufferPos, blockSize - connection->rxBufferPos,
               &n, 0);

            //Check status code
            if(!error)
            {
               //Adjust the length of the buffer
               connection->rxBufferPos += n;

               //The packet_length field may be encrypted, and processing it
               //requires special care when receiving packets
               if(connection->rxBufferPos >= blockSize)
               {
                  //Check whether an SSH_MSG_NEWKEYS message has been received
                  if(connection->newKeysReceived)
                  {
                     //When receiving a packet, the length must be decrypted first
                     error = sshDecryptPacketLength(connection, connection->buffer);
                  }
                  else
                  {
                     //The packet_length field is not encrypted
                     error = sshParsePacketLength(connection, connection->buffer);
                  }
               }
            }
         }
         else
         {
            //Read the contents of the SSH packet
            error = socketReceive(connection->socket,
               connection->buffer + connection->rxBufferPos,
               connection->rxBufferLen - connection->rxBufferPos, &n, 0);

            //Check status code
            if(!error)
            {
               //Adjust the length of the buffer
               connection->rxBufferPos += n;

               //Check whether a complete packet has been received
               if(connection->rxBufferPos >= connection->rxBufferLen)
               {
                  //Parse the received SSH packet
                  error = sshParsePacket(connection, connection->buffer,
                     connection->rxBufferLen);

                  //Flush receive buffer
                  connection->rxBufferLen = 0;
                  connection->rxBufferPos = 0;
               }
            }
         }
      }
   }
   else
   {
      //The implementation limits the size of packets it accepts
      error = ERROR_BUFFER_OVERFLOW;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in] packet Pointer to the received SSH packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sshParsePacket(SshConnection *connection, uint8_t *packet,
   size_t length)
{
   error_t error;
   size_t n;
   size_t paddingLen;

   //Initialize status code
   error = NO_ERROR;

   //Debug message
   TRACE_DEBUG("SSH packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Check whether an SSH_MSG_NEWKEYS message has been received
   if(connection->newKeysReceived)
   {
      //All messages sent after this message must use the new keys and
      //algorithms
      error = sshDecryptPacket(connection, packet, &length);
   }

   //Check status code
   if(!error)
   {
      //Check the length of the received packet
      if(length >= SSH_MIN_PACKET_SIZE)
      {
         //Parse SSH packet header
         n = LOAD32BE(packet);
         paddingLen = packet[4];

         //Sanity check
         if(length == (n + sizeof(uint32_t)))
         {
            //Check the length of the padding string
            if(n >= (paddingLen + sizeof(uint8_t)))
            {
               //Point to the payload
               packet += SSH_PACKET_HEADER_SIZE;
               //Retrieve the length of the payload
               n -= paddingLen + sizeof(uint8_t);

               //Parse the received message
               error = sshParseMessage(connection, packet, n);
            }
            else
            {
               //Invalid padding length
               error = ERROR_INVALID_MESSAGE;
            }
         }
         else
         {
            //Invalid length
            error = ERROR_INVALID_MESSAGE;
         }
      }
      else
      {
         //Invalid length
         error = ERROR_INVALID_MESSAGE;
      }
   }

   //Any decoding error?
   if(error)
   {
      //Terminate the connection with the relevant reason code
      if(error == ERROR_INVALID_KEY)
      {
         //Failed to verify the peer's host key
         error = sshSendDisconnect(connection, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
            "Host key not valid");
      }
      else if(error == ERROR_DECRYPTION_FAILED)
      {
         //A record has been received with an incorrect MAC
         error = sshSendDisconnect(connection, SSH_DISCONNECT_MAC_ERROR,
            "Invalid MAC");
      }
      else if(error == ERROR_UNEXPECTED_MESSAGE)
      {
         //An inappropriate message has been received
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Unexpected packet");
      }
      else if(error == ERROR_INVALID_MESSAGE)
      {
         //A malformed message has been received
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Malformed packet");
      }
      else if(error == ERROR_INVALID_CHANNEL)
      {
         //Invalid channel number
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Invalid channel number");
      }
      else if(error == ERROR_FLOW_CONTROL)
      {
         //Flow control error
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Flow control error");
      }
      else if(error == ERROR_INVALID_GROUP)
      {
         //Diffie-Hellman group out of range
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Diffie-Hellman group out of range");
      }
      else
      {
         //Generic protocol error
         error = sshSendDisconnect(connection, SSH_DISCONNECT_PROTOCOL_ERROR,
            "Protocol error");
      }
   }

   //The sequence number is incremented after every packet
   sshIncSequenceNumber(connection->decryptionEngine.seqNum);

   //Return status code
   return error;
}


/**
 * @brief Encrypt an outgoing SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in,out] packet SSH packet to be encrypted
 * @param[in,out] length Actual length of the SSH packet
 * @return Error code
 **/

error_t sshEncryptPacket(SshConnection *connection, uint8_t *packet,
   size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *data;
   size_t dataLen;
   SshEncryptionEngine *encryptionEngine;

   //Point to the encryption engine
   encryptionEngine = &connection->encryptionEngine;

   //Get the actual length of the packet
   n = *length;

   //Debug message
   TRACE_VERBOSE("Packet to be encrypted (%" PRIuSIZE " bytes):\r\n", n);
   TRACE_VERBOSE_ARRAY("  ", packet, n);

#if (SSH_HMAC_SUPPORT == ENABLED)
   //MAC-then-encrypt mode?
   if(encryptionEngine->hashAlgo != NULL && !encryptionEngine->etm)
   {
      //The packet_length field and the payload will be encrypted
      data = packet;
      dataLen = n;

      //Compute message authentication code
      sshAppendMessageAuthCode(encryptionEngine, packet, n);
   }
   else
#endif
   {
      //Point to the plaintext data to be encrypted
      data = packet + sizeof(uint32_t);
      dataLen = n - sizeof(uint32_t);
   }

#if (SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   //Stream cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM)
   {
      const CipherAlgo *cipherAlgo;

      //Cipher algorithm used to encrypt the packet
      cipherAlgo = encryptionEngine->cipherAlgo;

      //Encrypt the contents of the SSH packet
      cipherAlgo->encryptStream(&encryptionEngine->cipherContext, data,
         data, dataLen);

      //Successful encryption
      error = NO_ERROR;
   }
   else
#endif
#if (SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //Perform CBC encryption
      error = cbcEncrypt(encryptionEngine->cipherAlgo,
         &encryptionEngine->cipherContext, encryptionEngine->iv, data,
         data, dataLen);
   }
   else
#endif
#if (SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //CTR cipher mode?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CTR)
   {
      uint_t m;

      //Retrieve cipher block size, in bits
      m = encryptionEngine->cipherAlgo->blockSize * 8;

      //Perform CTR encryption
      error = ctrEncrypt(encryptionEngine->cipherAlgo,
         &encryptionEngine->cipherContext, m, encryptionEngine->iv, data,
         data, dataLen);
   }
   else
#endif
#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //When using AES-GCM, the packet_length field is to be treated as
      //additional authenticated data, not as plaintext (refer to RFC 5647,
      //section 7.3)
      error = gcmEncrypt(&encryptionEngine->gcmContext, encryptionEngine->iv,
         12, packet, 4, data, data, dataLen, packet + n,
         encryptionEngine->macSize);

      //The invocation counter is treated as a 64-bit integer and is
      //incremented after each invocation of AES-GCM to process a binary
      //packet (refer to RFC 5647, section 7.1)
      sshIncInvocationCounter(encryptionEngine->iv);
   }
   else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      ChachaContext chachaContext;
      Poly1305Context poly1305Context;
      uint8_t nonce[8];
      uint8_t key[32];

      //The nonce consists of the packet sequence number encoded as a uint64
      osMemset(nonce, 0, 4);
      osMemcpy(nonce + 4, encryptionEngine->seqNum, 4);

      //The ChaCha20 instance keyed by K_1 is a stream cipher that is used
      //only to encrypt the 4 byte packet length field
      error = chachaInit(&chachaContext, 20, encryptionEngine->encKey + 32, 32,
         nonce, 8);

      //Check status code
      if(!error)
      {
         //The packet_length field is encrypted using a zero block counter to
         //obtain the ciphertext length
         chachaCipher(&chachaContext, packet, packet, 4);

         //The second ChaCha20 instance, keyed by K_2, is used in conjunction
         //with Poly1305 to build an AEAD that is used to decrypt and
         //authenticate the entire packet
         error = chachaInit(&chachaContext, 20, encryptionEngine->encKey, 32,
            nonce, sizeof(nonce));
      }

      //Check status code
      if(!error)
      {
         //Generate a Poly1305 key by taking the first 256 bits of ChaCha20
         //stream output generated using K_2
         chachaCipher(&chachaContext, NULL, key, 32);

         //The other 256 bits of the ChaCha20 block are discarded
         chachaCipher(&chachaContext, NULL, NULL, 32);

         //Encrypt the packet payload
         chachaCipher(&chachaContext, data, data, dataLen);

         //Initialize the Poly1305 function with the key calculated above
         poly1305Init(&poly1305Context, key);

         //Compute MAC over the ciphertext of the packet length and the
         //payload together
         poly1305Update(&poly1305Context, packet, n);
         poly1305Final(&poly1305Context, packet + n);

         //Debug message
         TRACE_VERBOSE("Write sequence number:\r\n");
         TRACE_VERBOSE_ARRAY("  ", &encryptionEngine->seqNum, 4);
         TRACE_VERBOSE("Computed MAC:\r\n");
         TRACE_VERBOSE_ARRAY("  ", packet + n, encryptionEngine->macSize);
      }
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

#if (SSH_HMAC_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Encrypt-then-MAC mode?
      if(encryptionEngine->hashAlgo != NULL && encryptionEngine->etm)
      {
         //Compute message authentication code
         sshAppendMessageAuthCode(encryptionEngine, packet, n);
      }
   }
#endif

   //Check status code
   if(!error)
   {
      //The value resulting from the MAC algorithm must be transmitted without
      //encryption as the last part of the packet
      n += encryptionEngine->macSize;

      //Debug message
      TRACE_VERBOSE("Encrypted packet (%" PRIuSIZE " bytes):\r\n", n);
      TRACE_VERBOSE_ARRAY("  ", packet, n);

      //Return the length of the encrypted packet
      *length = n;
   }

   //Return status code
   return error;
}


/**
 * @brief Decrypt an incoming SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in,out] packet SSH packet to be decrypted
 * @param[in,out] length Actual length of the SSH packet
 * @return Error code
 **/

error_t sshDecryptPacket(SshConnection *connection, uint8_t *packet,
   size_t *length)
{
   error_t error;
   size_t n;
   size_t blockSize;
   SshEncryptionEngine *decryptionEngine;

   //Initialize status code
   error = NO_ERROR;

   //Point to the decryption engine
   decryptionEngine = &connection->decryptionEngine;

   //Block cipher algorithm?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CBC ||
      decryptionEngine->cipherMode == CIPHER_MODE_CTR)
   {
      //Encrypt-then-MAC mode?
      if(decryptionEngine->etm)
      {
         //The packet_length field is not encrypted
         blockSize = 4;
      }
      else
      {
         //Retrieve the cipher block size
         blockSize = decryptionEngine->cipherAlgo->blockSize;
      }
   }
   else
   {
      //The packet_length field is a 32-bit integer
      blockSize = 4;
   }

   //Get the actual length of the packet
   n = *length;

   //Debug message
   TRACE_VERBOSE("Packet to be decrypted (%" PRIuSIZE " bytes):\r\n", n);
   TRACE_VERBOSE_ARRAY("  ", packet, n);

   //Check the length of the incoming packet
   if(n >= (blockSize + decryptionEngine->macSize))
   {
      //The value resulting from the MAC algorithm is transmitted without
      //encryption as the last part of the packet
      n -= decryptionEngine->macSize;

#if (SSH_HMAC_SUPPORT == ENABLED)
      //Encrypt-then-MAC mode?
      if(decryptionEngine->hashAlgo != NULL && decryptionEngine->etm)
      {
         //Verify message authentication code
         error = sshVerifyMessageAuthCode(decryptionEngine, packet, n);
      }
#endif

      //Check status code
      if(!error)
      {
#if (SSH_STREAM_CIPHER_SUPPORT == ENABLED)
         //Stream cipher?
         if(decryptionEngine->cipherMode == CIPHER_MODE_STREAM)
         {
            const CipherAlgo *cipherAlgo;

            //Cipher algorithm used to encrypt the packet
            cipherAlgo = decryptionEngine->cipherAlgo;

            //Decrypt the contents of the SSH packet
            cipherAlgo->decryptStream(&decryptionEngine->cipherContext,
               packet + blockSize, packet + blockSize, n - blockSize);
         }
         else
#endif
#if (SSH_CBC_CIPHER_SUPPORT == ENABLED)
         //CBC cipher mode?
         if(decryptionEngine->cipherMode == CIPHER_MODE_CBC)
         {
            //Perform CBC decryption
            error = cbcDecrypt(decryptionEngine->cipherAlgo,
               &decryptionEngine->cipherContext, decryptionEngine->iv,
               packet + blockSize, packet + blockSize, n - blockSize);
         }
         else
#endif
#if (SSH_CTR_CIPHER_SUPPORT == ENABLED)
         //CTR cipher mode?
         if(decryptionEngine->cipherMode == CIPHER_MODE_CTR)
         {
            uint_t m;

            //Retrieve cipher block size, in bits
            m = decryptionEngine->cipherAlgo->blockSize * 8;

            //Perform CTR decryption
            error = ctrDecrypt(decryptionEngine->cipherAlgo,
               &decryptionEngine->cipherContext, m, decryptionEngine->iv,
               packet + blockSize, packet + blockSize, n - blockSize);
         }
         else
#endif
#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
         //GCM AEAD cipher?
         if(decryptionEngine->cipherMode == CIPHER_MODE_GCM)
         {
            //When using AES-GCM, the packet_length field is to be treated as
            //additional authenticated data, not as plaintext (refer to
            //RFC 5647, section 7.3)
            error = gcmDecrypt(&decryptionEngine->gcmContext,
               decryptionEngine->iv, 12, packet, blockSize, packet + blockSize,
               packet + blockSize, n - blockSize, packet + n,
               decryptionEngine->macSize);

            //The invocation counter is treated as a 64-bit integer and is
            //incremented after each invocation of AES-GCM to process a binary
            //packet (refer to RFC 5647, section 7.1)
            sshIncInvocationCounter(decryptionEngine->iv);
         }
         else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
         //ChaCha20Poly1305 AEAD cipher?
         if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
         {
            size_t i;
            uint8_t mask;
            uint8_t nonce[8];
            uint8_t key[32];
            uint8_t mac[16];
            ChachaContext chachaContext;
            Poly1305Context poly1305Context;

            //The nonce consists of the packet sequence number encoded as a
            //uint64
            osMemset(nonce, 0, 4);
            osMemcpy(nonce + 4, decryptionEngine->seqNum, 4);

            //The second ChaCha20 instance, keyed by K_2, is used in conjunction
            //with Poly1305 to build an AEAD that is used to decrypt and
            //authenticate the entire packet
            error = chachaInit(&chachaContext, 20, decryptionEngine->encKey, 32,
               nonce, sizeof(nonce));

            //Check status code
            if(!error)
            {
               //Generate a Poly1305 key by taking the first 256 bits of ChaCha20
               //stream output generated using K_2
               chachaCipher(&chachaContext, NULL, key, 32);

               //The other 256 bits of the ChaCha20 block are discarded
               chachaCipher(&chachaContext, NULL, NULL, 32);

               //Initialize the Poly1305 function with the key calculated above
               poly1305Init(&poly1305Context, key);

               //Compute MAC over the ciphertext of the packet length and the
               //payload together
               poly1305Update(&poly1305Context, decryptionEngine->aad, blockSize);
               poly1305Update(&poly1305Context, packet + blockSize, n - blockSize);
               poly1305Final(&poly1305Context, mac);

               //Decrypt the packet payload
               chachaCipher(&chachaContext, packet + blockSize, packet + blockSize,
                  n - blockSize);

               //The calculated MAC is then compared in constant time with the
               //one appended to the packet
               for(mask = 0, i = 0; i < 16; i++)
               {
                  mask |= mac[i] ^ packet[n + i];
               }

               //The message is authenticated if and only if the tags match
               error = (mask == 0) ? NO_ERROR : ERROR_FAILURE;
            }
         }
         else
#endif
         //Invalid cipher mode?
         {
            //The specified cipher mode is not supported
            error = ERROR_UNSUPPORTED_CIPHER_MODE;
         }
      }
   }
   else
   {
      //The packet is malformed
      error = ERROR_INVALID_PACKET;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_VERBOSE("Decrypted packet (%" PRIuSIZE " bytes):\r\n", n);
      TRACE_VERBOSE_ARRAY("  ", packet, n);

#if (SSH_HMAC_SUPPORT == ENABLED)
      //MAC-then-encrypt mode?
      if(decryptionEngine->hashAlgo != NULL && !decryptionEngine->etm)
      {
         //Verify message authentication code
         error = sshVerifyMessageAuthCode(decryptionEngine, packet, n);
      }
#endif
   }

   //Check status code
   if(!error)
   {
      //Return the length of the decrypted packet
      *length = n;
   }
   else
   {
      //Failed to decrypt SSH packet
      error = ERROR_DECRYPTION_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Retrieve the length of an incoming SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in] packet Pointer to the received SSH packet
 * @return Error code
 **/

error_t sshParsePacketLength(SshConnection *connection, uint8_t *packet)
{
   error_t error;
   size_t packetLen;

   //Initialize status code
   error = NO_ERROR;

   //Convert the packet length to host byte order
   packetLen = LOAD32BE(packet);
   //The length of the packet does not include the packet_length field itself
   packetLen += sizeof(uint32_t);

   //Sanity check
   if(packetLen <= SSH_BUFFER_SIZE && packetLen > LOAD32BE(packet))
   {
      //Save the total length of the packet
      connection->rxBufferLen = packetLen;
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
}


/**
 * @brief Decrypt the length field of an incoming SSH packet
 * @param[in] connection Pointer to the SSH connection
 * @param[in,out] packet Pointer to the first block of data
 * @return Error code
 **/

error_t sshDecryptPacketLength(SshConnection *connection, uint8_t *packet)
{
   error_t error;
#if (SSH_HMAC_SUPPORT == ENABLED || SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   size_t blockSize;
#endif
   size_t packetLen;
   SshEncryptionEngine *decryptionEngine;

   //Initialize status code
   error = NO_ERROR;

   //Point to the decryption engine
   decryptionEngine = &connection->decryptionEngine;

#if (SSH_HMAC_SUPPORT == ENABLED || SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //Block cipher algorithm?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CBC ||
      decryptionEngine->cipherMode == CIPHER_MODE_CTR)
   {
      //Encrypt-then-MAC mode?
      if(decryptionEngine->etm)
      {
         //The packet_length field is not encrypted
         blockSize = 4;
      }
      else
      {
         //Retrieve the cipher block size
         blockSize = decryptionEngine->cipherAlgo->blockSize;
      }
   }
   else
   {
      //The packet_length field is a 32-bit integer
      blockSize = 4;
   }

   //Debug message
   TRACE_VERBOSE("Block to be decrypted (%" PRIuSIZE " bytes):\r\n", blockSize);
   TRACE_VERBOSE_ARRAY("  ", packet, blockSize);
#endif

#if (SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   //Stream cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_STREAM)
   {
      //MAC-then-encrypt mode?
      if(!decryptionEngine->etm)
      {
         const CipherAlgo *cipherAlgo;

         //Cipher algorithm used to encrypt the packet
         cipherAlgo = decryptionEngine->cipherAlgo;

         //Decrypt packet_length field
         cipherAlgo->decryptStream(&decryptionEngine->cipherContext, packet,
            packet, blockSize);
      }
   }
   else
#endif
#if (SSH_CBC_CIPHER_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //MAC-then-encrypt mode?
      if(!decryptionEngine->etm)
      {
         //Perform CBC decryption
         error = cbcDecrypt(decryptionEngine->cipherAlgo,
            &decryptionEngine->cipherContext, decryptionEngine->iv, packet,
            packet, blockSize);
      }
   }
   else
#endif
#if (SSH_CTR_CIPHER_SUPPORT == ENABLED)
   //CTR cipher mode?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CTR)
   {
      //MAC-then-encrypt mode?
      if(!decryptionEngine->etm)
      {
         uint_t m;

         //Retrieve cipher block size, in bits
         m = decryptionEngine->cipherAlgo->blockSize * 8;

         //Perform CTR decryption
         error = ctrDecrypt(decryptionEngine->cipherAlgo,
            &decryptionEngine->cipherContext, m, decryptionEngine->iv,
            packet, packet, blockSize);
      }
   }
   else
#endif
#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //The packet_length field is not encrypted
   }
   else
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      ChachaContext chachaContext;
      uint8_t nonce[8];

      //The nonce consists of the packet sequence number encoded as a uint64
      osMemset(nonce, 0, 4);
      osMemcpy(nonce + 4, decryptionEngine->seqNum, 4);

      //Initialize ChaCha20 context
      error = chachaInit(&chachaContext, 20, decryptionEngine->encKey + 32, 32,
         nonce, 8);

      //Check status code
      if(!error)
      {
         //Save the ciphertext of the packet length
         osMemcpy(decryptionEngine->aad, packet, blockSize);

         //The packet_length field is decrypted using a zero block counter to
         //obtain the plaintext length
         chachaCipher(&chachaContext, packet, packet, blockSize);
      }
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_VERBOSE("Decrypted block (%" PRIuSIZE " bytes):\r\n", blockSize);
      TRACE_VERBOSE_ARRAY("  ", packet, blockSize);

      //Convert the packet length to host byte order
      packetLen = LOAD32BE(packet);

      //The length of the packet does not include the mac field and the
      //packet_length field itself
      packetLen += decryptionEngine->macSize + sizeof(uint32_t);

      //Sanity check
      if(packetLen <= SSH_BUFFER_SIZE && packetLen > LOAD32BE(packet))
      {
         //Save the total length of the packet
         connection->rxBufferLen = packetLen;
      }
      else
      {
         //Report an error
         error = ERROR_DECRYPTION_FAILED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to received message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseMessage(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint8_t type;

   //Check the length of the message
   if(length >= sizeof(uint8_t))
   {
      //The first byte of the payload indicates the message type
      type = message[0];

      //Check message type
      if(type == SSH_MSG_KEXINIT)
      {
         //Key exchange begins with an SSH_MSG_KEXINIT message
         error = sshParseKexInit(connection, message, length);
      }
      else if(type >= SSH_MSG_KEX_MIN && type <= SSH_MSG_KEX_MAX)
      {
         //Parse key exchange method-specific messages
         error = sshParseKexMessage(connection, type, message, length);
      }
      else if(type == SSH_MSG_NEWKEYS)
      {
         //Key exchange ends with an SSH_MSG_NEWKEYS message
         error = sshParseNewKeys(connection, message, length);
      }
      else if(type == SSH_MSG_SERVICE_REQUEST)
      {
         //After the key exchange, the client requests a service using a
         //SSH_MSG_SERVICE_REQUEST message
         error = sshParseServiceRequest(connection, message, length);
      }
      else if(type == SSH_MSG_SERVICE_ACCEPT)
      {
         //If the server supports the service (and permits the client to use
         //it), it must respond with an SSH_MSG_SERVICE_ACCEPT message
         error = sshParseServiceAccept(connection, message, length);
      }
      else if(type == SSH_MSG_USERAUTH_REQUEST)
      {
         //All authentication requests use an SSH_MSG_USERAUTH_REQUEST message
         error = sshParseUserAuthRequest(connection, message, length);
      }
      else if(type == SSH_MSG_USERAUTH_SUCCESS)
      {
         //When the server accepts authentication, it must respond with a
         //SSH_MSG_USERAUTH_SUCCESS message
         error = sshParseUserAuthSuccess(connection, message, length);
      }
      else if(type == SSH_MSG_USERAUTH_FAILURE)
      {
         //If the server rejects the authentication request, it must respond
         //with an SSH_MSG_USERAUTH_FAILURE message
         error = sshParseUserAuthFailure(connection, message, length);
      }
      else if(type == SSH_MSG_USERAUTH_BANNER)
      {
         //The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
         //time after this authentication protocol starts and before
         //authentication is successful
         error = sshParseUserAuthBanner(connection, message, length);
      }
      else if(type >= SSH_MSG_USERAUTH_MIN && type <= SSH_MSG_USERAUTH_MAX)
      {
         //Parse authentication method-specific messages
         error = sshParseUserAuthMessage(connection, type, message, length);
      }
      else if(type == SSH_MSG_GLOBAL_REQUEST)
      {
         //Both the client and server may send global requests at any time
         //(refer to RFC 4254, section 4)
         error = sshParseGlobalRequest(connection, message, length);
      }
      else if(type == SSH_MSG_REQUEST_SUCCESS)
      {
         //The recipient responds with either SSH_MSG_REQUEST_SUCCESS or
         //SSH_MSG_REQUEST_FAILURE
         error = sshParseRequestSuccess(connection, message, length);
      }
      else if(type == SSH_MSG_REQUEST_FAILURE)
      {
         //The recipient responds with either SSH_MSG_REQUEST_SUCCESS or
         //SSH_MSG_REQUEST_FAILURE
         error = sshParseRequestFailure(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_OPEN)
      {
         //When either side wishes to open a new channel, it then sends a
         //SSH_MSG_CHANNEL_OPEN message to the other side
         error = sshParseChannelOpen(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
      {
         //The recipient responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION
         //or SSH_MSG_CHANNEL_OPEN_FAILURE
         error = sshParseChannelOpenConfirmation(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_OPEN_FAILURE)
      {
         //The recipient responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION
         //or SSH_MSG_CHANNEL_OPEN_FAILURE
         error = sshParseChannelOpenFailure(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_REQUEST)
      {
         //All channel-specific requests use an SSH_MSG_CHANNEL_REQUEST message
         error = sshParseChannelRequest(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_SUCCESS)
      {
         //The recipient responds with either SSH_MSG_CHANNEL_SUCCESS or
         //SSH_MSG_CHANNEL_FAILURE
         error = sshParseChannelSuccess(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_FAILURE)
      {
         //The recipient responds with either SSH_MSG_CHANNEL_SUCCESS or
         //SSH_MSG_CHANNEL_FAILURE
         error = sshParseChannelFailure(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_WINDOW_ADJUST)
      {
         //Both parties use the SSH_MSG_CHANNEL_WINDOW_ADJUST message to adjust
         //the window
         error = sshParseChannelWindowAdjust(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_DATA)
      {
         //Data transfer is done with SSH_MSG_CHANNEL_DATA message
         error = sshParseChannelData(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_EXTENDED_DATA)
      {
         //Extended data can be passed with SSH_MSG_CHANNEL_EXTENDED_DATA
         //messages
         error = sshParseChannelExtendedData(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_EOF)
      {
         //When a party will no longer send more data to a channel, it should
         //send an SSH_MSG_CHANNEL_EOF message
         error = sshParseChannelEof(connection, message, length);
      }
      else if(type == SSH_MSG_CHANNEL_CLOSE)
      {
         //When either party wishes to terminate the channel, it sends an
         //SSH_MSG_CHANNEL_CLOSE message
         error = sshParseChannelClose(connection, message, length);
      }
      else if(type == SSH_MSG_IGNORE)
      {
         //The SSH_MSG_IGNORE message can be used as an additional protection
         //measure against advanced traffic analysis techniques
         error = sshParseIgnore(connection, message, length);
      }
      else if(type == SSH_MSG_DEBUG)
      {
         //The SSH_MSG_DEBUG message is used to transmit information that may
         //help debugging
         error = sshParseDebug(connection, message, length);
      }
      else if(type == SSH_MSG_DISCONNECT)
      {
         //The SSH_MSG_DISCONNECT message causes immediate termination of the
         //connection. All implementations must be able to process this message
         error = sshParseDisconnect(connection, message, length);
      }
      else if(type == SSH_MSG_UNIMPLEMENTED)
      {
         //An implementation must respond to all unrecognized messages with an
         //SSH_MSG_UNIMPLEMENTED message in the order in which the messages
         //were received
         error = sshParseUnimplemented(connection, message, length);
      }
#if (SSH_EXT_INFO_SUPPORT == ENABLED)
      else if(type == SSH_MSG_EXT_INFO)
      {
         //If a client or server offers "ext-info-c" or "ext-info-s"
         //respectively, it must be prepared to accept an SSH_MSG_EXT_INFO
         //message from the peer (refer to RFC 8308, section 2.2)
         error = sshParseExtInfo(connection, message, length);
      }
#endif
      else
      {
         //Unrecognized message received
         error = sshParseUnrecognized(connection, message, length);
      }
   }
   else
   {
      //Malformed message
      error = ERROR_INVALID_MESSAGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute message authentication code
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] packet Pointer to the packet to be authenticated
 * @param[in] length of the packet, in bytes
 **/

void sshAppendMessageAuthCode(SshEncryptionEngine *encryptionEngine,
   uint8_t *packet, size_t length)
{
#if (SSH_HMAC_SUPPORT == ENABLED)
   //Initialize HMAC calculation
   hmacInit(encryptionEngine->hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->macKey, encryptionEngine->hashAlgo->digestSize);

   //Compute MAC(key, sequence_number || unencrypted_packet)
   hmacUpdate(encryptionEngine->hmacContext, encryptionEngine->seqNum, 4);
   hmacUpdate(encryptionEngine->hmacContext, packet, length);
   hmacFinal(encryptionEngine->hmacContext, packet + length);

   //Debug message
   TRACE_VERBOSE("Write sequence number:\r\n");
   TRACE_VERBOSE_ARRAY("  ", &encryptionEngine->seqNum, 4);
   TRACE_VERBOSE("Computed MAC:\r\n");
   TRACE_VERBOSE_ARRAY("  ", packet + length, encryptionEngine->macSize);
#endif
}


/**
 * @brief Verify message authentication code
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] packet Pointer to the packet to be authenticated
 * @param[in] length of the packet, in bytes
 * @return Error code
 **/

error_t sshVerifyMessageAuthCode(SshEncryptionEngine *decryptionEngine,
   const uint8_t *packet, size_t length)
{
#if (SSH_HMAC_SUPPORT == ENABLED)
   size_t i;
   uint8_t mask;
   uint8_t mac[SSH_MAX_HASH_DIGEST_SIZE];

   //Initialize HMAC calculation
   hmacInit(decryptionEngine->hmacContext, decryptionEngine->hashAlgo,
      decryptionEngine->macKey, decryptionEngine->hashAlgo->digestSize);

   //Compute MAC(key, sequence_number || unencrypted_packet)
   hmacUpdate(decryptionEngine->hmacContext, decryptionEngine->seqNum, 4);
   hmacUpdate(decryptionEngine->hmacContext, packet, length);
   hmacFinal(decryptionEngine->hmacContext, mac);

   //Debug message
   TRACE_VERBOSE("Read sequence number:\r\n");
   TRACE_VERBOSE_ARRAY("  ", &decryptionEngine->seqNum, 4);
   TRACE_VERBOSE("Computed MAC:\r\n");
   TRACE_VERBOSE_ARRAY("  ", mac, decryptionEngine->macSize);

   //The calculated MAC is bitwise compared to the received message
   //authentication code
   for(mask = 0, i = 0; i < decryptionEngine->macSize; i++)
   {
      mask |= mac[i] ^ packet[length + i];
   }

   //The message is authenticated if and only if the MAC values match
   return (mask == 0) ? NO_ERROR : ERROR_DECRYPTION_FAILED;
#else
   //Not implemented
   return ERROR_DECRYPTION_FAILED;
#endif
}


/**
 * @brief Increment sequence number
 * @param[in,out] seqNum Pointer to the 32-bit sequence number
 **/

void sshIncSequenceNumber(uint8_t *seqNum)
{
   uint16_t temp;

   //Sequence numbers are stored MSB first
   temp = seqNum[3] + 1;
   seqNum[3] = temp & 0xFF;
   temp = (temp >> 8) + seqNum[2];
   seqNum[2] = temp & 0xFF;
   temp = (temp >> 8) + seqNum[1];
   seqNum[1] = temp & 0xFF;
   temp = (temp >> 8) + seqNum[0];
   seqNum[0] = temp & 0xFF;
}


/**
 * @brief Increment invocation counter
 * @param[in,out] iv Pointer to the 12-octet initialization vector
 **/

void sshIncInvocationCounter(uint8_t *iv)
{
   uint16_t temp;

   //With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
   //fixed field and an 8-octet invocation counter field (refer to RFC 5647,
   //section 7.1)
   temp = iv[11] + 1;
   iv[11] = temp & 0xFF;
   temp = (temp >> 8) + iv[10];
   iv[10] = temp & 0xFF;
   temp = (temp >> 8) + iv[9];
   iv[9] = temp & 0xFF;
   temp = (temp >> 8) + iv[8];
   iv[8] = temp & 0xFF;
   temp = (temp >> 8) + iv[7];
   iv[7] = temp & 0xFF;
   temp = (temp >> 8) + iv[6];
   iv[6] = temp & 0xFF;
   temp = (temp >> 8) + iv[5];
   iv[5] = temp & 0xFF;
   temp = (temp >> 8) + iv[4];
   iv[4] = temp & 0xFF;
}

#endif
