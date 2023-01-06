/**
 * @file sftp_client.c
 * @brief SFTP client
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
#define TRACE_LEVEL SFTP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_misc.h"
#include "sftp/sftp_client_packet.h"
#include "sftp/sftp_client_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format SSH_FXP_INIT packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] version Protocol version number
 * @return Error code
 **/

error_t sftpClientFormatFxpInit(SftpClientContext *context,
   uint32_t version)
{
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_INIT;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The SSH_FXP_INIT packet contains the client version
   STORE32BE(version, p);

   //Total length of the packet
   length += sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_INIT packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_OPEN packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] filename Name to the file to be be opened or created
 * @param[in] pflags File access mode
 * @return Error code
 **/

error_t sftpClientFormatFxpOpen(SftpClientContext *context,
   const char_t *filename, uint32_t pflags)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;
   SftpFileAttrs attributes;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_OPEN;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The filename field specifies the name to the file to be be opened
   error = sftpFormatPath(context, filename, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Encode pflags field
   STORE32BE(pflags, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The 'attrs' field specifies the initial attributes for the file. Default
   //values will be used for those attributes that are not specified
   osMemset(&attributes, 0, sizeof(SftpFileAttrs));

   //Format ATTRS compound data
   error = sftpFormatAttributes(context->version, &attributes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_OPEN packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_CLOSE packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] handle File handle returned by SSH_FXP_OPEN or SSH_FXP_OPENDIR
 * @param[in] handleLen Length of the handle string, in bytes
 * @return Error code
 **/

error_t sftpClientFormatFxpClose(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_CLOSE;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The handle field is a handle previously returned in the response to
   //SSH_FXP_OPEN or SSH_FXP_OPENDIR
   error = sshFormatBinaryString(handle, handleLen, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_CLOSE packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_READ packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] handle File handle returned by SSH_FXP_OPEN
 * @param[in] handleLen Length of the handle string, in bytes
 * @param[in] offset Offset relative to the beginning of the file from where
 *   to start reading
 * @param[in] dataLen Maximum number of bytes to read
 * @return Error code
 **/

error_t sftpClientFormatFxpRead(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen, uint64_t offset, uint32_t dataLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_READ;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The handle field is a handle previously returned in the response to
   //SSH_FXP_OPEN
   error = sshFormatBinaryString(handle, handleLen, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The 'offset' field is the offset relative to the beginning of the file
   //from where to start reading
   STORE64BE(offset, p);

   //Point to the next field
   p += sizeof(uint64_t);
   length += sizeof(uint64_t);

   //The 'len' field is the maximum number of bytes to read
   STORE32BE(dataLen, p);

   //Total length of the packet
   length += sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the number of data bytes requested in the SSH_FXP_READ packet
   context->dataLen = dataLen;
   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_READ packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_WRITE packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] handle File handle returned by SSH_FXP_OPEN
 * @param[in] handleLen Length of the handle string, in bytes
 * @param[in] offset Offset relative to the beginning of the file from where
 *   to start writing
 * @param[in] dataLen Length of the data to be written
 * @return Error code
 **/

error_t sftpClientFormatFxpWrite(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen, uint64_t offset, uint32_t dataLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_WRITE;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The handle field is a handle previously returned in the response to
   //SSH_FXP_OPEN
   error = sshFormatBinaryString(handle, handleLen, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The 'offset' field is the offset relative to the beginning of the file
   //from where to start writing
   STORE64BE(offset, p);

   //Point to the next field
   p += sizeof(uint64_t);
   length += sizeof(uint64_t);

   //The 'data' field contains the data to be written
   STORE32BE(dataLen, p);

   //Total length of the packet
   length += sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length + dataLen);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the number of data bytes to be written
   context->dataLen = dataLen;
   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_WRITE packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen + dataLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_OPENDIR packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path name of the directory to be listed
 * @return Error code
 **/

error_t sftpClientFormatFxpOpenDir(SftpClientContext *context,
   const char_t *path)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_OPENDIR;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The path field specifies the directory to be listed
   error = sftpFormatPath(context, path, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_OPENDIR packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_READDIR packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] handle File handle returned by SSH_FXP_OPENDIR
 * @param[in] handleLen Length of the handle string, in bytes
 * @return Error code
 **/

error_t sftpClientFormatFxpReadDir(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_READDIR;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The handle field is a handle previously returned in the response to
   //SSH_FXP_OPENDIR
   error = sshFormatBinaryString(handle, handleLen, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_READDIR packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_REMOVE packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] filename Name of the file to be removed
 * @return Error code
 **/

error_t sftpClientFormatFxpRemove(SftpClientContext *context,
   const char_t *filename)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_REMOVE;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The filename field specifies the file to be removed
   error = sftpFormatPath(context, filename, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_REMOVE packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_MKDIR packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Directory to be created
 * @return Error code
 **/

error_t sftpClientFormatFxpMkDir(SftpClientContext *context,
   const char_t *path)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;
   SftpFileAttrs attributes;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_MKDIR;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The path field specifies the directory to be created
   error = sftpFormatPath(context, path, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The 'attrs' field specifies the modifications to be made to its attributes
   osMemset(&attributes, 0, sizeof(SftpFileAttrs));

   //Format ATTRS compound data
   error = sftpFormatAttributes(context->version, &attributes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_MKDIR packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_RMDIR packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Directory to be removed
 * @return Error code
 **/

error_t sftpClientFormatFxpRmDir(SftpClientContext *context,
   const char_t *path)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_RMDIR;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The path field specifies the directory to be removed
   error = sftpFormatPath(context, path, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_RMDIR packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_REALPATH packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path name to be canonicalized
 * @return Error code
 **/

error_t sftpClientFormatFxpRealPath(SftpClientContext *context,
   const char_t *path)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_REALPATH;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The path field specifies the path name to be canonicalized
   error = sshFormatString(path, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_REALPATH packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_STAT packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path File system object for which status is to be returned
 * @return Error code
 **/

error_t sftpClientFormatFxpStat(SftpClientContext *context,
   const char_t *path)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_STAT;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The path field specifies the file system object for which status is to be
   //returned
   error = sftpFormatPath(context, path, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_STAT packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_RENAME packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] oldPath Name of an existing file or directory
 * @param[in] newPath New name for the file or directory
 * @return Error code
 **/

error_t sftpClientFormatFxpRename(SftpClientContext *context,
   const char_t *oldPath, const char_t *newPath)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) context->buffer;

   //Set packet type
   header->type = SSH_FXP_RENAME;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The request identifier is used to match each response with the
   //corresponding request
   context->requestId++;

   //Format request identifier
   STORE32BE(context->requestId, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The oldpath field is the name of an existing file or directory
   error = sftpFormatPath(context, oldPath, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The newpath field is the new name for the file or directory
   error = sftpFormatPath(context, newPath, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the packet
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   context->requestLen = length + sizeof(uint32_t);
   context->requestPos = 0;
   context->responseLen = 0;
   context->responsePos = 0;

   //Save the SFTP packet type
   context->requestType = (SftpPacketType) header->type;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_RENAME packet (%" PRIuSIZE " bytes)...\r\n", context->requestLen);
   TRACE_VERBOSE_ARRAY("  ", context->buffer, context->requestLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_FXP_VERSION packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpVersion(SftpClientContext *context,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t version;
   const uint8_t *p;
   SshString extensionName;
   SshString extensionValue;

   //Debug message
   TRACE_INFO("SSH_FXP_VERSION packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //An SSH_FXP_VERSION packet is sent in response to an SSH_FXP_INIT request
   if(context->requestType != SSH_FXP_INIT)
      return ERROR_INVALID_TYPE;

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The SSH_FXP_VERSION packet contains the lowest of its own and the
   //client's version number
   version = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse extensions
   while(length > 0)
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
   }

   //Sanity check
   if(version < SFTP_CLIENT_MIN_VERSION || version > SFTP_CLIENT_MAX_VERSION)
      return ERROR_INVALID_VERSION;

   //From then on, both parties must use the same version of the protocol
   context->version = (SftpVersion) version;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_FXP_STATUS packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpStatus(SftpClientContext *context,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString errorMessage;
   SshString languageTag;

   //Debug message
   TRACE_INFO("SSH_FXP_STATUS packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //All requests can return an SSH_FXP_STATUS response upon failure
   if(context->requestType == SSH_FXP_INIT)
      return ERROR_INVALID_TYPE;

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Each response packet begins with the request identifier
   id = LOAD32BE(p);

   //The request identifier is used to match each response with the
   //corresponding request
   if(id != context->requestId)
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The status code indicates the result of the requested operation
   context->statusCode = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //In version 3, the SSH_FXP_STATUS message was changed to include fields
   //'error message' and 'language tag'
   if(context->version >= SFTP_VERSION_3)
   {
      //Decode description string
      error = sshParseString(p, length, &errorMessage);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + errorMessage.length;
      length -= sizeof(uint32_t) + errorMessage.length;

      //Decode language tag
      error = sshParseString(p, length, &languageTag);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + languageTag.length;
      length -= sizeof(uint32_t) + languageTag.length;
   }

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Check the result of the requested operation
   if(context->statusCode == SSH_FX_OK)
   {
      //If no data needs to be returned to the client, the SSH_FXP_STATUS
      //response with SSH_FX_OK status is appropriate
      if(context->requestType == SSH_FXP_CLOSE ||
         context->requestType == SSH_FXP_WRITE ||
         context->requestType == SSH_FXP_SETSTAT ||
         context->requestType == SSH_FXP_FSETSTAT ||
         context->requestType == SSH_FXP_REMOVE ||
         context->requestType == SSH_FXP_MKDIR ||
         context->requestType == SSH_FXP_RMDIR ||
         context->requestType == SSH_FXP_RENAME ||
         context->requestType == SSH_FXP_SYMLINK)
      {
         //The value SSH_FX_OK indicates success
         error = NO_ERROR;
      }
      else
      {
         //Unexpected SSH_FXP_STATUS packet
         error = ERROR_INVALID_TYPE;
      }
   }
   else
   {
      //All other values indicate failure
      error = ERROR_UNEXPECTED_RESPONSE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_HANDLE packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpHandle(SftpClientContext *context,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString handle;

   //Debug message
   TRACE_INFO("SSH_FXP_HANDLE packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //The SSH_FXP_HANDLE message is used to return a file handle (for
   //SSH_FXP_OPEN and SSH_FXP_OPENDIR requests)
   if(context->requestType != SSH_FXP_OPEN &&
      context->requestType != SSH_FXP_OPENDIR)
   {
      return ERROR_INVALID_TYPE;
   }

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Each response packet begins with the request identifier
   id = LOAD32BE(p);

   //The request identifier is used to match each response with the
   //corresponding request
   if(id != context->requestId)
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The handle field is an arbitrary string that identifies a file or
   //directory on the server
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + handle.length;
   length -= sizeof(uint32_t) + handle.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_PACKET;

   //The length of the handle string must not exceed 256 data bytes
   if(handle.length > SFTP_CLIENT_MAX_HANDLE_SIZE)
      return ERROR_INVALID_HANDLE;

   //The handle is opaque to the client. The client must not attempt to
   //interpret or modify it in any way
   osMemcpy(context->handle, handle.value, handle.length);

   //Save the length of the handle string
   context->handleLen = handle.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_FXP_DATA packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpData(SftpClientContext *context,
   const uint8_t *packet, size_t fragLen, size_t totalLen)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString data;

   //Debug message
   TRACE_INFO("SSH_FXP_DATA packet received (%" PRIuSIZE " bytes)...\r\n", totalLen);
   TRACE_VERBOSE_ARRAY("  ", packet, fragLen);

   //Sanity check
   if(fragLen != sizeof(SftpFxpDataHeader))
      return ERROR_INVALID_PACKET;

   //SSH_FXP_DATA is used to return data from SSH_FXP_READ
   if(context->requestType != SSH_FXP_READ)
      return ERROR_INVALID_TYPE;

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(totalLen < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Each response packet begins with the request identifier
   id = LOAD32BE(p);

   //The request identifier is used to match each response with the
   //corresponding request
   if(id != context->requestId)
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   p += sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //The data field is a byte string containing the requested data
   error = sshParseBinaryString(p, totalLen, &data);
   //Any error to report?
   if(error)
      return error;

   //Point to the data payload
   p += sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //Malformed packet?
   if(data.length != totalLen)
      return ERROR_INVALID_PACKET;

   //The data string may be at most the number of bytes requested in a
   //SSH_FXP_READ request, but may also be shorter if end of file is reached
   if(data.length > context->dataLen)
      return ERROR_INVALID_LENGTH;

   //Save the actual number of data bytes in the SSH_FXP_DATA response
   context->dataLen = data.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_FXP_NAME packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpName(SftpClientContext *context,
   const uint8_t *packet, size_t fragLen, size_t totalLen)
{
   error_t error;
   size_t n;
   uint32_t id;
   uint32_t count;
   SftpName name;
   const uint8_t *p;

   //Debug message
   TRACE_INFO("SSH_FXP_NAME packet received (%" PRIuSIZE " bytes)...\r\n", totalLen);
   TRACE_VERBOSE_ARRAY("  ", packet, fragLen);

   //SSH_FXP_NAME is used to return one or more file names from an SSH_FXP_READDIR
   //or SSH_FXP_REALPATH request
   if(context->requestType != SSH_FXP_READDIR &&
      context->requestType != SSH_FXP_REALPATH)
   {
      return ERROR_INVALID_TYPE;
   }

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(fragLen < sizeof(uint32_t) || fragLen > totalLen)
      return ERROR_INVALID_PACKET;

   //Each response packet begins with the request identifier
   id = LOAD32BE(p);

   //The request identifier is used to match each response with the
   //corresponding request
   if(id != context->requestId)
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   p += sizeof(uint32_t);
   fragLen -= sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //Malformed packet?
   if(fragLen < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get the number of names returned in this response
   count = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   fragLen -= sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //SSH_FXP_READDIR or SSH_FXP_REALPATH request?
   if(context->requestType == SSH_FXP_READDIR)
   {
      //Each SSH_FXP_READDIR request returns one or more file names with full
      //file attributes for each file
      if(count < 1)
         return ERROR_INVALID_PACKET;
   }
   else
   {
      //The server will respond to an SSH_FXP_REALPATH request with an SSH_FXP_NAME
      //packet containing only one name and a dummy attributes value
      if(count != 1)
         return ERROR_INVALID_PACKET;

      //Parse file name and attributes
      error = sftpParseName(context->version, &name, p, fragLen, &n);
      //Any error to report?
      if(error)
         return error;

      //Malformed packet?
      if(fragLen != n || totalLen != n)
         return ERROR_INVALID_PACKET;
   }

   //Move the remaining data bytes to the start of the buffer
   osMemmove(context->buffer, p, fragLen);

   //Number of data bytes left to process
   context->dataLen = totalLen;
   context->responseLen = fragLen;
   context->responsePos = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_FXP_ATTRS packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParseFxpAttrs(SftpClientContext *context,
   const uint8_t *packet, size_t length)
{
   error_t error;
   size_t n;
   uint32_t id;
   const uint8_t *p;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_ATTRS packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //SSH_FXP_ATTRS is used to return file attributes from SSH_FXP_STAT,
   //SSH_FXP_LSTAT, and SSH_FXP_FSTAT requests
   if(context->requestType != SSH_FXP_STAT &&
      context->requestType != SSH_FXP_LSTAT &&
      context->requestType != SSH_FXP_FSTAT)
   {
      return ERROR_INVALID_TYPE;
   }

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Each response packet begins with the request identifier
   id = LOAD32BE(p);

   //The request identifier is used to match each response with the
   //corresponding request
   if(id != context->requestId)
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse ATTRS compound data
   error = sftpParseAttributes(context->version, &attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(length != n)
      return ERROR_INVALID_PACKET;

   //Move the remaining data bytes to the start of the buffer
   osMemmove(context->buffer, p, length);

   //Number of data bytes left to process
   context->dataLen = length;
   context->responseLen = length;
   context->responsePos = 0;

   //Successful processing
   return NO_ERROR;
}

#endif
