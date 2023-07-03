/**
 * @file sftp_server_packet.c
 * @brief SFTP packet parsing and formatting
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
#include "ssh/ssh_misc.h"
#include "sftp/sftp_server.h"
#include "sftp/sftp_server_file.h"
#include "sftp/sftp_server_directory.h"
#include "sftp/sftp_server_packet.h"
#include "sftp/sftp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Parse SSH_FXP_INIT packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpInit(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t version;

   //Debug message
   TRACE_INFO("SSH_FXP_INIT packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Malformed packet?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The SSH_FXP_INIT packet contains the client version
   version = LOAD32BE(packet);

   //Sanity check
   if(version < SFTP_SERVER_MIN_VERSION)
      return ERROR_INVALID_VERSION;

   //The server responds with an SSH_FXP_VERSION packet, supplying the lowest
   //of its own and the client's version number. Both parties should from then
   //on adhere to particular version of the protocol
   session->version = (SftpVersion) MIN(version, SFTP_SERVER_MAX_VERSION);

   //Send an SSH_FXP_VERSION packet to the client
   error = sftpFormatFxpVersion(session, session->version);

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_OPEN packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpOpen(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   size_t n;
   uint32_t id;
   uint32_t pflags;
   uint32_t handle;
   const uint8_t *p;
   SshString filename;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_OPEN packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get filename
   error = sshParseString(p, length, &filename);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + filename.length;
   length -= sizeof(uint32_t) + filename.length;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get pflags
   pflags = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse ATTRS compound data
   error = sftpParseAttributes(session->version, &attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(length != n)
      return ERROR_INVALID_PACKET;

   //Open the specified file
   error = sftpServerOpenFile(session, &filename, pflags, &attributes,
      &handle);

   //Check status code
   if(error == NO_ERROR)
   {
      //The server will respond to this request with an SSH_FXP_HANDLE packet
      error = sftpFormatFxpHandle(session, id, handle);
   }
   else if(error == ERROR_OUT_OF_RESOURCES)
   {
      //Too many files have been open
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Too many open files");
   }
   else
   {
      //The specified path name does not exist
      error = sftpFormatFxpStatus(session, id, SSH_FX_NO_SUCH_FILE,
         "No such file");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_CLOSE packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpClose(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString handle;

   //Debug message
   TRACE_INFO("SSH_FXP_CLOSE packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + handle.length))
      return ERROR_INVALID_PACKET;

   //An SSH_FXP_CLOSE request can be used to close a file
   error = sftpServerCloseFile(session, &handle);

   //Check status code
   if(error)
   {
      //This request can also be used to close a directory
      error = sftpServerCloseDir(session, &handle);
   }

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_READ packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpRead(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   uint32_t dataLen;
   uint64_t offset;
   const uint8_t *p;
   SshBinaryString handle;

   //Debug message
   TRACE_DEBUG("SSH_FXP_READ packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + handle.length;
   length -= sizeof(uint32_t) + handle.length;

   //Malformed packet?
   if(length < sizeof(uint64_t))
      return ERROR_INVALID_PACKET;

   //The 'offset' field is the offset is relative to the beginning of the
   //file from where to start reading
   offset = LOAD64BE(p);

   //Point to the next field
   p += sizeof(uint64_t);
   length -= sizeof(uint64_t);

   //Malformed packet?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The 'len' field is the maximum number of bytes to read
   dataLen = LOAD32BE(p);

   //Read data from the specified file
   error = sftpServerReadFile(session, &handle, offset, &dataLen);

   //Check status code
   if(!error)
   {
      //In response to this request, the server will read as many bytes as it
      //can from the file (up to 'len'), and return them in an SSH_FXP_DATA
      //message
      error = sftpFormatFxpData(session, id, dataLen);
   }

   //Check status code
   if(error == NO_ERROR)
   {
      //Successful read operation
   }
   else if(error == ERROR_END_OF_STREAM)
   {
      //End-of-file condition
      error = sftpFormatFxpStatus(session, id, SSH_FX_EOF, "No more data");
   }
   else if(error == ERROR_INVALID_HANDLE)
   {
      //The supplied handle is not valid
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }
   else
   {
      //Generic error
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Failed to read data");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_WRITE packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpWrite(SftpServerSession *session,
   const uint8_t *packet, size_t fragLen, size_t totalLen)
{
   error_t error;
   uint64_t offset;
   const uint8_t *p;
   SshBinaryString handle;
   SshBinaryString data;

   //Debug message
   TRACE_DEBUG("SSH_FXP_WRITE packet received (%" PRIuSIZE " bytes)...\r\n", totalLen);
   TRACE_VERBOSE_ARRAY("  ", packet, fragLen);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(fragLen < sizeof(uint32_t) || fragLen > totalLen)
      return ERROR_INVALID_PACKET;

   //Get request identifier
   session->requestId = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   fragLen -= sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, fragLen, &handle);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + handle.length;
   fragLen -= sizeof(uint32_t) + handle.length;
   totalLen -= sizeof(uint32_t) + handle.length;

   //Malformed packet?
   if(fragLen < sizeof(uint64_t))
      return ERROR_INVALID_PACKET;

   //The 'offset' field is the offset from the beginning of the file where
   //to start writing
   offset = LOAD64BE(p);

   //Point to the next field
   p += sizeof(uint64_t);
   fragLen -= sizeof(uint64_t);
   totalLen -= sizeof(uint64_t);

   //Malformed packet?
   if(fragLen < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The 'data' field is a byte string containing the data to be written
   error = sshParseBinaryString(p, totalLen, &data);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(totalLen != (sizeof(uint32_t) + data.length))
      return ERROR_INVALID_PACKET;

   //Point to the data payload
   p += sizeof(uint32_t);
   fragLen -= sizeof(uint32_t);
   totalLen -= sizeof(uint32_t);

   //Write data to the specified file
   error = sftpServerWriteFile(session, &handle, offset, p, fragLen, totalLen);

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_OPENDIR packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpOpenDir(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   uint32_t handle;
   const uint8_t *p;
   SshString path;

   //Debug message
   TRACE_INFO("SSH_FXP_OPENDIR packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the path name of the directory to be listed
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + path.length))
      return ERROR_INVALID_PACKET;

   //Open the specified directory
   error = sftpServerOpenDir(session, &path, &handle);

   //Check status code
   if(error == NO_ERROR)
   {
      //The server will respond to this request with an SSH_FXP_HANDLE packet
      error = sftpFormatFxpHandle(session, id, handle);
   }
   else if(error == ERROR_OUT_OF_RESOURCES)
   {
      //Too many files have been open
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Too many open files");
   }
   else
   {
      //The specified path name does not exist
      error = sftpFormatFxpStatus(session, id, SSH_FX_NO_SUCH_FILE,
         "No such directory");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_READDIR packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpReadDir(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString handle;
   SftpName name;

   //Debug message
   TRACE_DEBUG("SSH_FXP_READDIR packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + handle.length))
      return ERROR_INVALID_PACKET;

   //Read a new entry from the directory
   error = sftpServerReadDir(session, &handle, &name);

   //Check status code
   if(error == NO_ERROR)
   {
      //Each SSH_FXP_READDIR request returns one or more file names with full
      //file attributes for each file
      error = sftpFormatFxpName(session, id, &name);
   }
   else if(error == ERROR_END_OF_STREAM)
   {
      //Return an SSH_FX_EOF if there are no more files in the directory
      error = sftpFormatFxpStatus(session, id, SSH_FX_EOF, "No more files");
   }
   else if(error == ERROR_INVALID_HANDLE)
   {
      //The supplied handle is not valid
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }
   else
   {
      //Generic error
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Failed to read directory");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_REMOVE packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpRemove(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString filename;

   //Debug message
   TRACE_INFO("SSH_FXP_REMOVE packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The filename field specifies the file to be removed
   error = sshParseString(p, length, &filename);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + filename.length))
      return ERROR_INVALID_PACKET;

   //Remove the specified file
   error = sftpServerRemoveFile(session, &filename);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Cannot remove file");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_MKDIR packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpMkDir(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   size_t n;
   uint32_t id;
   const uint8_t *p;
   SshString path;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_MKDIR packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the directory to be created
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + path.length;
   length -= sizeof(uint32_t) + path.length;

   //Parse ATTRS compound data
   error = sftpParseAttributes(session->version, &attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(length != n)
      return ERROR_INVALID_PACKET;

   //Create the specified directory
   error = sftpServerCreateDir(session, &path, &attributes);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Cannot create directory");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_RMDIR packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpRmDir(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString path;

   //Debug message
   TRACE_INFO("SSH_FXP_RMDIR packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the directory to be removed
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + path.length))
      return ERROR_INVALID_PACKET;

   //Remove the specified directory
   error = sftpServerRemoveDir(session, &path);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Cannot remove directory");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_REALPATH packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpRealPath(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString path;
   SftpName name;

   //Debug message
   TRACE_INFO("SSH_FXP_REALPATH packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the path name to be canonicalized
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + path.length))
      return ERROR_INVALID_PACKET;

   //Canonicalize the specified path name to an absolute path
   error = sftpServerGetRealPath(session, &path, &name);

   //Check status code
   if(!error)
   {
      //The server will respond with an SSH_FXP_NAME packet containing the
      //name in canonical form and a dummy attributes value
      error = sftpFormatFxpName(session, id, &name);
   }
   else
   {
      //If an error occurs, the server may also respond with SSH_FXP_STATUS
      error = sftpFormatFxpStatus(session, id, SSH_FX_NO_SUCH_FILE,
         "Invalid path");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_STAT packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpStat(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString path;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_STAT packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the file system object for which status is
   //to be returned
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + path.length))
      return ERROR_INVALID_PACKET;

   //Retrieve the attributes of the specified file
   error = sftpServerGetFileStat(session, &path, &attributes);

   //Check status code
   if(!error)
   {
      //The server responds to this request with SSH_FXP_ATTRS
      error = sftpFormatFxpAttrs(session, id, &attributes);
   }
   else
   {
      //If an error occurs, the server may also respond with SSH_FXP_STATUS
      error = sftpFormatFxpStatus(session, id, SSH_FX_NO_SUCH_FILE,
         "No such file");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_FSTAT packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpFstat(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString handle;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_FSTAT packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + handle.length))
      return ERROR_INVALID_PACKET;

   //Retrieve the attributes of the specified file
   error = sftpServerGetFileStatEx(session, &handle, &attributes);

   //Check status code
   if(!error)
   {
      //The server responds to this request with SSH_FXP_ATTRS
      error = sftpFormatFxpAttrs(session, id, &attributes);
   }
   else
   {
      //If an error occurs, the server may also respond with SSH_FXP_STATUS
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_SETSTAT packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpSetStat(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   size_t n;
   uint32_t id;
   const uint8_t *p;
   SshString path;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_SETSTAT packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The path field specifies the file system object for which status is
   //to be returned
   error = sshParseString(p, length, &path);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + path.length;
   length -= sizeof(uint32_t) + path.length;

   //Parse ATTRS compound data
   error = sftpParseAttributes(session->version, &attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(length != n)
      return ERROR_INVALID_PACKET;

   //Modify the attributes of the specified file
   error = sftpServerSetFileStat(session, &path, &attributes);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_FSETSTAT packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpSetFstat(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   size_t n;
   uint32_t id;
   const uint8_t *p;
   SshBinaryString handle;
   SftpFileAttrs attributes;

   //Debug message
   TRACE_INFO("SSH_FXP_FSETSTAT packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Get handle
   error = sshParseBinaryString(p, length, &handle);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + handle.length;
   length -= sizeof(uint32_t) + handle.length;

   //Parse ATTRS compound data
   error = sftpParseAttributes(session->version, &attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Malformed packet?
   if(length != n)
      return ERROR_INVALID_PACKET;

   //Modify the attributes of the specified file
   error = sftpServerSetFileStatEx(session, &handle, &attributes);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Invalid handle");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_RENAME packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpRename(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString oldPath;
   SshString newPath;

   //Debug message
   TRACE_INFO("SSH_FXP_RENAME packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The oldpath field is the name of an existing file or directory
   error = sshParseString(p, length, &oldPath);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + oldPath.length;
   length -= sizeof(uint32_t) + oldPath.length;

   //The newpath field is the new name for the file or directory
   error = sshParseString(p, length, &newPath);
   //Any error to report?
   if(error)
      return error;

   //Malformed message?
   if(length != (sizeof(uint32_t) + newPath.length))
      return ERROR_INVALID_PACKET;

   //Rename the specified file
   error = sftpServerRenameFile(session, &oldPath, &newPath);

   //Check status code
   if(!error)
   {
      //When the operation is successful, the server responds with an
      //SSH_FXP_STATUS message with SSH_FX_OK status
      error = sftpFormatFxpStatus(session, id, SSH_FX_OK, "Success");
   }
   else
   {
      //If an error occurs, the server responds with an SSH_FXP_STATUS
      //message message indicating an failure
      error = sftpFormatFxpStatus(session, id, SSH_FX_FAILURE,
         "Cannot rename file");
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_FXP_EXTENDED packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to packet
 * @param[in] length Length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParseFxpExtended(SftpServerSession *session,
   const uint8_t *packet, size_t length)
{
   error_t error;
   uint32_t id;
   const uint8_t *p;
   SshString extendedRequest;

   //Debug message
   TRACE_INFO("SSH_FXP_EXTENDED packet received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", packet, length);

   //Point to the first field of the packet
   p = packet;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //Get request identifier
   id = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The 'extended-request' field is a string of the format "name@domain", where
   //domain is an Internet domain name of the vendor defining the request
   error = sshParseString(p, length, &extendedRequest);
   //Any error to report?
   if(error)
      return error;

   //If the server does not recognize the 'extended-request' name, then
   //the server must respond with SSH_FXP_STATUS with error/status set to
   //SSH_FX_OP_UNSUPPORTED
   error = sftpFormatFxpStatus(session, id, SSH_FX_OP_UNSUPPORTED,
      "Extended request not supported");

   //Return status code
   return error;
}


/**
 * @brief Format SSH_FXP_VERSION packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] version Protocol version number
 * @return Error code
 **/

error_t sftpFormatFxpVersion(SftpServerSession *session, uint32_t version)
{
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_VERSION;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //The SSH_FXP_VERSION packet contains the lowest of its own and the
   //client's version number
   STORE32BE(version, p);

   //Total length of the packet
   length += sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_VERSION packet (%" PRIuSIZE " bytes)...\r\n", session->bufferLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_STATUS message
 * @param[in] session Handle referencing an SFTP session
 * @param[in] id Request identifier
 * @param[in] statusCode Result of the requested operation
 * @param[in] message NULL-terminating description string
 * @return Error code
 **/

error_t sftpFormatFxpStatus(SftpServerSession *session, uint32_t id,
   uint32_t statusCode, const char_t *message)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_STATUS;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //Format request identifier
   STORE32BE(id, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Format status code
   STORE32BE(statusCode, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Copy the description string
   error = sshFormatString(message, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Set language tag
   error = sshFormatString("en", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_DEBUG("Sending SSH_FXP_STATUS packet (%" PRIuSIZE " bytes)...\r\n", session->bufferLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_HANDLE message
 * @param[in] session Handle referencing an SFTP session
 * @param[in] id Request identifier
 * @param[in] handle Opaque value that identifies a file or directory
 * @return Error code
 **/

error_t sftpFormatFxpHandle(SftpServerSession *session, uint32_t id,
   uint32_t handle)
{
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_HANDLE;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //Format request identifier
   STORE32BE(id, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The handle field is an arbitrary string that identifies a file or
   //directory on the server
   STORE32BE(handle, p + sizeof(uint32_t));

   //The string is preceded by a uint32 containing its length
   STORE32BE(sizeof(uint32_t), p);

   //Total length of the message
   length += 2 * sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_HANDLE packet (%" PRIuSIZE " bytes)...\r\n", session->bufferLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_DATA message
 * @param[in] session Handle referencing an SFTP session
 * @param[in] id Request identifier
 * @param[in] dataLen Length of the data string, in bytes
 * @return Error code
 **/

error_t sftpFormatFxpData(SftpServerSession *session, uint32_t id,
   size_t dataLen)
{
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_DATA;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //Format request identifier
   STORE32BE(id, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //The data string is preceded by a uint32 containing its length
   STORE32BE(dataLen, p);

   //Point to the data payload
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Convert the length field to network byte order
   header->length = htonl(length + dataLen);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_DEBUG("Sending SSH_FXP_DATA packet (%" PRIuSIZE " bytes)...\r\n",
      session->bufferLen + session->dataLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING_DATA;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_NAME packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] id Request identifier
 * @param[in] name Pointer to the name structure
 * @return Error code
 **/

error_t sftpFormatFxpName(SftpServerSession *session, uint32_t id,
   const SftpName *name)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_NAME;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //Format request identifier
   STORE32BE(id, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Number of names returned in this response
   STORE32BE(1, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Format name structure
   error = sftpFormatName(session->version, name, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_DEBUG("Sending SSH_FXP_NAME packet (%" PRIuSIZE " bytes)...\r\n", session->bufferLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_FXP_ATTRS packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] id Request identifier
 * @param[in] attributes File attributes
 * @return Error code
 **/

error_t sftpFormatFxpAttrs(SftpServerSession *session, uint32_t id,
   const SftpFileAttrs *attributes)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   SftpPacketHeader *header;

   //Point to the buffer where to format the packet
   header = (SftpPacketHeader *) session->buffer;

   //Set packet type
   header->type = SSH_FXP_ATTRS;
   //Total length of the packet
   length = sizeof(uint8_t);

   //Point the data payload
   p = header->payload;

   //Format request identifier
   STORE32BE(id, p);

   //Point to the next field
   p += sizeof(uint32_t);
   length += sizeof(uint32_t);

   //Format ATTRS compound data
   error = sftpFormatAttributes(session->version, attributes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   length += n;

   //Convert the length field to network byte order
   header->length = htonl(length);

   //The packet length does not include the length field itself
   session->bufferLen = length + sizeof(uint32_t);
   session->bufferPos = 0;

   //Debug message
   TRACE_INFO("Sending SSH_FXP_ATTRS packet (%" PRIuSIZE " bytes)...\r\n", session->bufferLen);
   TRACE_VERBOSE_ARRAY("  ", session->buffer, session->bufferLen);

   //Send the packet to the SFTP client
   session->state = SFTP_SERVER_SESSION_STATE_SENDING;

   //Successful processing
   return NO_ERROR;
}

#endif
