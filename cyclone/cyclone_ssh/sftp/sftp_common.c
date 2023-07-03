/**
 * @file sftp_common.c
 * @brief Definitions common to SFTP client and server
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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
#include "sftp/sftp_common.h"
#include "debug.h"


/**
 * @brief Format name structure
 * @param[in] version Protocol version
 * @param[in] name Pointer to the name structure
 * @param[in] p Buffer where to format the name structure
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sftpFormatName(SftpVersion version, const SftpName *name,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Total number of bytes that have been written
   *written = 0;

   //Format the file name
   error = sshFormatBinaryString(name->filename.value, name->filename.length,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The long file name has been removed in version 4
   if(version <= SFTP_VERSION_3)
   {
      //Format the long file name
      error = sftpFormatLongFilename(&name->filename, &name->attributes,
         (char_t *) p + 4, &n);
      //Any error to report?
      if(error)
         return error;

      //The string is preceded by a uint32 containing its length
      STORE32BE(n, p);

      //Point to the next field
      p += sizeof(uint32_t) + n;
      *written += sizeof(uint32_t) + n;
   }

   //Format ATTRS compound data
   error = sftpFormatAttributes(version, &name->attributes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format long file name
 * @param[in] filename File name
 * @param[in] attributes File attributes
 * @param[in] p Buffer where to format the long file name
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sftpFormatLongFilename(const SshString *filename,
   const SftpFileAttrs *attributes, char_t *p, size_t *written)
{
   size_t n;
   time_t time;
   time_t modified;

   //Abbreviated months
   static const char_t months[13][4] =
   {
      "   ",
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec"
   };

   //Valid attributes?
   if(attributes->flags != 0)
   {
      //Format links, owner, group and size fields
      n = osSprintf(p, "----------   1 owner    group    %10" PRIu64,
         attributes->size);

      //Check whether the current entry is a directory
      if(attributes->type == SSH_FILEXFER_TYPE_DIRECTORY)
      {
         p[0] = 'd';
      }

      //Check user permissions
      if((attributes->permissions & SFTP_MODE_IRUSR) != 0)
      {
         p[1] = 'r';
      }

      if((attributes->permissions & SFTP_MODE_IWUSR) != 0)
      {
         p[2] = 'w';
      }

      if((attributes->permissions & SFTP_MODE_IXUSR) != 0)
      {
         p[3] = 'x';
      }

      //Check group permissions
      if((attributes->permissions & SFTP_MODE_IRGRP) != 0)
      {
         p[4] = 'r';
      }

      if((attributes->permissions & SFTP_MODE_IWGRP) != 0)
      {
         p[5] = 'w';
      }

      if((attributes->permissions & SFTP_MODE_IXGRP) != 0)
      {
         p[6] = 'x';
      }

      //Check other (everyone) permissions
      if((attributes->permissions & SFTP_MODE_IROTH) != 0)
      {
         p[7] = 'r';
      }

      if((attributes->permissions & SFTP_MODE_IWOTH) != 0)
      {
         p[8] = 'w';
      }

      if((attributes->permissions & SFTP_MODE_IXOTH) != 0)
      {
         p[9] = 'x';
      }

      //Get current time
      time = getCurrentUnixTime();
      //Get modification time
      modified = convertDateToUnixTime(&attributes->mtime);

      //Check whether the modification time is within the previous 180 days
      if(time > modified && time < (modified + SFTP_180_DAYS))
      {
         //The format of the date/time field is Mmm dd hh:mm
         n += osSprintf(p + n, " %s %02" PRIu8 " %02" PRIu8 ":%02" PRIu8,
            months[MIN(attributes->mtime.month, 12)], attributes->mtime.day,
            attributes->mtime.hours, attributes->mtime.minutes);
      }
      else
      {
         //The format of the date/time field is Mmm dd  yyyy
         n += osSprintf(p + n, " %s %02" PRIu8 "  %04" PRIu16,
            months[MIN(attributes->mtime.month, 12)], attributes->mtime.day,
            attributes->mtime.year);
      }

      //Append a space character
      p[n++] = ' ';
   }
   else
   {
      //The file attributes are not valid
      n = 0;
   }

   //Copy file name
   osMemcpy(p + n, filename->value, filename->length);

   //Total number of bytes that have been written
   *written = n + filename->length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format file attributes
 * @param[in] version Protocol version
 * @param[in] attributes File attributes
 * @param[in] p Buffer where to format the attributes
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sftpFormatAttributes(SftpVersion version,
   const SftpFileAttrs *attributes, uint8_t *p, size_t *written)
{
   time_t time;
   uint32_t permissions;

   //Total number of bytes that have been written
   *written = 0;

   //The flags specify which of the fields are present
   STORE32BE(attributes->flags, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Version 4 splits the file type out of the permissions field and into
   //its own field (which is always present)
   if(version >= SFTP_VERSION_4)
   {
      //The 'type' field is encoded as a byte
      p[0] = (uint8_t) attributes->type;

      //Point to the next field
      p += sizeof(uint8_t);
      *written += sizeof(uint8_t);
   }

   //The 'size' field is optional
   if((attributes->flags & SSH_FILEXFER_ATTR_SIZE) != 0)
   {
      //The size field specifies the size of the file in bytes
      STORE64BE(attributes->size, p);

      //Point to the next field
      p += sizeof(uint64_t);
      *written += sizeof(uint64_t);
   }

   //The 'uid' and 'gid' fields are optional
   if((attributes->flags & SSH_FILEXFER_ATTR_UIDGID) != 0)
   {
      //The 'uid' field contains numeric Unix-like user identifier
      STORE32BE(attributes->uid, p);

      //Point to the next field
      p += sizeof(uint32_t);
      *written += sizeof(uint32_t);

      //The 'gid' field contains numeric Unix-like group identifier
      STORE32BE(attributes->gid, p);

      //Point to the next field
      p += sizeof(uint32_t);
      *written += sizeof(uint32_t);
   }

   //The 'permissions' field is optional
   if((attributes->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0)
   {
      //The 'permissions' field contains a bit mask of file permissions
      permissions = attributes->permissions & ~SFTP_MODE_IFMT;

      //Check SFTP protocol version
      if(version <= SFTP_VERSION_3)
      {
         //Convert file type to permission bits
         permissions |= sftpConvertFileTypeToPerm(attributes->type);
      }

      //The 'permissions' field is encoded as a 32-bit integer
      STORE32BE(permissions, p);

      //Point to the next field
      p += sizeof(uint32_t);
      *written += sizeof(uint32_t);
   }

   //The 'atime' and 'mtime' fields are optional
   if((attributes->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0)
   {
      //The 'atime' field contain the access time of the file
      time = convertDateToUnixTime(&attributes->atime);
      //The time is represented as seconds from Jan 1, 1970 in UTC
      STORE32BE(time, p);

      //Point to the next field
      p += sizeof(uint32_t);
      *written += sizeof(uint32_t);

      //The 'mtime' field contain the modification time of the file
      time = convertDateToUnixTime(&attributes->mtime);
      //The time is represented as seconds from Jan 1, 1970 in UTC
      STORE32BE(time, p);

      //Point to the next field
      p += sizeof(uint32_t);
      *written += sizeof(uint32_t);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse name structure
 * @param[in] version Protocol version
 * @param[out] name Pointer to the name structure
 * @param[in] data Input data stream
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t sftpParseName(SftpVersion version, SftpName *name, const uint8_t *data,
   size_t length, size_t *consumed)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Clear name structure
   osMemset(name, 0, sizeof(SftpName));

   //Point to the input data stream
   p = data;

   //Decode the file name
   error = sshParseString(p, length, &name->filename);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + name->filename.length;
   length -= sizeof(uint32_t) + name->filename.length;

   //The long file name has been removed in version 4
   if(version <= SFTP_VERSION_3)
   {
      //Decode the long file name
      error = sshParseString(p, length, &name->longname);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + name->longname.length;
      length -= sizeof(uint32_t) + name->longname.length;
   }

   //Parse ATTRS compound data
   error = sftpParseAttributes(version, &name->attributes, p, length, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length -= n;

   //Check SFTP protocol version
   if(version <= SFTP_VERSION_3)
   {
      //Unknown file type?
      if(name->attributes.type == SSH_FILEXFER_TYPE_UNKNOWN &&
         name->longname.length > 0)
      {
         //Check file type
         if(name->longname.value[0] == 'd')
         {
            name->attributes.type = SSH_FILEXFER_TYPE_DIRECTORY;
         }
         else
         {
            name->attributes.type = SSH_FILEXFER_TYPE_REGULAR;
         }
      }
   }

   //Total number of bytes that have been consumed
   *consumed = p - data;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse file attributes
 * @param[in] version Protocol version
 * @param[out] attributes File attributes
 * @param[in] data Pointer to ATTRS compound data
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t sftpParseAttributes(SftpVersion version, SftpFileAttrs *attributes,
   const uint8_t *data, size_t length, size_t *consumed)
{
   error_t error;
   time_t time;
   uint32_t i;
   uint32_t extendedCount;
   SshString extendedType;
   SshString extendedData;
   const uint8_t *p;

   //Clear file attributes
   osMemset(attributes, 0, sizeof(SftpFileAttrs));

   //Point to the first byte of the ATTRS compound data
   p = data;

   //Malformed packet?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_PACKET;

   //The flags specify which of the fields are present
   attributes->flags = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Version 4 splits the file type out of the permissions field and into
   //its own field (which is always present)
   if(version >= SFTP_VERSION_4)
   {
      //Malformed packet?
      if(length < sizeof(uint8_t))
         return ERROR_INVALID_PACKET;

      //The 'type' field is always present in version 4
      attributes->type = (SftpFileType) p[0];

      //Point to the next field
      p += sizeof(uint8_t);
      length -= sizeof(uint8_t);
   }
   else
   {
      //The 'type' field is not present in version 3
      attributes->type = SSH_FILEXFER_TYPE_UNKNOWN;
   }

   //Check if the 'size' field is present?
   if((attributes->flags & SSH_FILEXFER_ATTR_SIZE) != 0)
   {
      //Malformed packet?
      if(length < sizeof(uint64_t))
         return ERROR_INVALID_PACKET;

      //The 'size' field specifies the size of the file in bytes
      attributes->size = LOAD64BE(p);

      //Point to the next field
      p += sizeof(uint64_t);
      length -= sizeof(uint64_t);
   }

   //Check if the 'uid' and 'gid' fields are present?
   if((attributes->flags & SSH_FILEXFER_ATTR_UIDGID) != 0)
   {
      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //The 'uid' field contains numeric Unix-like user identifier
      attributes->uid = LOAD32BE(p);

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);

      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //The 'gid' field contains numeric Unix-like group identifier
      attributes->gid = LOAD32BE(p);

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);
   }

   //Check if the 'permissions' field is present?
   if((attributes->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0)
   {
      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //The 'permissions' field contains a bit mask of file permissions
      attributes->permissions = LOAD32BE(p);

      //Check SFTP protocol version
      if(version <= SFTP_VERSION_3)
      {
         //Extract file type from permission bits
         attributes->type = sftpConvertPermToFileType(attributes->permissions);
      }

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);
   }

   //Check if the 'atime' and 'mtime' fields are present?
   if((attributes->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0)
   {
      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //The 'atime' field contain the access time of the file
      time = LOAD32BE(p);
      //The time is represented as seconds from Jan 1, 1970 in UTC
      convertUnixTimeToDate(time, &attributes->atime);

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);

      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //The 'mtime' field contain the modification time of the file
      time = LOAD32BE(p);
      //The time is represented as seconds from Jan 1, 1970 in UTC
      convertUnixTimeToDate(time, &attributes->mtime);

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);
   }

   //Check if the 'extended_count' field is present?
   if((attributes->flags & SSH_FILEXFER_ATTR_EXTENDED) != 0)
   {
      //Malformed packet?
      if(length < sizeof(uint32_t))
         return ERROR_INVALID_PACKET;

      //Parse the 'extended_count' field
      extendedCount = LOAD32BE(p);

      //Point to the next field
      p += sizeof(uint32_t);
      length -= sizeof(uint32_t);
   }
   else
   {
      //The 'extended_count' field is not present
      extendedCount = 0;
   }

   //The 'extended_count' field specifies the number of extended type/data
   //pairs that follow
   for(i = 0; i < extendedCount; i++)
   {
      //For each of the attributes, the 'extended_type' field should be a
      //string of the format "name@domain"
      error = sshParseString(p, length, &extendedType);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + extendedType.length;
      length -= sizeof(uint32_t) + extendedType.length;

      //The interpretation of 'extended_data' depends on the type
      error = sshParseString(p, length, &extendedData);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += sizeof(uint32_t) + extendedData.length;
      length -= sizeof(uint32_t) + extendedData.length;
   }

   //Total number of bytes that have been consumed
   *consumed = p - data;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract file type from permission bits
 * @param[in] permissions Permission bits
 * @return File type
 **/

SftpFileType sftpConvertPermToFileType(uint32_t permissions)
{
   SftpFileType type;

   //Check permission bits
   switch(permissions & SFTP_MODE_IFMT)
   {
   case SFTP_MODE_IFREG:
      //The file is a regular file
      type = SSH_FILEXFER_TYPE_REGULAR;
      break;
   case SFTP_MODE_IFDIR:
      //The file is a directory
      type = SSH_FILEXFER_TYPE_DIRECTORY;
      break;
   case SFTP_MODE_IFLNK:
      //The file is a symbolic link
      type = SSH_FILEXFER_TYPE_SYMLINK;
      break;
   case SFTP_MODE_IFSOCK:
      //The file is a socket
      type = SSH_FILEXFER_TYPE_SOCKET;
      break;
   case SFTP_MODE_IFCHR:
      //The file is a character special file
      type = SSH_FILEXFER_TYPE_CHAR_DEVICE;
      break;
   case SFTP_MODE_IFBLK:
      //The file is a block special file
      type = SSH_FILEXFER_TYPE_BLOCK_DEVICE;
      break;
   case SFTP_MODE_IFIFO:
      //The file is a FIFO special file or a pipe
      type = SSH_FILEXFER_TYPE_FIFO;
      break;
   default:
      //The file type is unknown
      type = SSH_FILEXFER_TYPE_UNKNOWN;
      break;
   }

   //Return file type
   return type;
}


/**
 * @brief Convert file type to permission bits
 * @param[in] type File type
 * @return Permission bits
 **/

uint32_t sftpConvertFileTypeToPerm(SftpFileType type)
{
   uint32_t permissions;

   //Check file type
   switch(type)
   {
   case SSH_FILEXFER_TYPE_REGULAR:
      //The file is a regular file
      permissions = SFTP_MODE_IFREG;
      break;
   case SSH_FILEXFER_TYPE_DIRECTORY:
      //The file is a directory
      permissions = SFTP_MODE_IFDIR;
      break;
   case SSH_FILEXFER_TYPE_SYMLINK:
      //The file is a symbolic link
      permissions = SFTP_MODE_IFLNK;
      break;
   case SSH_FILEXFER_TYPE_SOCKET:
      //The file is a socket
      permissions = SFTP_MODE_IFSOCK;
      break;
   case SSH_FILEXFER_TYPE_CHAR_DEVICE:
      //The file is a character special file
      permissions = SFTP_MODE_IFCHR;
      break;
   case SSH_FILEXFER_TYPE_BLOCK_DEVICE:
      //The file is a block special file
      permissions = SFTP_MODE_IFBLK;
      break;
   case SSH_FILEXFER_TYPE_FIFO:
      //The file is a FIFO special file or a pipe
      permissions = SFTP_MODE_IFIFO;
      break;
   default:
      //The file type is unknown
      permissions = 0;
      break;
   }

   //Return permission bits
   return permissions;
}
