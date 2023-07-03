/**
 * @file sftp_common.h
 * @brief Definitions common to SFTP client and server
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

#ifndef _SFTP_COMMON_H
#define _SFTP_COMMON_H

//Dependencies
#include "ssh/ssh.h"
#include "date_time.h"

//Time constant
#define SFTP_180_DAYS (180 * 86400)

//File flags
#define SSH_FXF_READ   0x00000001
#define SSH_FXF_WRITE  0x00000002
#define SSH_FXF_APPEND 0x00000004
#define SSH_FXF_CREAT  0x00000008
#define SSH_FXF_TRUNC  0x00000010
#define SSH_FXF_EXCL   0x00000020

//Valid attribute flags
#define SSH_FILEXFER_ATTR_SIZE             0x00000001
#define SSH_FILEXFER_ATTR_UIDGID           0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS      0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME        0x00000008
#define SSH_FILEXFER_ATTR_ACCESSTIME       0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME       0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME       0x00000020
#define SSH_FILEXFER_ATTR_ACL              0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP       0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES  0x00000100
#define SSH_FILEXFER_ATTR_BITS             0x00000200
#define SSH_FILEXFER_ATTR_ALLOCATION_SIZE  0x00000400
#define SSH_FILEXFER_ATTR_TEXT_HINT        0x00000800
#define SSH_FILEXFER_ATTR_MIME_TYPE        0x00001000
#define SSH_FILEXFER_ATTR_LINK_COUNT       0x00002000
#define SSH_FILEXFER_ATTR_UNTRANLATED_NAME 0x00004000
#define SSH_FILEXFER_ATTR_EXTENDED         0x80000000

//File attribute bits
#define SSH_FILEXFER_ATTR_FLAGS_READONLY         0x00000001
#define SSH_FILEXFER_ATTR_FLAGS_SYSTEM           0x00000002
#define SSH_FILEXFER_ATTR_FLAGS_HIDDEN           0x00000004
#define SSH_FILEXFER_ATTR_FLAGS_CASE_INSENSITIVE 0x00000008
#define SSH_FILEXFER_ATTR_FLAGS_ARCHIVE          0x00000010
#define SSH_FILEXFER_ATTR_FLAGS_ENCRYPTED        0x00000020
#define SSH_FILEXFER_ATTR_FLAGS_COMPRESSED       0x00000040
#define SSH_FILEXFER_ATTR_FLAGS_SPARSE           0x00000080
#define SSH_FILEXFER_ATTR_FLAGS_APPEND_ONLY      0x00000100
#define SSH_FILEXFER_ATTR_FLAGS_IMMUTABLE        0x00000200
#define SSH_FILEXFER_ATTR_FLAGS_SYNC             0x00000400
#define SSH_FILEXFER_ATTR_FLAGS_TRANSLATION_ERR  0x00000800

//File permissions
#define SFTP_MODE_IXOTH  0x0001
#define SFTP_MODE_IWOTH  0x0002
#define SFTP_MODE_IROTH  0x0004
#define SFTP_MODE_IRWXO  0x0007
#define SFTP_MODE_IXGRP  0x0008
#define SFTP_MODE_IWGRP  0x0010
#define SFTP_MODE_IRGRP  0x0020
#define SFTP_MODE_IRWXG  0x0038
#define SFTP_MODE_IXUSR  0x0040
#define SFTP_MODE_IWUSR  0x0080
#define SFTP_MODE_IRUSR  0x0100
#define SFTP_MODE_IRWXU  0x01C0
#define SFTP_MODE_ISVTX  0x0200
#define SFTP_MODE_ISGID  0x0400
#define SFTP_MODE_ISUID  0x0800
#define SFTP_MODE_IFMT   0xF000
#define SFTP_MODE_IFIFO  0x1000
#define SFTP_MODE_IFCHR  0x2000
#define SFTP_MODE_IFDIR  0x4000
#define SFTP_MODE_IFBLK  0x6000
#define SFTP_MODE_IFREG  0x8000
#define SFTP_MODE_IFLNK  0xA000
#define SFTP_MODE_IFSOCK 0xC000

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SFTP protocol version
 **/

typedef enum
{
   SFTP_VERSION_0 = 0,
   SFTP_VERSION_1 = 1,
   SFTP_VERSION_2 = 2,
   SFTP_VERSION_3 = 3,
   SFTP_VERSION_4 = 4,
   SFTP_VERSION_5 = 5,
   SFTP_VERSION_6 = 6
} SftpVersion;


/**
 * @brief SFTP packet types
 **/

typedef enum
{
   SSH_FXP_INIT           = 1,
   SSH_FXP_VERSION        = 2,
   SSH_FXP_OPEN           = 3,
   SSH_FXP_CLOSE          = 4,
   SSH_FXP_READ           = 5,
   SSH_FXP_WRITE          = 6,
   SSH_FXP_LSTAT          = 7,
   SSH_FXP_FSTAT          = 8,
   SSH_FXP_SETSTAT        = 9,
   SSH_FXP_FSETSTAT       = 10,
   SSH_FXP_OPENDIR        = 11,
   SSH_FXP_READDIR        = 12,
   SSH_FXP_REMOVE         = 13,
   SSH_FXP_MKDIR          = 14,
   SSH_FXP_RMDIR          = 15,
   SSH_FXP_REALPATH       = 16,
   SSH_FXP_STAT           = 17,
   SSH_FXP_RENAME         = 18,
   SSH_FXP_READLINK       = 19,
   SSH_FXP_SYMLINK        = 20,
   SSH_FXP_STATUS         = 101,
   SSH_FXP_HANDLE         = 102,
   SSH_FXP_DATA           = 103,
   SSH_FXP_NAME           = 104,
   SSH_FXP_ATTRS          = 105,
   SSH_FXP_EXTENDED       = 200,
   SSH_FXP_EXTENDED_REPLY = 201
} SftpPacketType;


/**
 * @brief Status codes
 **/

typedef enum
{
   SSH_FX_OK                  = 0,
   SSH_FX_EOF                 = 1,
   SSH_FX_NO_SUCH_FILE        = 2,
   SSH_FX_PERMISSION_DENIED   = 3,
   SSH_FX_FAILURE             = 4,
   SSH_FX_BAD_MESSAGE         = 5,
   SSH_FX_NO_CONNECTION       = 6,
   SSH_FX_CONNECTION_LOST     = 7,
   SSH_FX_OP_UNSUPPORTED      = 8
} SftpStatusCode;


/**
 * @brief File types
 **/

typedef enum
{
   SSH_FILEXFER_TYPE_INVALID      = 0,
   SSH_FILEXFER_TYPE_REGULAR      = 1,
   SSH_FILEXFER_TYPE_DIRECTORY    = 2,
   SSH_FILEXFER_TYPE_SYMLINK      = 3,
   SSH_FILEXFER_TYPE_SPECIAL      = 4,
   SSH_FILEXFER_TYPE_UNKNOWN      = 5,
   SSH_FILEXFER_TYPE_SOCKET       = 6,
   SSH_FILEXFER_TYPE_CHAR_DEVICE  = 7,
   SSH_FILEXFER_TYPE_BLOCK_DEVICE = 8,
   SSH_FILEXFER_TYPE_FIFO         = 9
} SftpFileType;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief SFTP packet header
 **/

typedef __start_packed struct
{
   uint32_t length;   //0-3
   uint8_t type;      //4
   uint8_t payload[]; //5
} __end_packed SftpPacketHeader;


/**
 * @brief SSH_FXP_DATA packet header
 **/

typedef __start_packed struct
{
   uint32_t id;      //0-3
   uint32_t dataLen; //4-7
   uint8_t data[];   //8
} __end_packed SftpFxpDataHeader;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief File attributes
 **/

typedef struct
{
   uint32_t flags;
   SftpFileType type;
   uint64_t size;
   uint32_t uid;
   uint32_t gid;
   uint32_t permissions;
   DateTime atime;
   DateTime mtime;
   uint32_t bits;
} SftpFileAttrs;


/**
 * @brief Name structure
 **/

typedef struct
{
   SshString filename;
   SshString longname;
   SftpFileAttrs attributes;
} SftpName;


//SFTP related functions
error_t sftpFormatName(SftpVersion version, const SftpName *name,
   uint8_t *p, size_t *written);

error_t sftpFormatLongFilename(const SshString *filename,
   const SftpFileAttrs *attributes, char_t *p, size_t *written);

error_t sftpFormatAttributes(SftpVersion version,
   const SftpFileAttrs *attributes, uint8_t *p, size_t *written);

error_t sftpParseName(SftpVersion version, SftpName *name, const uint8_t *data,
   size_t length, size_t *consumed);

error_t sftpParseAttributes(SftpVersion version, SftpFileAttrs *attributes,
   const uint8_t *data, size_t length, size_t *consumed);

SftpFileType sftpConvertPermToFileType(uint32_t permissions);
uint32_t sftpConvertFileTypeToPerm(SftpFileType type);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
