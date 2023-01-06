/**
 * @file scp_common.h
 * @brief Definitions common to SCP client and server
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

#ifndef _SCP_COMMON_H
#define _SCP_COMMON_H

//Dependencies
#include "ssh/ssh.h"

//File permissions
#define SCP_MODE_IXOTH 0x0001
#define SCP_MODE_IWOTH 0x0002
#define SCP_MODE_IROTH 0x0004
#define SCP_MODE_IRWXO 0x0007
#define SCP_MODE_IXGRP 0x0008
#define SCP_MODE_IWGRP 0x0010
#define SCP_MODE_IRGRP 0x0020
#define SCP_MODE_IRWXG 0x0038
#define SCP_MODE_IXUSR 0x0040
#define SCP_MODE_IWUSR 0x0080
#define SCP_MODE_IRUSR 0x0100
#define SCP_MODE_IRWXU 0x01C0

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SCP directive opcodes
 **/

typedef enum
{
   SCP_OPCODE_OK      = 0,
   SCP_OPCODE_WARNING = 1,
   SCP_OPCODE_ERROR   = 2,
   SCP_OPCODE_FILE    = 67,
   SCP_OPCODE_DIR     = 68,
   SCP_OPCODE_END     = 69,
   SCP_OPCODE_TIME    = 84
} ScpOpcode;


/**
 * @brief SCP directive parameters
 **/

typedef struct
{
   ScpOpcode opcode;
   uint32_t mode;
   uint64_t size;
   uint32_t mtime;
   uint32_t atime;
   const char_t *filename;
   const char_t *message;
} ScpDirective;


//SCP related functions
size_t scpFormatDirective(const ScpDirective *directive, char_t *buffer);
error_t scpParseDirective(const char_t *buffer, ScpDirective *directive);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
