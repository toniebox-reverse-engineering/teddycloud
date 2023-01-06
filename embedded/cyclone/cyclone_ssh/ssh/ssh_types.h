/**
 * @file ssh_types.h
 * @brief SSH data type representations
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

#ifndef _SSH_TYPES_H
#define _SSH_TYPES_H

//Dependencies
#include "compiler_port.h"
#include "error.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Boolean
 **/

typedef bool_t SshBoolean;


/**
 * @brief String
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} SshString;


/**
 * @brief Binary string
 **/

typedef struct
{
   const uint8_t *value;
   size_t length;
} SshBinaryString;


/**
 * @brief String containing a comma-separated list of names
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} SshNameList;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
