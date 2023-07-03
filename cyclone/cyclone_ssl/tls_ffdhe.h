/**
 * @file tls_ffdhe.h
 * @brief FFDHE key exchange
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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

#ifndef _TLS_FFDHE_H
#define _TLS_FFDHE_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief FFDHE parameters
 **/

typedef struct
{
   const char_t *name;   ///<Group name
   const uint8_t p[512]; ///<Prime modulus
   size_t pLen;          ///<Length of the prime modulus, in bytes
   uint8_t g;            ///<Generator
} TlsFfdheGroup;


//TLS related functions
error_t tlsSelectFfdheGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList);

const TlsFfdheGroup *tlsGetFfdheGroup(TlsContext *context,
   uint16_t namedGroup);

error_t tlsLoadFfdheParameters(DhParameters *params,
   const TlsFfdheGroup *ffdheGroup);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
