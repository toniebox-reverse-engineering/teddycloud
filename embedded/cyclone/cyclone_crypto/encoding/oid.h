/**
 * @file oid.h
 * @brief OID (Object Identifier)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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

#ifndef _OID_H
#define _OID_H

//Dependencies
#include "core/crypto.h"

//Mask definition
#define OID_MORE_FLAG  0x80
#define OID_VALUE_MASK 0x7F

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//OID related functions
error_t oidCheck(const uint8_t *oid, size_t oidLen);

int_t oidComp(const uint8_t *oid1, size_t oidLen1, const uint8_t *oid2,
   size_t oidLen2);

bool_t oidMatch(const uint8_t *oid, size_t oidLen, const uint8_t *subtree,
   size_t subtreeLen, const uint8_t *mask, size_t maskLen);

uint_t oidCountSubIdentifiers(const uint8_t *oid, size_t oidLen);

error_t oidEncodeSubIdentifier(uint8_t *oid, size_t maxOidLen,
   size_t *pos, uint32_t value);

error_t oidDecodeSubIdentifier(const uint8_t *oid, size_t oidLen,
   size_t *pos, uint32_t *value);

error_t oidFromString(const char_t *str, uint8_t *oid, size_t maxOidLen,
   size_t *oidLen);

char_t *oidToString(const uint8_t *oid, size_t oidLen, char_t *str,
   size_t maxStrLen);

error_t maskFromString(const char_t *str, uint8_t *mask, size_t maxMaskLen,
   size_t *maskLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
