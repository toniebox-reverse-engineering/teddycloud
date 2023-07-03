/**
 * @file mimxrt1060_crypto.h
 * @brief i.MX RT1060 hardware cryptographic accelerator (DCP)
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

#ifndef _MIMXRT1060_CRYPTO_H
#define _MIMXRT1060_CRYPTO_H

//Dependencies
#include "core/crypto.h"

//DCP buffer size
#ifndef MIMXRT1060_DCP_BUFFER_SIZE
   #define MIMXRT1060_DCP_BUFFER_SIZE 1024
#elif (MIMXRT1060_DCP_BUFFER_SIZE < 256)
   #error MIMXRT1060_DCP_BUFFER_SIZE parameter is not valid
#endif

//Name of the section where to place DCP buffers
#ifndef MIMXRT1060_DCP_RAM_SECTION
   #define MIMXRT1060_DCP_RAM_SECTION ".dcp_ram"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Global variables
extern OsMutex mimxrt1060CryptoMutex;

//i.MX RT1060 hardware cryptographic accelerator related functions
error_t mimxrt1060CryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
