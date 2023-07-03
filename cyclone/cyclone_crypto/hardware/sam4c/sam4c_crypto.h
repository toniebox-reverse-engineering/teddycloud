/**
 * @file sam4c_crypto.h
 * @brief SAM4C hardware cryptographic accelerator
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

#ifndef _SAM4C_CRYPTO_H
#define _SAM4C_CRYPTO_H

//Device-specific definitions
#if defined(__SAM4C4C_0__)
   #include "sam4c4c_0.h"
#elif defined(__SAM4C4C_1__)
   #include "sam4c4c_1.h"
#elif defined(__SAM4C8C_0__)
   #include "sam4c8c_0.h"
#elif defined(__SAM4C8C_1__)
   #include "sam4c8c_1.h"
#elif defined(__SAM4C16C_0__)
   #include "sam4c16c_0.h"
#elif defined(__SAM4C16C_1__)
   #include "sam4c16c_1.h"
#elif defined(__SAM4C32C_0__)
   #include "sam4c32c_0.h"
#elif defined(__SAM4C32C_1__)
   #include "sam4c32c_1.h"
#elif defined(__SAM4C32E_0__)
   #include "sam4c32e_0.h"
#elif defined(__SAM4C32E_1__)
   #include "sam4c32e_1.h"
#elif defined(__SAM4CP16B_0__)
   #include "sam4cp16b_0.h"
#elif defined(__SAM4CP16B_1__)
   #include "sam4cp16b_1.h"
#elif defined(__SAM4CP16C_0__)
   #include "sam4cp16c_0.h"
#elif defined(__SAM4CP16C_1__)
   #include "sam4cp16c_1.h"
#elif defined(__SAM4CMP8C_0__)
   #include "sam4cmp8c_0.h"
#elif defined(__SAM4CMP8C_1__)
   #include "sam4cmp8c_1.h"
#elif defined(__SAM4CMP16C_0__)
   #include "sam4cmp16c_0.h"
#elif defined(__SAM4CMP16C_1__)
   #include "sam4cmp16c_1.h"
#elif defined(__SAM4CMS4C_0__)
   #include "sam4cms4c_0.h"
#elif defined(__SAM4CMS4C_1__)
   #include "sam4cms4c_1.h"
#elif defined(__SAM4CMS8C_0__)
   #include "sam4cms8c_0.h"
#elif defined(__SAM4CMS8C_1__)
   #include "sam4cms8c_1.h"
#elif defined(__SAM4CMS16C_0__)
   #include "sam4cms16c_0.h"
#elif defined(__SAM4CMS16C_1__)
   #include "sam4cms16c_1.h"
#elif defined(__SAM4CMP32C_0__)
   #include "sam4cmp32c_0.h"
#elif defined(__SAM4CMP32C_1__)
   #include "sam4cmp32c_1.h"
#elif defined(__SAM4CMS32C_0__)
   #include "sam4cms32c_0.h"
#elif defined(__SAM4CMS32C_1__)
   #include "sam4cms32c_1.h"
#endif

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Global variables
extern OsMutex sam4cCryptoMutex;

//SAM4C hardware cryptographic accelerator related functions
error_t sam4cCryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
