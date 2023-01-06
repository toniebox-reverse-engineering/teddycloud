/**
 * @file saml11_crypto_hash.c
 * @brief SAML11 hash hardware accelerator
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "sam.h"
#include "core/crypto.h"
#include "hardware/saml11/saml11_crypto.h"
#include "hardware/saml11/saml11_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (SAML11_CRYPTO_HASH_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-256 context
 **/

void sha256ProcessBlock(Sha256Context *context)
{
   static uint32_t buffer[64];

   //Acquire exclusive access to the CRYA module
   osAcquireMutex(&saml11CryptoMutex);
   //Accelerate SHA-256 inner compression loop
   crya_sha_process(context->h, context->buffer, buffer);
   //Release exclusive access to the CRYA module
   osReleaseMutex(&saml11CryptoMutex);
}

#endif
