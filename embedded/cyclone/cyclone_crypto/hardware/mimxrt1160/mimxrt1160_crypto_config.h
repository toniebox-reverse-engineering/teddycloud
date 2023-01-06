/**
 * @file mimxrt1160_crypto_conifg.h
 * @brief CAAM-specific configuration file
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

#ifndef _MIMXRT1160_CRYPTO_CONFIG_H
#define _MIMXRT1160_CRYPTO_CONFIG_H

//Dependencies
#include "fsl_caam.h"

//CAAM-specific context (SHA-1)
#define SHA1_PRIVATE_CONTEXT \
   caam_handle_t caamHandle; \
   caam_hash_ctx_t caamContext;

//CAAM-specific context (SHA-256)
#define SHA256_PRIVATE_CONTEXT \
   caam_handle_t caamHandle; \
   caam_hash_ctx_t caamContext;

//CAAM-specific context (SHA-512)
#define SHA512_PRIVATE_CONTEXT \
   caam_handle_t caamHandle; \
   caam_hash_ctx_t caamContext;

#endif
