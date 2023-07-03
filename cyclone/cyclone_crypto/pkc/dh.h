/**
 * @file dh.h
 * @brief Diffie-Hellman key exchange
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

#ifndef _DH_H
#define _DH_H

//Dependencies
#include "core/crypto.h"
#include "mpi/mpi.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Diffie-Hellman parameters
 **/

typedef struct
{
   Mpi p; ///<Prime modulus
   Mpi g; ///<Generator
} DhParameters;


/**
 * @brief Diffie-Hellman context
 **/

typedef struct
{
   DhParameters params; //Diffie-Hellman parameters
   Mpi xa;              ///<One's own private value
   Mpi ya;              ///<One's own public value
   Mpi yb;              ///<Peer's public value
} DhContext;


//Diffie-Hellman related functions
void dhInit(DhContext *context);
void dhFree(DhContext *context);

void dhInitParameters(DhParameters *params);
void dhFreeParameters(DhParameters *params);

error_t dhGenerateKeyPair(DhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t dhCheckPublicKey(DhParameters *params, const Mpi *publicKey);

error_t dhComputeSharedSecret(DhContext *context, uint8_t *output,
   size_t outputSize, size_t *outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
