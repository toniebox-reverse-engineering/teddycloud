/**
 * @file cipher_algorithms.h
 * @brief Collection of cipher algorithms
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

#ifndef _CIPHER_ALGORITHMS_H
#define _CIPHER_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//RC2 cipher support?
#if (RC2_SUPPORT == ENABLED)
   #include "cipher/rc2.h"
#endif

//RC4 cipher support?
#if (RC4_SUPPORT == ENABLED)
   #include "cipher/rc4.h"
#endif

//RC6 cipher support?
#if (RC6_SUPPORT == ENABLED)
   #include "cipher/rc6.h"
#endif

//CAST-128 cipher support?
#if (CAST128_SUPPORT == ENABLED)
   #include "cipher/cast128.h"
#endif

//CAST-256 cipher support?
#if (CAST256_SUPPORT == ENABLED)
   #include "cipher/cast256.h"
#endif

//IDEA cipher support?
#if (IDEA_SUPPORT == ENABLED)
   #include "cipher/idea.h"
#endif

//DES cipher support?
#if (DES_SUPPORT == ENABLED)
   #include "cipher/des.h"
#endif

//Triple DES cipher support?
#if (DES3_SUPPORT == ENABLED)
   #include "cipher/des3.h"
#endif

//AES cipher support?
#if (AES_SUPPORT == ENABLED)
   #include "cipher/aes.h"
#endif

//Blowfish cipher support?
#if (BLOWFISH_SUPPORT == ENABLED)
   #include "cipher/blowfish.h"
#endif

//Twofish cipher support?
#if (TWOFISH_SUPPORT == ENABLED)
   #include "cipher/twofish.h"
#endif

//MARS cipher support?
#if (MARS_SUPPORT == ENABLED)
   #include "cipher/mars.h"
#endif

//Serpent cipher support?
#if (SERPENT_SUPPORT == ENABLED)
   #include "cipher/serpent.h"
#endif

//Camellia cipher support?
#if (CAMELLIA_SUPPORT == ENABLED)
   #include "cipher/camellia.h"
#endif

//ARIA cipher support?
#if (ARIA_SUPPORT == ENABLED)
   #include "cipher/aria.h"
#endif

//SEED cipher support?
#if (SEED_SUPPORT == ENABLED)
   #include "cipher/seed.h"
#endif

//PRESENT cipher support?
#if (PRESENT_SUPPORT == ENABLED)
   #include "cipher/present.h"
#endif

//Trivium cipher support?
#if (TRIVIUM_SUPPORT == ENABLED)
   #include "cipher/trivium.h"
#endif

//Salsa20 cipher support?
#if (SALSA20_SUPPORT == ENABLED)
   #include "cipher/salsa20.h"
#endif

//ChaCha cipher support?
#if (CHACHA_SUPPORT == ENABLED)
   #include "cipher/chacha.h"
#endif

//Maximum block size
#if (RC6_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE RC6_BLOCK_SIZE
#elif (CAST256_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE CAST256_BLOCK_SIZE
#elif (AES_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE AES_BLOCK_SIZE
#elif (TWOFISH_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE TWOFISH_BLOCK_SIZE
#elif (MARS_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE MARS_BLOCK_SIZE
#elif (SERPENT_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE SERPENT_BLOCK_SIZE
#elif (CAMELLIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE CAMELLIA_BLOCK_SIZE
#elif (ARIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE ARIA_BLOCK_SIZE
#elif (SEED_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE SEED_BLOCK_SIZE
#elif (RC2_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE RC2_BLOCK_SIZE
#elif (CAST128_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE CAST128_BLOCK_SIZE
#elif (IDEA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE IDEA_BLOCK_SIZE
#elif (DES_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE DES_BLOCK_SIZE
#elif (DES3_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE DES3_BLOCK_SIZE
#elif (BLOWFISH_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE BLOWFISH_BLOCK_SIZE
#elif (PRESENT_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE PRESENT_BLOCK_SIZE
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Generic cipher algorithm context
 **/

typedef union
{
#if (RC2_SUPPORT == ENABLED)
   Rc2Context rc2Context;
#endif
#if (RC4_SUPPORT == ENABLED)
   Rc4Context rc4Context;
#endif
#if (RC6_SUPPORT == ENABLED)
   Rc6Context rc6Context;
#endif
#if (CAST128_SUPPORT == ENABLED)
   Cast128Context cast128Context;
#endif
#if (CAST256_SUPPORT == ENABLED)
   Cast256Context cast256Context;
#endif
#if (IDEA_SUPPORT == ENABLED)
   IdeaContext ideaContext;
#endif
#if (DES_SUPPORT == ENABLED)
   DesContext desContext;
#endif
#if (DES3_SUPPORT == ENABLED)
   Des3Context des3Context;
#endif
#if (AES_SUPPORT == ENABLED)
   AesContext aesContext;
#endif
#if (BLOWFISH_SUPPORT == ENABLED)
   BlowfishContext blowfishContext;
#endif
#if (TWOFISH_SUPPORT == ENABLED)
   TwofishContext twofishContext;
#endif
#if (MARS_SUPPORT == ENABLED)
   MarsContext marsContext;
#endif
#if (SERPENT_SUPPORT == ENABLED)
   SerpentContext serpentContext;
#endif
#if (CAMELLIA_SUPPORT == ENABLED)
   CamelliaContext camelliaContext;
#endif
#if (ARIA_SUPPORT == ENABLED)
   AriaContext ariaContext;
#endif
#if (SEED_SUPPORT == ENABLED)
   SeedContext seedContext;
#endif
#if (PRESENT_SUPPORT == ENABLED)
   PresentContext presentContext;
#endif
#if (TRIVIUM_SUPPORT == ENABLED)
   TriviumContext triviumContext;
#endif
} CipherContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
