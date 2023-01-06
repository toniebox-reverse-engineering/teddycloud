/**
 * @file hash_algorithms.h
 * @brief Collection of hash algorithms
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

#ifndef _HASH_ALGORITHMS_H
#define _HASH_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//MD2 hash support?
#if (MD2_SUPPORT == ENABLED)
   #include "hash/md2.h"
#endif

//MD4 hash support?
#if (MD4_SUPPORT == ENABLED)
   #include "hash/md4.h"
#endif

//MD5 hash support?
#if (MD5_SUPPORT == ENABLED)
   #include "hash/md5.h"
#endif

//RIPEMD-128 hash support?
#if (RIPEMD128_SUPPORT == ENABLED)
   #include "hash/ripemd128.h"
#endif

//RIPEMD-160 hash support?
#if (RIPEMD160_SUPPORT == ENABLED)
   #include "hash/ripemd160.h"
#endif

//SHA-1 hash support?
#if (SHA1_SUPPORT == ENABLED)
   #include "hash/sha1.h"
#endif

//SHA-224 hash support?
#if (SHA224_SUPPORT == ENABLED)
   #include "hash/sha224.h"
#endif

//SHA-256 hash support?
#if (SHA256_SUPPORT == ENABLED)
   #include "hash/sha256.h"
#endif

//SHA-384 hash support?
#if (SHA384_SUPPORT == ENABLED)
   #include "hash/sha384.h"
#endif

//SHA-512 hash support?
#if (SHA512_SUPPORT == ENABLED)
   #include "hash/sha512.h"
#endif

//SHA-512/224 hash support?
#if (SHA512_224_SUPPORT == ENABLED)
   #include "hash/sha512_224.h"
#endif

//SHA-512/256 hash support?
#if (SHA512_256_SUPPORT == ENABLED)
   #include "hash/sha512_256.h"
#endif

//SHA3-224 hash support?
#if (SHA3_224_SUPPORT == ENABLED)
   #include "hash/sha3_224.h"
#endif

//SHA3-256 hash support?
#if (SHA3_256_SUPPORT == ENABLED)
   #include "hash/sha3_256.h"
#endif

//SHA3-384 hash support?
#if (SHA3_384_SUPPORT == ENABLED)
   #include "hash/sha3_384.h"
#endif

//SHA3-512 hash support?
#if (SHA3_512_SUPPORT == ENABLED)
   #include "hash/sha3_512.h"
#endif

//BLAKE2b-160 hash support?
#if (BLAKE2B160_SUPPORT == ENABLED)
   #include "hash/blake2b160.h"
#endif

//BLAKE2b-256 hash support?
#if (BLAKE2B256_SUPPORT == ENABLED)
   #include "hash/blake2b256.h"
#endif

//BLAKE2b-384 hash support?
#if (BLAKE2B384_SUPPORT == ENABLED)
   #include "hash/blake2b384.h"
#endif

//BLAKE2b-512 hash support?
#if (BLAKE2B512_SUPPORT == ENABLED)
   #include "hash/blake2b512.h"
#endif

//BLAKE2s-128 hash support?
#if (BLAKE2S128_SUPPORT == ENABLED)
   #include "hash/blake2s128.h"
#endif

//BLAKE2s-160 hash support?
#if (BLAKE2S160_SUPPORT == ENABLED)
   #include "hash/blake2s160.h"
#endif

//BLAKE2s-224 hash support?
#if (BLAKE2S224_SUPPORT == ENABLED)
   #include "hash/blake2s224.h"
#endif

//BLAKE2s-256 hash support?
#if (BLAKE2S256_SUPPORT == ENABLED)
   #include "hash/blake2s256.h"
#endif

//Tiger hash support?
#if (TIGER_SUPPORT == ENABLED)
   #include "hash/tiger.h"
#endif

//Whirlpool hash support?
#if (WHIRLPOOL_SUPPORT == ENABLED)
   #include "hash/whirlpool.h"
#endif

//Maximum block size
#if (SHA3_224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_224_BLOCK_SIZE
#elif (SHA3_256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_256_BLOCK_SIZE
#elif (BLAKE2B512_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2B512_BLOCK_SIZE
#elif (BLAKE2B384_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2B384_BLOCK_SIZE
#elif (BLAKE2B256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2B256_BLOCK_SIZE
#elif (BLAKE2B160_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2B160_BLOCK_SIZE
#elif (SHA512_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_BLOCK_SIZE
#elif (SHA384_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA384_BLOCK_SIZE
#elif (SHA512_256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_256_BLOCK_SIZE
#elif (SHA512_224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_224_BLOCK_SIZE
#elif (SHA3_384_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_384_BLOCK_SIZE
#elif (SHA3_512_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_512_BLOCK_SIZE
#elif (BLAKE2S256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2S256_BLOCK_SIZE
#elif (BLAKE2S224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2S224_BLOCK_SIZE
#elif (BLAKE2S160_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2S160_BLOCK_SIZE
#elif (BLAKE2S128_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE BLAKE2S128_BLOCK_SIZE
#elif (SHA256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA256_BLOCK_SIZE
#elif (SHA224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA224_BLOCK_SIZE
#elif (SHA1_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA1_BLOCK_SIZE
#elif (WHIRLPOOL_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE WHIRLPOOL_BLOCK_SIZE
#elif (TIGER_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE TIGER_BLOCK_SIZE
#elif (RIPEMD160_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE RIPEMD160_BLOCK_SIZE
#elif (RIPEMD128_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE RIPEMD128_BLOCK_SIZE
#elif (MD5_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD5_BLOCK_SIZE
#elif (MD4_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD4_BLOCK_SIZE
#elif (MD2_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD2_BLOCK_SIZE
#endif

//Maximum digest size
#if (WHIRLPOOL_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE WHIRLPOOL_DIGEST_SIZE
#elif (BLAKE2B512_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2B512_DIGEST_SIZE
#elif (SHA3_512_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_512_DIGEST_SIZE
#elif (SHA512_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif (BLAKE2B384_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2B384_DIGEST_SIZE
#elif (SHA3_384_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_384_DIGEST_SIZE
#elif (SHA384_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif (BLAKE2B256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2B256_DIGEST_SIZE
#elif (BLAKE2S256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2S256_DIGEST_SIZE
#elif (SHA3_256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#elif (SHA512_256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_256_DIGEST_SIZE
#elif (SHA256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif (BLAKE2S224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2S224_DIGEST_SIZE
#elif (SHA3_224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_224_DIGEST_SIZE
#elif (SHA512_224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_224_DIGEST_SIZE
#elif (SHA224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA224_DIGEST_SIZE
#elif (TIGER_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE TIGER_DIGEST_SIZE
#elif (BLAKE2B160_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2B160_DIGEST_SIZE
#elif (BLAKE2S160_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2S160_DIGEST_SIZE
#elif (SHA1_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA1_DIGEST_SIZE
#elif (RIPEMD160_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE RIPEMD160_DIGEST_SIZE
#elif (BLAKE2S128_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE BLAKE2S128_DIGEST_SIZE
#elif (RIPEMD128_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE RIPEMD128_DIGEST_SIZE
#elif (MD5_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD5_DIGEST_SIZE
#elif (MD4_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD4_DIGEST_SIZE
#elif (MD2_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD2_DIGEST_SIZE
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Generic hash algorithm context
 **/

typedef union
{
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (MD2_SUPPORT == ENABLED)
   Md2Context md2Context;
#endif
#if (MD4_SUPPORT == ENABLED)
   Md4Context md4Context;
#endif
#if (MD5_SUPPORT == ENABLED)
   Md5Context md5Context;
#endif
#if (RIPEMD128_SUPPORT == ENABLED)
   Ripemd128Context ripemd128Context;
#endif
#if (RIPEMD160_SUPPORT == ENABLED)
   Ripemd160Context ripemd160Context;
#endif
#if (SHA1_SUPPORT == ENABLED)
   Sha1Context sha1Context;
#endif
#if (SHA224_SUPPORT == ENABLED)
   Sha224Context sha224Context;
#endif
#if (SHA256_SUPPORT == ENABLED)
   Sha256Context sha256Context;
#endif
#if (SHA384_SUPPORT == ENABLED)
   Sha384Context sha384Context;
#endif
#if (SHA512_SUPPORT == ENABLED)
   Sha512Context sha512Context;
#endif
#if (SHA512_224_SUPPORT == ENABLED)
   Sha512_224Context sha512_224Context;
#endif
#if (SHA512_256_SUPPORT == ENABLED)
   Sha512_256Context sha512_256Context;
#endif
#if (SHA3_224_SUPPORT == ENABLED)
   Sha3_224Context sha3_224Context;
#endif
#if (SHA3_256_SUPPORT == ENABLED)
   Sha3_256Context sha3_256Context;
#endif
#if (SHA3_384_SUPPORT == ENABLED)
   Sha3_384Context sha3_384Context;
#endif
#if (SHA3_512_SUPPORT == ENABLED)
   Sha3_512Context sha3_512Context;
#endif
#if (BLAKE2B160_SUPPORT == ENABLED)
   Blake2b160Context blake2b160Context;
#endif
#if (BLAKE2B256_SUPPORT == ENABLED)
   Blake2b256Context blake2b256Context;
#endif
#if (BLAKE2B384_SUPPORT == ENABLED)
   Blake2b384Context blake2b384Context;
#endif
#if (BLAKE2B512_SUPPORT == ENABLED)
   Blake2b512Context blake2b512Context;
#endif
#if (BLAKE2S128_SUPPORT == ENABLED)
   Blake2s128Context blake2s128Context;
#endif
#if (BLAKE2S160_SUPPORT == ENABLED)
   Blake2s160Context blake2s160Context;
#endif
#if (BLAKE2S224_SUPPORT == ENABLED)
   Blake2s224Context blake2s224Context;
#endif
#if (BLAKE2S256_SUPPORT == ENABLED)
   Blake2s256Context blake2s256Context;
#endif
#if (TIGER_SUPPORT == ENABLED)
   TigerContext tigerContext;
#endif
#if (WHIRLPOOL_SUPPORT == ENABLED)
   WhirlpoolContext whirlpoolContext;
#endif
} HashContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
