/**
 * @file pic32mz_crypto.h
 * @brief PIC32MZ hardware cryptographic accelerator
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

#ifndef _PIC32MZ_CRYPTO_H
#define _PIC32MZ_CRYPTO_H

//Dependencies
#include "core/crypto.h"

//DMA buffer size
#ifndef PIC32MZ_CRYPTO_BUFFER_SIZE
   #define PIC32MZ_CRYPTO_BUFFER_SIZE 1024
#elif (PIC32MZ_CRYPTO_BUFFER_SIZE < 64)
   #error PIC32MZ_CRYPTO_BUFFER_SIZE parameter is not valid
#endif

//BD_CTRL format
#define BD_CTRL_DESC_EN                 0x80000000
#define BD_CTRL_CRY_MODE                0x38000000
#define BD_CTRL_CRY_MODE_NORMAL         0x00000000
#define BD_CTRL_CRY_MODE_PREBOOT_AUTH   0x08000000
#define BD_CTRL_CRY_MODE_KEK            0x10000000
#define BD_CTRL_CRY_MODE_CEK            0x18000000
#define BD_CTRL_SA_FETCH_EN             0x00400000
#define BD_CTRL_LAST_BD                 0x00080000
#define BD_CTRL_LIFM                    0x00040000
#define BD_CTRL_PKT_INT_EN              0x00020000
#define BD_CTRL_CBD_INT_EN              0x00010000
#define BD_CTRL_BD_BUFLEN               0x0000FFFF

//SA_CTRL format
#define SA_CTRL_VERIFY                  0x20000000
#define SA_CTRL_NO_RX                   0x08000000
#define SA_CTRL_OR_EN                   0x04000000
#define SA_CTRL_ICVONLY                 0x02000000
#define SA_CTRL_IRFLAG                  0x01000000
#define SA_CTRL_LNC                     0x00800000
#define SA_CTRL_LOADIV                  0x00400000
#define SA_CTRL_FB                      0x00200000
#define SA_CTRL_FLAGS                   0x00100000
#define SA_CTRL_ALGO                    0x0001FC00
#define SA_CTRL_ALGO_DES                0x00000400
#define SA_CTRL_ALGO_TDES               0x00000800
#define SA_CTRL_ALGO_AES                0x00001000
#define SA_CTRL_ALGO_MD5                0x00002000
#define SA_CTRL_ALGO_SHA1               0x00004000
#define SA_CTRL_ALGO_SHA256             0x00008000
#define SA_CTRL_ALGO_HMAC               0x00010000
#define SA_CTRL_ENC                     0x00000200
#define SA_CTRL_KEYSIZE                 0x00000180
#define SA_CTRL_KEYSIZE_128             0x00000000
#define SA_CTRL_KEYSIZE_192             0x00000080
#define SA_CTRL_KEYSIZE_256             0x00000100
#define SA_CTRL_MULTITASK               0x00000070
#define SA_CTRL_MULTITASK_NO_PASS       0x00000000
#define SA_CTRL_MULTITASK_PIPE_PASS     0x00000050
#define SA_CTRL_MULTITASK_PARALLEL_PASS 0x00000070
#define SA_CTRL_CRYPTOALGO              0x0000000F
#define SA_CTRL_CRYPTOALGO_ECB          0x00000000
#define SA_CTRL_CRYPTOALGO_CBC          0x00000001
#define SA_CTRL_CRYPTOALGO_CFB          0x00000002
#define SA_CTRL_CRYPTOALGO_OFB          0x00000003
#define SA_CTRL_CRYPTOALGO_TECB         0x00000004
#define SA_CTRL_CRYPTOALGO_TCBC         0x00000005
#define SA_CTRL_CRYPTOALGO_TCFB         0x00000006
#define SA_CTRL_CRYPTOALGO_TOFB         0x00000007
#define SA_CTRL_CRYPTOALGO_RECB         0x00000008
#define SA_CTRL_CRYPTOALGO_RCBC         0x00000009
#define SA_CTRL_CRYPTOALGO_RCFB         0x0000000A
#define SA_CTRL_CRYPTOALGO_ROFB         0x0000000B
#define SA_CTRL_CRYPTOALGO_RCBC_MAC     0x0000000C
#define SA_CTRL_CRYPTOALGO_RCTR         0x0000000D
#define SA_CTRL_CRYPTOALGO_AES_GCM      0x0000000E

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Buffer description
 **/

typedef struct {
   uint32_t BD_CTRL;
   uint32_t SA_ADDR;
   uint32_t SRCADDR;
   uint32_t DSTADDR;
   uint32_t NXTPTR;
   uint32_t UPDPTR;
   uint32_t MSG_LEN;
   uint32_t ENC_OFF;
} Pic32mzCryptoBufferDesc;


/**
 * @brief Security association
 **/

typedef struct {
   uint32_t SA_CTRL;
   uint32_t SA_AUTHKEY[8];
   uint32_t SA_ENCKEY[8];
   uint32_t SA_AUTHIV[8];
   uint32_t SA_ENCIV[8];
} Pic32mzCryptoSecurityAssoc;


//Global variables
extern OsMutex pic32mzCryptoMutex;

//PIC32MZ hardware cryptographic accelerator related functions
error_t pic32mzCryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
