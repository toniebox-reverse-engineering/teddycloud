/**
 * @file s32k1_crypto.h
 * @brief S32K1 hardware cryptographic accelerator (CSEq)
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

#ifndef _S32K1_CRYPTO_H
#define _S32K1_CRYPTO_H

//Dependencies
#include "core/crypto.h"

//Commands
#define CSEQ_CMD_ENC_ECB             0x01000000
#define CSEQ_CMD_ENC_CBC             0x02000000
#define CSEQ_CMD_DEC_ECB             0x03000000
#define CSEQ_CMD_DEC_CBC             0x04000000
#define CSEQ_CMD_GENERATE_MAC        0x05000000
#define CSEQ_CMD_VERIFY_MAC          0x06000000
#define CSEQ_CMD_LOAD_KEY            0x07000000
#define CSEQ_CMD_LOAD_PLAIN_KEY      0x08000000
#define CSEQ_CMD_EXPORT_RAM_KEY      0x09000000
#define CSEQ_CMD_INIT_RNG            0x0A000000
#define CSEQ_CMD_EXTEND_SEED         0x0B000000
#define CSEQ_CMD_RND                 0x0C000000
#define CSEQ_CMD_BOOT_FAILURE        0x0E000000
#define CSEQ_CMD_BOOT_OK             0x0F000000
#define CSEQ_CMD_GET_ID              0x10000000
#define CSEQ_CMD_BOOT_DEFINE         0x11000000
#define CSEQ_CMD_DBG_CHAL            0x12000000
#define CSEQ_CMD_DBG_AUTH            0x13000000
#define CSEQ_CMD_MP_COMPRESS         0x16000000

//Function format
#define CSEQ_FORMAT_COPY             0x00000000
#define CSEQ_FORMAT_POINTER          0x00010000

//Call sequence
#define CSEQ_CALL_SEQ_FIRST          0x00000000
#define CSEQ_CALL_SEQ_SUBSEQUENT     0x00000100

//Key identifiers
#define CSEQ_SECRET_KEY              0x00000000
#define CSEQ_MASTER_ECU_KEY          0x00000001
#define CSEQ_BOOT_MAC_KEY            0x00000002
#define CSEQ_BOOT_MAC                0x00000003
#define CSEQ_KEY_1                   0x00000004
#define CSEQ_KEY_2                   0x00000005
#define CSEQ_KEY_3                   0x00000006
#define CSEQ_KEY_4                   0x00000007
#define CSEQ_KEY_5                   0x00000008
#define CSEQ_KEY_6                   0x00000009
#define CSEQ_KEY_7                   0x0000000A
#define CSEQ_KEY_8                   0x0000000B
#define CSEQ_KEY_9                   0x0000000C
#define CSEQ_KEY_10                  0x0000000D
#define CSEQ_RAM_KEY                 0x0000000F
#define CSEQ_KEY_11                  0x00000014
#define CSEQ_KEY_12                  0x00000015
#define CSEQ_KEY_13                  0x00000016
#define CSEQ_KEY_14                  0x00000017
#define CSEQ_KEY_15                  0x00000018
#define CSEQ_KEY_16                  0x00000019
#define CSEQ_KEY_17                  0x0000001A
#define CSEQ_KEY_18                  0x0000001B
#define CSEQ_KEY_19                  0x0000001C
#define CSEQ_KEY_20                  0x0000001D
#define CSEQ_KEY_21                  0x0000001E

//Error codes
#define CSEQ_ERC_NO_ERROR            0x0001
#define CSEQ_ERC_SEQUENCE_ERROR      0x0002
#define CSEQ_ERC_KEY_NOT_AVAILABLE   0x0004
#define CSEQ_ERC_KEY_INVALID         0x0008
#define CSEQ_ERC_KEY_EMPTY           0x0010
#define CSEQ_ERC_NO_SECURE_BOOT      0x0020
#define CSEQ_ERC_KEY_WRITE_PROTECTED 0x0040
#define CSEQ_ERC_KEY_UPDATE_ERROR    0x0080
#define CSEQ_ERC_RNG_SEED            0x0100
#define CSEQ_ERC_NO_DEBUGGING        0x0200
#define CSEQ_ERC_MEMORY_FAILURE      0x0400
#define CSEQ_ERC_GENERAL_ERROR       0x0800

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Global variables
extern OsMutex s32k1CryptoMutex;

//S32K1 hardware cryptographic accelerator related functions
error_t s32k1CryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
