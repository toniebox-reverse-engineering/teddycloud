/**
 * @file tm4c129_crypto_hash.h
 * @brief Tiva TM4C129 hash hardware accelerator
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

#ifndef _TM4C129_CRYPTO_HASH_H
#define _TM4C129_CRYPTO_HASH_H

//Dependencies
#include "core/crypto.h"

//Hash hardware accelerator
#ifndef TM4C129_CRYPTO_HASH_SUPPORT
   #define TM4C129_CRYPTO_HASH_SUPPORT DISABLED
#elif (TM4C129_CRYPTO_HASH_SUPPORT != ENABLED && TM4C129_CRYPTO_HASH_SUPPORT != DISABLED)
   #error TM4C129_CRYPTO_HASH_SUPPORT parameter is not valid
#endif

//SHA/MD5 engine registers
#ifndef SHAMD5_ODIGEST_A_R
   #define SHAMD5_ODIGEST_A_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_A)
   #define SHAMD5_ODIGEST_B_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_B)
   #define SHAMD5_ODIGEST_C_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_C)
   #define SHAMD5_ODIGEST_D_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_D)
   #define SHAMD5_ODIGEST_E_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_E)
   #define SHAMD5_ODIGEST_F_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_F)
   #define SHAMD5_ODIGEST_G_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_G)
   #define SHAMD5_ODIGEST_H_R    HWREG(SHAMD5_BASE + SHAMD5_O_ODIGEST_H)
   #define SHAMD5_IDIGEST_A_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_A)
   #define SHAMD5_IDIGEST_B_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_B)
   #define SHAMD5_IDIGEST_C_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_C)
   #define SHAMD5_IDIGEST_D_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_D)
   #define SHAMD5_IDIGEST_E_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_E)
   #define SHAMD5_IDIGEST_F_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_F)
   #define SHAMD5_IDIGEST_G_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_G)
   #define SHAMD5_IDIGEST_H_R    HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_H)
   #define SHAMD5_DIGEST_COUNT_R HWREG(SHAMD5_BASE + SHAMD5_O_DIGEST_COUNT)
   #define SHAMD5_MODE_R         HWREG(SHAMD5_BASE + SHAMD5_O_MODE)
   #define SHAMD5_LENGTH_R       HWREG(SHAMD5_BASE + SHAMD5_O_LENGTH)
   #define SHAMD5_DATA_0_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_0_IN)
   #define SHAMD5_DATA_1_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_1_IN)
   #define SHAMD5_DATA_2_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_2_IN)
   #define SHAMD5_DATA_3_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_3_IN)
   #define SHAMD5_DATA_4_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_4_IN)
   #define SHAMD5_DATA_5_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_5_IN)
   #define SHAMD5_DATA_6_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_6_IN)
   #define SHAMD5_DATA_7_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_7_IN)
   #define SHAMD5_DATA_8_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_8_IN)
   #define SHAMD5_DATA_9_IN_R    HWREG(SHAMD5_BASE + SHAMD5_O_DATA_9_IN)
   #define SHAMD5_DATA_10_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_10_IN)
   #define SHAMD5_DATA_11_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_11_IN)
   #define SHAMD5_DATA_12_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_12_IN)
   #define SHAMD5_DATA_13_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_13_IN)
   #define SHAMD5_DATA_14_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_14_IN)
   #define SHAMD5_DATA_15_IN_R   HWREG(SHAMD5_BASE + SHAMD5_O_DATA_15_IN)
   #define SHAMD5_REVISION_R     HWREG(SHAMD5_BASE + SHAMD5_O_REVISION)
   #define SHAMD5_SYSCONFIG_R    HWREG(SHAMD5_BASE + SHAMD5_O_SYSCONFIG)
   #define SHAMD5_SYSSTATUS_R    HWREG(SHAMD5_BASE + SHAMD5_O_SYSSTATUS)
   #define SHAMD5_IRQSTATUS_R    HWREG(SHAMD5_BASE + SHAMD5_O_IRQSTATUS)
   #define SHAMD5_IRQENABLE_R    HWREG(SHAMD5_BASE + SHAMD5_O_IRQENABLE)
   #define SHAMD5_DMAIM_R        HWREG(SHAMD5_BASE + SHAMD5_O_DMAIM)
   #define SHAMD5_DMARIS_R       HWREG(SHAMD5_BASE + SHAMD5_O_DMARIS)
   #define SHAMD5_DMAMIS_R       HWREG(SHAMD5_BASE + SHAMD5_O_DMAMIS)
   #define SHAMD5_DMAIC_R        HWREG(SHAMD5_BASE + SHAMD5_O_DMAIC)
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
