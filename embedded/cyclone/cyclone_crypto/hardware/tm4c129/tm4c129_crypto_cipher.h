/**
 * @file tm4c129_crypto_cipher.h
 * @brief Tiva TM4C129 cipher hardware accelerator
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

#ifndef _TM4C129_CRYPTO_CIPHER_H
#define _TM4C129_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef TM4C129_CRYPTO_CIPHER_SUPPORT
   #define TM4C129_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (TM4C129_CRYPTO_CIPHER_SUPPORT != ENABLED && TM4C129_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error TM4C129_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//AES engine registers
#ifndef AES_KEY2_6_R
   #define AES_KEY2_6_R      HWREG(AES_BASE + AES_O_KEY2_6)
   #define AES_KEY2_7_R      HWREG(AES_BASE + AES_O_KEY2_7)
   #define AES_KEY2_4_R      HWREG(AES_BASE + AES_O_KEY2_4)
   #define AES_KEY2_5_R      HWREG(AES_BASE + AES_O_KEY2_5)
   #define AES_KEY2_2_R      HWREG(AES_BASE + AES_O_KEY2_2)
   #define AES_KEY2_3_R      HWREG(AES_BASE + AES_O_KEY2_3)
   #define AES_KEY2_0_R      HWREG(AES_BASE + AES_O_KEY2_0)
   #define AES_KEY2_1_R      HWREG(AES_BASE + AES_O_KEY2_1)
   #define AES_KEY1_6_R      HWREG(AES_BASE + AES_O_KEY1_6)
   #define AES_KEY1_7_R      HWREG(AES_BASE + AES_O_KEY1_7)
   #define AES_KEY1_4_R      HWREG(AES_BASE + AES_O_KEY1_4)
   #define AES_KEY1_5_R      HWREG(AES_BASE + AES_O_KEY1_5)
   #define AES_KEY1_2_R      HWREG(AES_BASE + AES_O_KEY1_2)
   #define AES_KEY1_3_R      HWREG(AES_BASE + AES_O_KEY1_3)
   #define AES_KEY1_0_R      HWREG(AES_BASE + AES_O_KEY1_0)
   #define AES_KEY1_1_R      HWREG(AES_BASE + AES_O_KEY1_1)
   #define AES_IV_IN_0_R     HWREG(AES_BASE + AES_O_IV_IN_0)
   #define AES_IV_IN_1_R     HWREG(AES_BASE + AES_O_IV_IN_1)
   #define AES_IV_IN_2_R     HWREG(AES_BASE + AES_O_IV_IN_2)
   #define AES_IV_IN_3_R     HWREG(AES_BASE + AES_O_IV_IN_3)
   #define AES_CTRL_R        HWREG(AES_BASE + AES_O_CTRL)
   #define AES_C_LENGTH_0_R  HWREG(AES_BASE + AES_O_C_LENGTH_0)
   #define AES_C_LENGTH_1_R  HWREG(AES_BASE + AES_O_C_LENGTH_1)
   #define AES_AUTH_LENGTH_R HWREG(AES_BASE + AES_O_AUTH_LENGTH)
   #define AES_DATA_IN_0_R   HWREG(AES_BASE + AES_O_DATA_IN_0)
   #define AES_DATA_IN_1_R   HWREG(AES_BASE + AES_O_DATA_IN_1)
   #define AES_DATA_IN_2_R   HWREG(AES_BASE + AES_O_DATA_IN_2)
   #define AES_DATA_IN_3_R   HWREG(AES_BASE + AES_O_DATA_IN_3)
   #define AES_TAG_OUT_0_R   HWREG(AES_BASE + AES_O_TAG_OUT_0)
   #define AES_TAG_OUT_1_R   HWREG(AES_BASE + AES_O_TAG_OUT_1)
   #define AES_TAG_OUT_2_R   HWREG(AES_BASE + AES_O_TAG_OUT_2)
   #define AES_TAG_OUT_3_R   HWREG(AES_BASE + AES_O_TAG_OUT_3)
   #define AES_REVISION_R    HWREG(AES_BASE + AES_O_REVISION)
   #define AES_SYSCONFIG_R   HWREG(AES_BASE + AES_O_SYSCONFIG)
   #define AES_SYSSTATUS_R   HWREG(AES_BASE + AES_O_SYSSTATUS)
   #define AES_IRQSTATUS_R   HWREG(AES_BASE + AES_O_IRQSTATUS)
   #define AES_IRQENABLE_R   HWREG(AES_BASE + AES_O_IRQENABLE)
   #define AES_DIRTYBITS_R   HWREG(AES_BASE + AES_O_DIRTYBITS)
   #define AES_DMAIM_R       HWREG(AES_BASE + AES_O_DMAIM)
   #define AES_DMARIS_R      HWREG(AES_BASE + AES_O_DMARIS)
   #define AES_DMAMIS_R      HWREG(AES_BASE + AES_O_DMAMIS)
   #define AES_DMAIC_R       HWREG(AES_BASE + AES_O_DMAIC)
#endif

//DES engine registers
#ifndef DES_KEY3_L_R
   #define DES_KEY3_L_R    HWREG(DES_BASE + DES_O_KEY3_L)
   #define DES_KEY3_H_R    HWREG(DES_BASE + DES_O_KEY3_H)
   #define DES_KEY2_L_R    HWREG(DES_BASE + DES_O_KEY2_L)
   #define DES_KEY2_H_R    HWREG(DES_BASE + DES_O_KEY2_H)
   #define DES_KEY1_L_R    HWREG(DES_BASE + DES_O_KEY1_L)
   #define DES_KEY1_H_R    HWREG(DES_BASE + DES_O_KEY1_H)
   #define DES_IV_L_R      HWREG(DES_BASE + DES_O_IV_L)
   #define DES_IV_H_R      HWREG(DES_BASE + DES_O_IV_H)
   #define DES_CTRL_R      HWREG(DES_BASE + DES_O_CTRL)
   #define DES_LENGTH_R    HWREG(DES_BASE + DES_O_LENGTH)
   #define DES_DATA_L_R    HWREG(DES_BASE + DES_O_DATA_L)
   #define DES_DATA_H_R    HWREG(DES_BASE + DES_O_DATA_H)
   #define DES_REVISION_R  HWREG(DES_BASE + DES_O_REVISION)
   #define DES_SYSCONFIG_R HWREG(DES_BASE + DES_O_SYSCONFIG)
   #define DES_SYSSTATUS_R HWREG(DES_BASE + DES_O_SYSSTATUS)
   #define DES_IRQSTATUS_R HWREG(DES_BASE + DES_O_IRQSTATUS)
   #define DES_IRQENABLE_R HWREG(DES_BASE + DES_O_IRQENABLE)
   #define DES_DIRTYBITS_R HWREG(DES_BASE + DES_O_DIRTYBITS)
   #define DES_DMAIM_R     HWREG(DES_BASE + DES_O_DMAIM)
   #define DES_DMARIS_R    HWREG(DES_BASE + DES_O_DMARIS)
   #define DES_DMAMIS_R    HWREG(DES_BASE + DES_O_DMAMIS)
   #define DES_DMAIC_R     HWREG(DES_BASE + DES_O_DMAIC)
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
