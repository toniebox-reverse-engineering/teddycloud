/**
 * @file gd32f3xx_eth_driver.h
 * @brief GD32F3 Ethernet MAC driver
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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

#ifndef _GD32F3XX_ETH_DRIVER_H
#define _GD32F3XX_ETH_DRIVER_H

//Dependencies
#include "core/nic.h"

//Number of TX buffers
#ifndef GD32F3XX_ETH_TX_BUFFER_COUNT
   #define GD32F3XX_ETH_TX_BUFFER_COUNT 3
#elif (GD32F3XX_ETH_TX_BUFFER_COUNT < 1)
   #error GD32F3XX_ETH_TX_BUFFER_COUNT parameter is not valid
#endif

//TX buffer size
#ifndef GD32F3XX_ETH_TX_BUFFER_SIZE
   #define GD32F3XX_ETH_TX_BUFFER_SIZE 1536
#elif (GD32F3XX_ETH_TX_BUFFER_SIZE != 1536)
   #error GD32F3XX_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//Number of RX buffers
#ifndef GD32F3XX_ETH_RX_BUFFER_COUNT
   #define GD32F3XX_ETH_RX_BUFFER_COUNT 6
#elif (GD32F3XX_ETH_RX_BUFFER_COUNT < 1)
   #error GD32F3XX_ETH_RX_BUFFER_COUNT parameter is not valid
#endif

//RX buffer size
#ifndef GD32F3XX_ETH_RX_BUFFER_SIZE
   #define GD32F3XX_ETH_RX_BUFFER_SIZE 1536
#elif (GD32F3XX_ETH_RX_BUFFER_SIZE != 1536)
   #error GD32F3XX_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Interrupt priority grouping
#ifndef GD32F3XX_ETH_IRQ_PRIORITY_GROUPING
   #define GD32F3XX_ETH_IRQ_PRIORITY_GROUPING 3
#elif (GD32F3XX_ETH_IRQ_PRIORITY_GROUPING < 0)
   #error GD32F3XX_ETH_IRQ_PRIORITY_GROUPING parameter is not valid
#endif

//Ethernet interrupt group priority
#ifndef GD32F3XX_ETH_IRQ_GROUP_PRIORITY
   #define GD32F3XX_ETH_IRQ_GROUP_PRIORITY 12
#elif (GD32F3XX_ETH_IRQ_GROUP_PRIORITY < 0)
   #error GD32F3XX_ETH_IRQ_GROUP_PRIORITY parameter is not valid
#endif

//Ethernet interrupt subpriority
#ifndef GD32F3XX_ETH_IRQ_SUB_PRIORITY
   #define GD32F3XX_ETH_IRQ_SUB_PRIORITY 0
#elif (GD32F3XX_ETH_IRQ_SUB_PRIORITY < 0)
   #error GD32F3XX_ETH_IRQ_SUB_PRIORITY parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Enhanced TX DMA descriptor
 **/

typedef struct
{
   uint32_t tdes0;
   uint32_t tdes1;
   uint32_t tdes2;
   uint32_t tdes3;
   uint32_t tdes4;
   uint32_t tdes5;
   uint32_t tdes6;
   uint32_t tdes7;
} Gd32f3xxTxDmaDesc;


/**
 * @brief Enhanced RX DMA descriptor
 **/

typedef struct
{
   uint32_t rdes0;
   uint32_t rdes1;
   uint32_t rdes2;
   uint32_t rdes3;
   uint32_t rdes4;
   uint32_t rdes5;
   uint32_t rdes6;
   uint32_t rdes7;
} Gd32f3xxRxDmaDesc;


//GD32F3XX Ethernet MAC driver
extern const NicDriver gd32f3xxEthDriver;

//GD32F3XX Ethernet MAC related functions
error_t gd32f3xxEthInit(NetInterface *interface);
void gd32f3xxEthInitGpio(NetInterface *interface);
void gd32f3xxEthInitDmaDesc(NetInterface *interface);

void gd32f3xxEthTick(NetInterface *interface);

void gd32f3xxEthEnableIrq(NetInterface *interface);
void gd32f3xxEthDisableIrq(NetInterface *interface);
void gd32f3xxEthEventHandler(NetInterface *interface);

error_t gd32f3xxEthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t gd32f3xxEthReceivePacket(NetInterface *interface);

error_t gd32f3xxEthUpdateMacAddrFilter(NetInterface *interface);
error_t gd32f3xxEthUpdateMacConfig(NetInterface *interface);

void gd32f3xxEthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data);

uint16_t gd32f3xxEthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr);

uint32_t gd32f3xxEthCalcCrc(const void *data, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
