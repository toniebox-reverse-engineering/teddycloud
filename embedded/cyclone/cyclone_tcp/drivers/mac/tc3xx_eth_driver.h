/**
 * @file tc3xx_eth_driver.h
 * @brief Infineon AURIX TriCore TC3xx Ethernet MAC driver
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

#ifndef _TC3XX_ETH_DRIVER_H
#define _TC3XX_ETH_DRIVER_H

//Dependencies
#include "core/nic.h"

//Number of TX buffers
#ifndef TC3XX_ETH_TX_BUFFER_COUNT
   #define TC3XX_ETH_TX_BUFFER_COUNT 3
#elif (TC3XX_ETH_TX_BUFFER_COUNT < 1)
   #error TC3XX_ETH_TX_BUFFER_COUNT parameter is not valid
#endif

//TX buffer size
#ifndef TC3XX_ETH_TX_BUFFER_SIZE
   #define TC3XX_ETH_TX_BUFFER_SIZE 1536
#elif (TC3XX_ETH_TX_BUFFER_SIZE != 1536)
   #error TC3XX_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//Number of RX buffers
#ifndef TC3XX_ETH_RX_BUFFER_COUNT
   #define TC3XX_ETH_RX_BUFFER_COUNT 6
#elif (TC3XX_ETH_RX_BUFFER_COUNT < 1)
   #error TC3XX_ETH_RX_BUFFER_COUNT parameter is not valid
#endif

//RX buffer size
#ifndef TC3XX_ETH_RX_BUFFER_SIZE
   #define TC3XX_ETH_RX_BUFFER_SIZE 1536
#elif (TC3XX_ETH_RX_BUFFER_SIZE != 1536)
   #error TC3XX_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Ethernet interrupt priority
#ifndef TC3XX_ETH_IRQ_PRIORITY
   #define TC3XX_ETH_IRQ_PRIORITY 10
#elif (TC3XX_ETH_IRQ_PRIORITY < 0)
   #error TC3XX_ETH_IRQ_PRIORITY parameter is not valid
#endif

//DMA_CH_STATUS register
#define ETH_DMA_CH_STATUS_REB            0x00380000
#define ETH_DMA_CH_STATUS_TEB            0x00070000
#define ETH_DMA_CH_STATUS_NIS            0x00008000
#define ETH_DMA_CH_STATUS_AIS            0x00004000
#define ETH_DMA_CH_STATUS_CDE            0x00002000
#define ETH_DMA_CH_STATUS_FBE            0x00001000
#define ETH_DMA_CH_STATUS_ERI            0x00000800
#define ETH_DMA_CH_STATUS_ETI            0x00000400
#define ETH_DMA_CH_STATUS_RWT            0x00000200
#define ETH_DMA_CH_STATUS_RPS            0x00000100
#define ETH_DMA_CH_STATUS_RBU            0x00000080
#define ETH_DMA_CH_STATUS_RI             0x00000040
#define ETH_DMA_CH_STATUS_TBU            0x00000004
#define ETH_DMA_CH_STATUS_TPS            0x00000002
#define ETH_DMA_CH_STATUS_TI             0x00000001

//DMA_CH_INTERRUPT_ENABLE register
#define ETH_DMA_CH_INTERRUPT_ENABLE_NIE  0x00008000
#define ETH_DMA_CH_INTERRUPT_ENABLE_AIE  0x00004000
#define ETH_DMA_CH_INTERRUPT_ENABLE_CDEE 0x00002000
#define ETH_DMA_CH_INTERRUPT_ENABLE_FBEE 0x00001000
#define ETH_DMA_CH_INTERRUPT_ENABLE_ERIE 0x00000800
#define ETH_DMA_CH_INTERRUPT_ENABLE_ETIE 0x00000400
#define ETH_DMA_CH_INTERRUPT_ENABLE_RWTE 0x00000200
#define ETH_DMA_CH_INTERRUPT_ENABLE_RSE  0x00000100
#define ETH_DMA_CH_INTERRUPT_ENABLE_RBUE 0x00000080
#define ETH_DMA_CH_INTERRUPT_ENABLE_RIE  0x00000040
#define ETH_DMA_CH_INTERRUPT_ENABLE_TBUE 0x00000004
#define ETH_DMA_CH_INTERRUPT_ENABLE_TXSE 0x00000002
#define ETH_DMA_CH_INTERRUPT_ENABLE_TIE  0x00000001

//Transmit normal descriptor (read format)
#define ETH_TDES0_BUF1AP                 0xFFFFFFFF
#define ETH_TDES1_BUF2AP                 0xFFFFFFFF
#define ETH_TDES2_IOC                    0x80000000
#define ETH_TDES2_TTSE                   0x40000000
#define ETH_TDES2_B2L                    0x3FFF0000
#define ETH_TDES2_B1L                    0x00003FFF
#define ETH_TDES3_OWN                    0x80000000
#define ETH_TDES3_CTXT                   0x40000000
#define ETH_TDES3_FD                     0x20000000
#define ETH_TDES3_LD                     0x10000000
#define ETH_TDES3_CPC                    0x0C000000
#define ETH_TDES3_SLOTNUM                0x00780000
#define ETH_TDES3_CIC                    0x00030000
#define ETH_TDES3_FL                     0x00007FFF

//Transmit normal descriptor (write-back format)
#define ETH_TDES0_TTSL                   0xFFFFFFFF
#define ETH_TDES1_TTSH                   0xFFFFFFFF
#define ETH_TDES3_OWN                    0x80000000
#define ETH_TDES3_CTXT                   0x40000000
#define ETH_TDES3_FD                     0x20000000
#define ETH_TDES3_LD                     0x10000000
#define ETH_TDES3_TTSS                   0x00020000
#define ETH_TDES3_ES                     0x00008000
#define ETH_TDES3_JT                     0x00004000
#define ETH_TDES3_FF                     0x00002000
#define ETH_TDES3_PCE                    0x00001000
#define ETH_TDES3_LOC                    0x00000800
#define ETH_TDES3_NC                     0x00000400
#define ETH_TDES3_LC                     0x00000200
#define ETH_TDES3_EC                     0x00000100
#define ETH_TDES3_CC                     0x000000F0
#define ETH_TDES3_ED                     0x00000008
#define ETH_TDES3_UF                     0x00000004
#define ETH_TDES3_DB                     0x00000002
#define ETH_TDES3_IHE                    0x00000001

//Receive normal descriptor (read format)
#define ETH_RDES0_BUF1AP                 0xFFFFFFFF
#define ETH_RDES2_BUF2AP                 0xFFFFFFFF
#define ETH_RDES3_OWN                    0x80000000
#define ETH_RDES3_IOC                    0x40000000
#define ETH_RDES3_BUF2V                  0x02000000
#define ETH_RDES3_BUF1V                  0x01000000

//Receive normal descriptor (write-back format)
#define ETH_RDES1_OPC                    0xFFFF0000
#define ETH_RDES1_TD                     0x00008000
#define ETH_RDES1_TSA                    0x00004000
#define ETH_RDES1_PV                     0x00002000
#define ETH_RDES1_PFT                    0x00001000
#define ETH_RDES1_PMT                    0x00000F00
#define ETH_RDES1_IPCE                   0x00000080
#define ETH_RDES1_IPCB                   0x00000040
#define ETH_RDES1_IPV6                   0x00000020
#define ETH_RDES1_IPV4                   0x00000010
#define ETH_RDES1_IPHE                   0x00000008
#define ETH_RDES1_PT                     0x00000007
#define ETH_RDES2_MADRM                  0x07F80000
#define ETH_RDES2_DAF                    0x00020000
#define ETH_RDES2_SAF                    0x00010000
#define ETH_RDES3_OWN                    0x80000000
#define ETH_RDES3_CTXT                   0x40000000
#define ETH_RDES3_FD                     0x20000000
#define ETH_RDES3_LD                     0x10000000
#define ETH_RDES3_RS2V                   0x08000000
#define ETH_RDES3_RS1V                   0x04000000
#define ETH_RDES3_RS0V                   0x02000000
#define ETH_RDES3_CE                     0x01000000
#define ETH_RDES3_GP                     0x00800000
#define ETH_RDES3_RWT                    0x00400000
#define ETH_RDES3_OE                     0x00200000
#define ETH_RDES3_RE                     0x00100000
#define ETH_RDES3_DE                     0x00080000
#define ETH_RDES3_LT                     0x00070000
#define ETH_RDES3_ES                     0x00008000
#define ETH_RDES3_PL                     0x00007FFF

//Get CPU core identifier
#define ETH_CPU_ID() (_mfcr(CPU_CORE_ID) & IFX_CPU_CORE_ID_CORE_ID_MSK)

//Convert a local DSPR address to a global DSPR address
#define ETH_GLOBAL_DSPR_ADDR(address) \
   ((((uint32_t) (address) & 0xF0000000) == 0xD0000000) ? \
   ((((uint32_t) (address) & 0x000FFFFF) | 0x70000000) - (ETH_CPU_ID() * 0x10000000)) : \
   (uint32_t) (address))

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Transmit DMA descriptor
 **/

typedef struct
{
   uint32_t tdes0;
   uint32_t tdes1;
   uint32_t tdes2;
   uint32_t tdes3;
} Tc3xxTxDmaDesc;


/**
 * @brief Receive DMA descriptor
 **/

typedef struct
{
   uint32_t rdes0;
   uint32_t rdes1;
   uint32_t rdes2;
   uint32_t rdes3;
} Tc3xxRxDmaDesc;


//TC3xx Ethernet MAC driver
extern const NicDriver tc3xxEthDriver;

//TC3xx Ethernet MAC related functions
error_t tc3xxEthInit(NetInterface *interface);
void tc3xxEthInitGpio(NetInterface *interface);
void tc3xxEthInitDmaDesc(NetInterface *interface);

void tc3xxEthTick(NetInterface *interface);

void tc3xxEthEnableIrq(NetInterface *interface);
void tc3xxEthDisableIrq(NetInterface *interface);
void tc3xxEthIrqHandler(int_t arg);
void tc3xxEthEventHandler(NetInterface *interface);

error_t tc3xxEthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t tc3xxEthReceivePacket(NetInterface *interface);

error_t tc3xxEthUpdateMacAddrFilter(NetInterface *interface);
error_t tc3xxEthUpdateMacConfig(NetInterface *interface);

void tc3xxEthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data);

uint16_t tc3xxEthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
