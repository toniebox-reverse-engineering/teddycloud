/**
 * @file s7g2_eth1_driver.h
 * @brief Renesas Synergy S7G2 Ethernet MAC driver (ETHERC0 instance)
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

#ifndef _S7G2_ETH1_DRIVER_H
#define _S7G2_ETH1_DRIVER_H

//Dependencies
#include "core/nic.h"

//Number of TX buffers
#ifndef S7G2_ETH1_TX_BUFFER_COUNT
   #define S7G2_ETH1_TX_BUFFER_COUNT 3
#elif (S7G2_ETH1_TX_BUFFER_COUNT < 1)
   #error S7G2_ETH1_TX_BUFFER_COUNT parameter is not valid
#endif

//TX buffer size
#ifndef S7G2_ETH1_TX_BUFFER_SIZE
   #define S7G2_ETH1_TX_BUFFER_SIZE 1536
#elif (S7G2_ETH1_TX_BUFFER_SIZE != 1536)
   #error S7G2_ETH1_TX_BUFFER_SIZE parameter is not valid
#endif

//Number of RX buffers
#ifndef S7G2_ETH1_RX_BUFFER_COUNT
   #define S7G2_ETH1_RX_BUFFER_COUNT 6
#elif (S7G2_ETH1_RX_BUFFER_COUNT < 1)
   #error S7G2_ETH1_RX_BUFFER_COUNT parameter is not valid
#endif

//RX buffer size
#ifndef S7G2_ETH1_RX_BUFFER_SIZE
   #define S7G2_ETH1_RX_BUFFER_SIZE 1536
#elif (S7G2_ETH1_RX_BUFFER_SIZE != 1536)
   #error S7G2_ETH1_RX_BUFFER_SIZE parameter is not valid
#endif

//Interrupt priority grouping
#ifndef S7G2_ETH1_IRQ_PRIORITY_GROUPING
   #define S7G2_ETH1_IRQ_PRIORITY_GROUPING 3
#elif (S7G2_ETH1_IRQ_PRIORITY_GROUPING < 0)
   #error S7G2_ETH1_IRQ_PRIORITY_GROUPING parameter is not valid
#endif

//Ethernet interrupt group priority
#ifndef S7G2_ETH1_IRQ_GROUP_PRIORITY
   #define S7G2_ETH1_IRQ_GROUP_PRIORITY 12
#elif (S7G2_ETH1_IRQ_GROUP_PRIORITY < 0)
   #error S7G2_ETH1_IRQ_GROUP_PRIORITY parameter is not valid
#endif

//Ethernet interrupt subpriority
#ifndef S7G2_ETH1_IRQ_SUB_PRIORITY
   #define S7G2_ETH1_IRQ_SUB_PRIORITY 0
#elif (S7G2_ETH1_IRQ_SUB_PRIORITY < 0)
   #error S7G2_ETH1_IRQ_SUB_PRIORITY parameter is not valid
#endif

//ECMR register
#define ETHERC_ECMR_TPC      0x00100000
#define ETHERC_ECMR_ZPF      0x00080000
#define ETHERC_ECMR_PFR      0x00040000
#define ETHERC_ECMR_RXF      0x00020000
#define ETHERC_ECMR_TXF      0x00010000
#define ETHERC_ECMR_PRCEF    0x00001000
#define ETHERC_ECMR_MPDE     0x00000200
#define ETHERC_ECMR_RE       0x00000040
#define ETHERC_ECMR_TE       0x00000020
#define ETHERC_ECMR_ILB      0x00000008
#define ETHERC_ECMR_RTM      0x00000004
#define ETHERC_ECMR_DM       0x00000002
#define ETHERC_ECMR_PRM      0x00000001

//PIR register
#define ETHERC_PIR_MDI       0x00000008
#define ETHERC_PIR_MDO       0x00000004
#define ETHERC_PIR_MMD       0x00000002
#define ETHERC_PIR_MDC       0x00000001

//EDMR register
#define EDMAC_EDMR_DE        0x00000040
#define EDMAC_EDMR_DL        0x00000030
#define EDMAC_EDMR_DL_16     0x00000000
#define EDMAC_EDMR_DL_32     0x00000010
#define EDMAC_EDMR_DL_64     0x00000020
#define EDMAC_EDMR_SWR       0x00000001

//EDTRR register
#define EDMAC_EDTRR_TR       0x00000001

//EDRRR register
#define EDMAC_EDRRR_RR       0x00000001

//EESR register
#define EDMAC_EESR_TWB       0x40000000
#define EDMAC_EESR_TABT      0x04000000
#define EDMAC_EESR_RABT      0x02000000
#define EDMAC_EESR_RFCOF     0x01000000
#define EDMAC_EESR_ADE       0x00800000
#define EDMAC_EESR_ECI       0x00400000
#define EDMAC_EESR_TC        0x00200000
#define EDMAC_EESR_TDE       0x00100000
#define EDMAC_EESR_TFUF      0x00080000
#define EDMAC_EESR_FR        0x00040000
#define EDMAC_EESR_RDE       0x00020000
#define EDMAC_EESR_RFOF      0x00010000
#define EDMAC_EESR_CND       0x00000800
#define EDMAC_EESR_DLC       0x00000400
#define EDMAC_EESR_CD        0x00000200
#define EDMAC_EESR_TRO       0x00000100
#define EDMAC_EESR_RMAF      0x00000080
#define EDMAC_EESR_RRF       0x00000010
#define EDMAC_EESR_RTLF      0x00000008
#define EDMAC_EESR_RTSF      0x00000004
#define EDMAC_EESR_PRE       0x00000002
#define EDMAC_EESR_CERF      0x00000001

//EESIPR register
#define EDMAC_EESIPR_TWBIP   0x40000000
#define EDMAC_EESIPR_TABTIP  0x04000000
#define EDMAC_EESIPR_RABTIP  0x02000000
#define EDMAC_EESIPR_RFCOFIP 0x01000000
#define EDMAC_EESIPR_ADEIP   0x00800000
#define EDMAC_EESIPR_ECIIP   0x00400000
#define EDMAC_EESIPR_TCIP    0x00200000
#define EDMAC_EESIPR_TDEIP   0x00100000
#define EDMAC_EESIPR_TFUFIP  0x00080000
#define EDMAC_EESIPR_FRIP    0x00040000
#define EDMAC_EESIPR_RDEIP   0x00020000
#define EDMAC_EESIPR_RFOFIP  0x00010000
#define EDMAC_EESIPR_CNDIP   0x00000800
#define EDMAC_EESIPR_DLCIP   0x00000400
#define EDMAC_EESIPR_CDIP    0x00000200
#define EDMAC_EESIPR_TROIP   0x00000100
#define EDMAC_EESIPR_RMAFIP  0x00000080
#define EDMAC_EESIPR_RRFIP   0x00000010
#define EDMAC_EESIPR_RTLFIP  0x00000008
#define EDMAC_EESIPR_RTSFIP  0x00000004
#define EDMAC_EESIPR_PREIP   0x00000002
#define EDMAC_EESIPR_CERFIP  0x00000001

//FDR register
#define EDMAC_FDR_TFD        0x00001F00
#define EDMAC_FDR_TFD_2048   0x00000700
#define EDMAC_FDR_RFD        0x0000001F
#define EDMAC_FDR_RFD_4096   0x0000000F

//RMCR register
#define EDMAC_RMCR_RNR       0x00000001

//TRIMD register
#define EDMAC_TRIMD_TIM      0x00000010
#define EDMAC_TRIMD_TIS      0x00000001

//Transmit DMA descriptor flags
#define EDMAC_TD0_TACT       0x80000000
#define EDMAC_TD0_TDLE       0x40000000
#define EDMAC_TD0_TFP_SOF    0x20000000
#define EDMAC_TD0_TFP_EOF    0x10000000
#define EDMAC_TD0_TFE        0x08000000
#define EDMAC_TD0_TWBI       0x04000000
#define EDMAC_TD0_TFS_MASK   0x0000010F
#define EDMAC_TD0_TFS_TABT   0x00000100
#define EDMAC_TD0_TFS_CND    0x00000008
#define EDMAC_TD0_TFS_DLC    0x00000004
#define EDMAC_TD0_TFS_CD     0x00000002
#define EDMAC_TD0_TFS_TRO    0x00000001
#define EDMAC_TD1_TBL        0xFFFF0000
#define EDMAC_TD2_TBA        0xFFFFFFFF

//Receive DMA descriptor flags
#define EDMAC_RD0_RACT       0x80000000
#define EDMAC_RD0_RDLE       0x40000000
#define EDMAC_RD0_RFP_SOF    0x20000000
#define EDMAC_RD0_RFP_EOF    0x10000000
#define EDMAC_RD0_RFE        0x08000000
#define EDMAC_RD0_RFS_MASK   0x0000039F
#define EDMAC_RD0_RFS_RFOF   0x00000200
#define EDMAC_RD0_RFS_RABT   0x00000100
#define EDMAC_RD0_RFS_RMAF   0x00000080
#define EDMAC_RD0_RFS_RRF    0x00000010
#define EDMAC_RD0_RFS_RTLF   0x00000008
#define EDMAC_RD0_RFS_RTSF   0x00000004
#define EDMAC_RD0_RFS_PRE    0x00000002
#define EDMAC_RD0_RFS_CERF   0x00000001
#define EDMAC_RD1_RBL        0xFFFF0000
#define EDMAC_RD1_RFL        0x0000FFFF
#define EDMAC_RD2_RBA        0xFFFFFFFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Transmit DMA descriptor
 **/

typedef struct
{
   uint32_t td0;
   uint32_t td1;
   uint32_t td2;
   uint32_t padding;
} S7g2Eth1TxDmaDesc;


/**
 * @brief Receive DMA descriptor
 **/

typedef struct
{
   uint32_t rd0;
   uint32_t rd1;
   uint32_t rd2;
   uint32_t padding;
} S7g2Eth1RxDmaDesc;


//S7G2 Ethernet MAC driver (ETHERC0 instance)
extern const NicDriver s7g2Eth1Driver;

//S7G2 Ethernet MAC related functions
error_t s7g2Eth1Init(NetInterface *interface);
void s7g2Eth1InitGpio(NetInterface *interface);
void s7g2Eth1InitDmaDesc(NetInterface *interface);

void s7g2Eth1Tick(NetInterface *interface);

void s7g2Eth1EnableIrq(NetInterface *interface);
void s7g2Eth1DisableIrq(NetInterface *interface);
void s7g2Eth1EventHandler(NetInterface *interface);

error_t s7g2Eth1SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t s7g2Eth1ReceivePacket(NetInterface *interface);

error_t s7g2Eth1UpdateMacAddrFilter(NetInterface *interface);
error_t s7g2Eth1UpdateMacConfig(NetInterface *interface);

void s7g2Eth1WritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data);

uint16_t s7g2Eth1ReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr);

void s7g2Eth1WriteSmi(uint32_t data, uint_t length);
uint32_t s7g2Eth1ReadSmi(uint_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
