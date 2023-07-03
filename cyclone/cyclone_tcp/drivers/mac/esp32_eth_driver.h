/**
 * @file esp32_eth_driver.h
 * @brief ESP32 Ethernet MAC driver
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

#ifndef _ESP32_ETH_DRIVER_H
#define _ESP32_ETH_DRIVER_H

//Dependencies
#include "core/nic.h"

//Number of TX buffers
#ifndef ESP32_ETH_TX_BUFFER_COUNT
   #define ESP32_ETH_TX_BUFFER_COUNT 3
#elif (ESP32_ETH_TX_BUFFER_COUNT < 1)
   #error ESP32_ETH_TX_BUFFER_COUNT parameter is not valid
#endif

//TX buffer size
#ifndef ESP32_ETH_TX_BUFFER_SIZE
   #define ESP32_ETH_TX_BUFFER_SIZE 1536
#elif (ESP32_ETH_TX_BUFFER_SIZE != 1536)
   #error ESP32_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//Number of RX buffers
#ifndef ESP32_ETH_RX_BUFFER_COUNT
   #define ESP32_ETH_RX_BUFFER_COUNT 6
#elif (ESP32_ETH_RX_BUFFER_COUNT < 1)
   #error ESP32_ETH_RX_BUFFER_COUNT parameter is not valid
#endif

//RX buffer size
#ifndef ESP32_ETH_RX_BUFFER_SIZE
   #define ESP32_ETH_RX_BUFFER_SIZE 1536
#elif (ESP32_ETH_RX_BUFFER_SIZE != 1536)
   #error ESP32_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Ethernet interrupt flags
#ifndef ESP32_ETH_IRQ_FLAGS
   #define ESP32_ETH_IRQ_FLAGS ESP_INTR_FLAG_LEVEL2
#endif

//DMA configuration and control registers
#define EMAC_DMABUSMODE_REG                            *((volatile uint32_t *) 0x3FF69000)
#define EMAC_DMATXPOLLDEMAND_REG                       *((volatile uint32_t *) 0x3FF69004)
#define EMAC_DMARXPOLLDEMAND_REG                       *((volatile uint32_t *) 0x3FF69008)
#define EMAC_DMARXBASEADDR_REG                         *((volatile uint32_t *) 0x3FF6900C)
#define EMAC_DMATXBASEADDR_REG                         *((volatile uint32_t *) 0x3FF69010)
#define EMAC_DMASTATUS_REG                             *((volatile uint32_t *) 0x3FF69014)
#define EMAC_DMAOPERATION_MODE_REG                     *((volatile uint32_t *) 0x3FF69018)
#define EMAC_DMAIN_EN_REG                              *((volatile uint32_t *) 0x3FF6901C)
#define EMAC_DMAMISSEDFR_REG                           *((volatile uint32_t *) 0x3FF69020)
#define EMAC_DMARINTWDTIMER_REG                        *((volatile uint32_t *) 0x3FF69024)
#define EMAC_DMATXCURRDESC_REG                         *((volatile uint32_t *) 0x3FF69048)
#define EMAC_DMARXCURRDESC_REG                         *((volatile uint32_t *) 0x3FF6904C)
#define EMAC_DMATXCURRADDR_BUF_REG                     *((volatile uint32_t *) 0x3FF69050)
#define EMAC_DMARXCURRADDR_BUF_REG                     *((volatile uint32_t *) 0x3FF69054)

//MAC configuration and control registers
#define EMAC_CONFIG_REG                                *((volatile uint32_t *) 0x3FF6A000)
#define EMAC_FF_REG                                    *((volatile uint32_t *) 0x3FF6A004)
#define EMAC_MIIADDR_REG                               *((volatile uint32_t *) 0x3FF6A010)
#define EMAC_MIIDATA_REG                               *((volatile uint32_t *) 0x3FF6A014)
#define EMAC_FC_REG                                    *((volatile uint32_t *) 0x3FF6A018)
#define EMAC_DEBUG_REG                                 *((volatile uint32_t *) 0x3FF6A024)
#define EMAC_PMT_RWUFFR_REG                            *((volatile uint32_t *) 0x3FF6A028)
#define EMAC_PMT_CSR_REG                               *((volatile uint32_t *) 0x3FF6A02C)
#define EMAC_LPI_CSR_REG                               *((volatile uint32_t *) 0x3FF6A030)
#define EMAC_LPITIMERSCONTROL_REG                      *((volatile uint32_t *) 0x3FF6A034)
#define EMAC_INTS_REG                                  *((volatile uint32_t *) 0x3FF6A038)
#define EMAC_INTMASK_REG                               *((volatile uint32_t *) 0x3FF6A03C)
#define EMAC_ADDR0HIGH_REG                             *((volatile uint32_t *) 0x3FF6A040)
#define EMAC_ADDR0LOW_REG                              *((volatile uint32_t *) 0x3FF6A044)
#define EMAC_ADDR1HIGH_REG                             *((volatile uint32_t *) 0x3FF6A048)
#define EMAC_ADDR1LOW_REG                              *((volatile uint32_t *) 0x3FF6A04C)
#define EMAC_ADDR2HIGH_REG                             *((volatile uint32_t *) 0x3FF6A050)
#define EMAC_ADDR2LOW_REG                              *((volatile uint32_t *) 0x3FF6A054)
#define EMAC_ADDR3HIGH_REG                             *((volatile uint32_t *) 0x3FF6A058)
#define EMAC_ADDR3LOW_REG                              *((volatile uint32_t *) 0x3FF6A05C)
#define EMAC_ADDR4HIGH_REG                             *((volatile uint32_t *) 0x3FF6A060)
#define EMAC_ADDR4LOW_REG                              *((volatile uint32_t *) 0x3FF6A064)
#define EMAC_ADDR5HIGH_REG                             *((volatile uint32_t *) 0x3FF6A068)
#define EMAC_ADDR5LOW_REG                              *((volatile uint32_t *) 0x3FF6A06C)
#define EMAC_ADDR6HIGH_REG                             *((volatile uint32_t *) 0x3FF6A070)
#define EMAC_ADDR6LOW_REG                              *((volatile uint32_t *) 0x3FF6A074)
#define EMAC_ADDR7HIGH_REG                             *((volatile uint32_t *) 0x3FF6A078)
#define EMAC_ADDR7LOW_REG                              *((volatile uint32_t *) 0x3FF6A07C)
#define EMAC_STATUS_REG                                *((volatile uint32_t *) 0x3FF6A0D8)
#define EMAC_WDOGTO_REG                                *((volatile uint32_t *) 0x3FF6A0DC)

//Clock configuration registers
#define EMAC_EX_CLKOUT_CONF_REG                        *((volatile uint32_t *) 0x3FF69800)
#define EMAC_EX_OSCCLK_CONF_REG                        *((volatile uint32_t *) 0x3FF69804)
#define EMAC_EX_CLK_CTRL_REG                           *((volatile uint32_t *) 0x3FF69808)

//PHY type and SRAM configuration registers
#define EMAC_EX_PHYINF_CONF_REG                        *((volatile uint32_t *) 0x3FF6980C)
#define EMAC_PD_SEL_REG                                *((volatile uint32_t *) 0x3FF69810)

//DMA Bus Mode register
#define EMAC_DMABUSMODE_DMAMIXEDBURST                  0x04000000
#define EMAC_DMABUSMODE_DMAADDRALIBEA                  0x02000000
#define EMAC_DMABUSMODE_PBLX8_MODE                     0x01000000
#define EMAC_DMABUSMODE_USE_SEP_PBL                    0x00800000
#define EMAC_DMABUSMODE_RX_DMA_PBL                     0x007E0000
#define EMAC_DMABUSMODE_RX_DMA_PBL_1                   0x00020000
#define EMAC_DMABUSMODE_RX_DMA_PBL_2                   0x00040000
#define EMAC_DMABUSMODE_RX_DMA_PBL_4                   0x00080000
#define EMAC_DMABUSMODE_RX_DMA_PBL_8                   0x00100000
#define EMAC_DMABUSMODE_RX_DMA_PBL_16                  0x00200000
#define EMAC_DMABUSMODE_RX_DMA_PBL_32                  0x00400000
#define EMAC_DMABUSMODE_FIXED_BURST                    0x00010000
#define EMAC_DMABUSMODE_PRI_RATIO                      0x0000C000
#define EMAC_DMABUSMODE_PRI_RATIO_1_1                  0x00000000
#define EMAC_DMABUSMODE_PRI_RATIO_2_1                  0x00004000
#define EMAC_DMABUSMODE_PRI_RATIO_3_1                  0x00008000
#define EMAC_DMABUSMODE_PRI_RATIO_4_1                  0x0000C000
#define EMAC_DMABUSMODE_PROG_BURST_LEN                 0x00003F00
#define EMAC_DMABUSMODE_PROG_BURST_LEN_1               0x00000100
#define EMAC_DMABUSMODE_PROG_BURST_LEN_2               0x00000200
#define EMAC_DMABUSMODE_PROG_BURST_LEN_4               0x00000400
#define EMAC_DMABUSMODE_PROG_BURST_LEN_8               0x00000800
#define EMAC_DMABUSMODE_PROG_BURST_LEN_16              0x00001000
#define EMAC_DMABUSMODE_PROG_BURST_LEN_32              0x00002000
#define EMAC_DMABUSMODE_ALT_DESC_SIZE                  0x00000080
#define EMAC_DMABUSMODE_DESC_SKIP_LEN                  0x0000007C
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_0                0x00000000
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_1                0x00000004
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_2                0x00000008
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_4                0x00000010
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_8                0x00000020
#define EMAC_DMABUSMODE_DESC_SKIP_LEN_16               0x00000040
#define EMAC_DMABUSMODE_DMA_ARB_SCH                    0x00000002
#define EMAC_DMABUSMODE_SW_RST                         0x00000001

//DMA Status register
#define EMAC_DMASTATUS_TS_TRI_INT                      0x20000000
#define EMAC_DMASTATUS_EMAC_PMT_INT                    0x10000000
#define EMAC_DMASTATUS_ERROR_BITS                      0x03800000
#define EMAC_DMASTATUS_TRANS_PROC_STATE                0x00700000
#define EMAC_DMASTATUS_RECV_PROC_STATE                 0x000E0000
#define EMAC_DMASTATUS_NORM_INT_SUMM                   0x00010000
#define EMAC_DMASTATUS_ABN_INT_SUMM                    0x00008000
#define EMAC_DMASTATUS_EARLY_RECV_INT                  0x00004000
#define EMAC_DMASTATUS_FATAL_BUS_ERR_INT               0x00002000
#define EMAC_DMASTATUS_EARLY_TRANS_INT                 0x00000400
#define EMAC_DMASTATUS_RECV_WDT_TO                     0x00000200
#define EMAC_DMASTATUS_RECV_PROC_STOP                  0x00000100
#define EMAC_DMASTATUS_RECV_BUF_UNAVAIL                0x00000080
#define EMAC_DMASTATUS_RECV_INT                        0x00000040
#define EMAC_DMASTATUS_TRANS_UNDFLOW                   0x00000020
#define EMAC_DMASTATUS_RECV_OVFLOW                     0x00000010
#define EMAC_DMASTATUS_TRANS_JABBER_TO                 0x00000008
#define EMAC_DMASTATUS_TRANS_BUF_UNAVAIL               0x00000004
#define EMAC_DMASTATUS_TRANS_PROC_STOP                 0x00000002
#define EMAC_DMASTATUS_TRANS_INT                       0x00000001

//DMA Operation Mode register
#define EMAC_DMAOPERATION_MODE_DIS_DROP_TCPIP_ERR_FRAM 0x04000000
#define EMAC_DMAOPERATION_MODE_RX_STORE_FORWARD        0x02000000
#define EMAC_DMAOPERATION_MODE_DIS_FLUSH_RECV_FRAMES   0x01000000
#define EMAC_DMAOPERATION_MODE_TX_STORE_FORWARD        0x00200000
#define EMAC_DMAOPERATION_MODE_FLUSH_TX_FIFO           0x00100000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL          0x0001C000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_64       0x00000000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_128      0x00004000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_192      0x00008000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_256      0x0000C000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_40       0x00010000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_32       0x00014000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_24       0x00018000
#define EMAC_DMAOPERATION_MODE_TX_THRESH_CTRL_16       0x0001C000
#define EMAC_DMAOPERATION_MODE_START_STOP_TX           0x00002000
#define EMAC_DMAOPERATION_MODE_FWD_ERR_FRAME           0x00000080
#define EMAC_DMAOPERATION_MODE_FWD_UNDER_GF            0x00000040
#define EMAC_DMAOPERATION_MODE_DROP_GFRM               0x00000020
#define EMAC_DMAOPERATION_MODE_RX_THRESH_CTRL          0x00000018
#define EMAC_DMAOPERATION_MODE_RX_THRESH_CTRL_64       0x00000000
#define EMAC_DMAOPERATION_MODE_RX_THRESH_CTRL_32       0x00000008
#define EMAC_DMAOPERATION_MODE_RX_THRESH_CTRL_96       0x00000010
#define EMAC_DMAOPERATION_MODE_RX_THRESH_CTRL_128      0x00000018
#define EMAC_DMAOPERATION_MODE_OPT_SECOND_FRAME        0x00000004
#define EMAC_DMAOPERATION_MODE_START_STOP_RX           0x00000002

//DMA Interrupt Enable register
#define EMAC_DMAIN_EN_DMAIN_NISE                       0x00010000
#define EMAC_DMAIN_EN_DMAIN_AISE                       0x00008000
#define EMAC_DMAIN_EN_DMAIN_ERIE                       0x00004000
#define EMAC_DMAIN_EN_DMAIN_FBEE                       0x00002000
#define EMAC_DMAIN_EN_DMAIN_ETIE                       0x00000400
#define EMAC_DMAIN_EN_DMAIN_RWTE                       0x00000200
#define EMAC_DMAIN_EN_DMAIN_RSE                        0x00000100
#define EMAC_DMAIN_EN_DMAIN_RBUE                       0x00000080
#define EMAC_DMAIN_EN_DMAIN_RIE                        0x00000040
#define EMAC_DMAIN_EN_DMAIN_UIE                        0x00000020
#define EMAC_DMAIN_EN_DMAIN_OIE                        0x00000010
#define EMAC_DMAIN_EN_DMAIN_TJTE                       0x00000008
#define EMAC_DMAIN_EN_DMAIN_TBUE                       0x00000004
#define EMAC_DMAIN_EN_DMAIN_TSE                        0x00000002
#define EMAC_DMAIN_EN_DMAIN_TIE                        0x00000001

//Missed Frame and Buffer Overflow Counter register
#define EMAC_DMAMISSEDFR_OVERFLOW_BFOC                 0x10000000
#define EMAC_DMAMISSEDFR_OVERFLOW_FC                   0x0FFE0000
#define EMAC_DMAMISSEDFR_OVERFLOW_BMFC                 0x00010000
#define EMAC_DMAMISSEDFR_MISSED_FC                     0x0000FFFF

//DMA Receive Status Watchdog Timer register
#define EMAC_DMARINTWDTIMER_RIWTC                      0x000000FF

//DMA Current Host Transmit Descriptor register
#define EMAC_DMATXCURRDESC_TRANS_DSCR_ADDR_PTR         0xFFFFFFFF

//DMA Current Host Receive Descriptor register
#define EMAC_DMARXCURRDESC_RECV_DSCR_ADDR_PTR          0xFFFFFFFF

//DMA Current Host Transmit Buffer Address register
#define EMAC_DMATXCURRADDR_BUF_TRANS_BUFF_ADDR_PTR     0xFFFFFFFF

//DMA Current Host Receive Buffer Address register
#define EMAC_DMARXCURRADDR_BUF_RECV_BUFF_ADDR_PTR      0xFFFFFFFF

//MAC Configuration register
#define EMAC_CONFIG_SAIRC                              0x70000000
#define EMAC_CONFIG_ASS2KP                             0x08000000
#define EMAC_CONFIG_EMACWATCHDOG                       0x00800000
#define EMAC_CONFIG_EMACJABBER                         0x00400000
#define EMAC_CONFIG_EMACJUMBOFRAME                     0x00100000
#define EMAC_CONFIG_EMACINTERFRAMEGAP                  0x000E0000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_96               0x00000000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_88               0x00020000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_80               0x00040000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_72               0x00060000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_64               0x00080000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_56               0x000A0000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_48               0x000C0000
#define EMAC_CONFIG_EMACINTERFRAMEGAP_40               0x000E0000
#define EMAC_CONFIG_EMACDISABLECRS                     0x00010000
#define EMAC_CONFIG_EMACMII                            0x00008000
#define EMAC_CONFIG_EMACFESPEED                        0x00004000
#define EMAC_CONFIG_EMACRXOWN                          0x00002000
#define EMAC_CONFIG_EMACLOOPBACK                       0x00001000
#define EMAC_CONFIG_EMACDUPLEX                         0x00000800
#define EMAC_CONFIG_EMACRXIPCOFFLOAD                   0x00000400
#define EMAC_CONFIG_EMACRETRY                          0x00000200
#define EMAC_CONFIG_EMACPADCRCSTRIP                    0x00000080
#define EMAC_CONFIG_EMACBACKOFFLIMIT                   0x00000060
#define EMAC_CONFIG_EMACBACKOFFLIMIT_10                0x00000040
#define EMAC_CONFIG_EMACBACKOFFLIMIT_8                 0x00000020
#define EMAC_CONFIG_EMACBACKOFFLIMIT_4                 0x00000040
#define EMAC_CONFIG_EMACBACKOFFLIMIT_1                 0x00000060
#define EMAC_CONFIG_EMACDEFERRALCHECK                  0x00000010
#define EMAC_CONFIG_EMACTX                             0x00000008
#define EMAC_CONFIG_EMACRX                             0x00000004
#define EMAC_CONFIG_PLTF                               0x00000003
#define EMAC_CONFIG_PLTF_7                             0x00000000
#define EMAC_CONFIG_PLTF_5                             0x00000001
#define EMAC_CONFIG_PLTF_3                             0x00000002

//Frame Filter register
#define EMAC_FF_RECEIVE_ALL                            0x80000000
#define EMAC_FF_SAFE                                   0x00000200
#define EMAC_FF_SAIF                                   0x00000100
#define EMAC_FF_PCF                                    0x000000C0
#define EMAC_FF_DBF                                    0x00000020
#define EMAC_FF_PAM                                    0x00000010
#define EMAC_FF_DAIF                                   0x00000008
#define EMAC_FF_PMODE                                  0x00000001

//MAC MII Address register
#define EMAC_MIIADDR_MIIDEV                            0x0000F800
#define EMAC_MIIADDR_MIIREG                            0x000007C0
#define EMAC_MIIADDR_MIICSRCLK                         0x0000003C
#define EMAC_MIIADDR_MIICSRCLK_DIV_42                  0x00000000
#define EMAC_MIIADDR_MIICSRCLK_DIV_62                  0x00000004
#define EMAC_MIIADDR_MIICSRCLK_DIV_16                  0x00000008
#define EMAC_MIIADDR_MIICSRCLK_DIV_26                  0x0000000C
#define EMAC_MIIADDR_MIICSRCLK_DIV_102                 0x00000010
#define EMAC_MIIADDR_MIICSRCLK_DIV_124                 0x00000014
#define EMAC_MIIADDR_MIIWRITE                          0x00000002
#define EMAC_MIIADDR_MIIBUSY                           0x00000001

//MAC MII Data register
#define EMAC_MIIDATA_MII_DATA                          0x0000FFFF

//MAC Flow Control register
#define EMAC_FC_PAUSE_TIME                             0xFFFF0000
#define EMAC_FC_PLT                                    0x00000030
#define EMAC_FC_UPFD                                   0x00000008
#define EMAC_FC_RFCE                                   0x00000004
#define EMAC_FC_TFCE                                   0x00000002
#define EMAC_FC_FCBBA                                  0x00000001

//MAC Debug register
#define EMAC_DEBUG_MTLTSFFS                            0x02000000
#define EMAC_DEBUG_MTLTFNES                            0x01000000
#define EMAC_DEBUG_MTLTFWCS                            0x00400000
#define EMAC_DEBUG_MTLTFRCS                            0x00300000
#define EMAC_DEBUG_MTLTFRCS_IDLE                       0x00000000
#define EMAC_DEBUG_MTLTFRCS_READ                       0x00100000
#define EMAC_DEBUG_MTLTFRCS_WAITING                    0x00200000
#define EMAC_DEBUG_MTLTFRCS_WRITING                    0x00300000
#define EMAC_DEBUG_MACTP                               0x00080000
#define EMAC_DEBUG_MACTFCS                             0x00060000
#define EMAC_DEBUG_MACTFCS_IDLE                        0x00000000
#define EMAC_DEBUG_MACTFCS_WAITING_STATUS              0x00020000
#define EMAC_DEBUG_MACTFCS_GENERATING_PAUSE            0x00040000
#define EMAC_DEBUG_MACTFCS_TRANSFERRING_FRAME          0x00060000
#define EMAC_DEBUG_MACTPES                             0x00010000
#define EMAC_DEBUG_MTLRFFLS                            0x00000300
#define EMAC_DEBUG_MTLRFFLS_EMPTY                      0x00000000
#define EMAC_DEBUG_MTLRFFLS_BELOW_THRESHOLD            0x00000100
#define EMAC_DEBUG_MTLRFFLS_ABOVE_THRESHOLD            0x00000200
#define EMAC_DEBUG_MTLRFFLS_FULL                       0x00000300
#define EMAC_DEBUG_MTLRFRCS                            0x00000060
#define EMAC_DEBUG_MTLRFRCS_IDLE                       0x00000000
#define EMAC_DEBUG_MTLRFRCS_READING_DATA               0x00000020
#define EMAC_DEBUG_MTLRFRCS_READING_STATUS             0x00000040
#define EMAC_DEBUG_MTLRFRCS_FLUSHING                   0x00000060
#define EMAC_DEBUG_MTLRFWCAS                           0x00000010
#define EMAC_DEBUG_MACRFFCS                            0x00000006
#define EMAC_DEBUG_MACRPES                             0x00000001

//PMT Control and Status register
#define EMAC_PMT_CSR_RWKFILTRST                        0x80000000
#define EMAC_PMT_CSR_RWKPTR                            0x1F000000
#define EMAC_PMT_CSR_GLBLUCAST                         0x00000200
#define EMAC_PMT_CSR_RWKPRCVD                          0x00000040
#define EMAC_PMT_CSR_MGKPRCVD                          0x00000020
#define EMAC_PMT_CSR_RWKPKTEN                          0x00000004
#define EMAC_PMT_CSR_MGKPKTEN                          0x00000002
#define EMAC_PMT_CSR_PWRDWN                            0x00000001

//LPI Control and Status register
#define EMAC_LPI_CSR_LPITXA                            0x00080000
#define EMAC_LPI_CSR_PLS                               0x00020000
#define EMAC_LPI_CSR_LPIEN                             0x00010000
#define EMAC_LPI_CSR_RLPIST                            0x00000200
#define EMAC_LPI_CSR_TLPIST                            0x00000100
#define EMAC_LPI_CSR_RLPIEX                            0x00000008
#define EMAC_LPI_CSR_RLPIEN                            0x00000004
#define EMAC_LPI_CSR_TLPIEX                            0x00000002
#define EMAC_LPI_CSR_TLPIEN                            0x00000001

//LPI Timers Control register
#define EMAC_LPITIMERSCONTROL_LPI_LS_TIMER             0x03FF0000
#define EMAC_LPITIMERSCONTROL_LPI_TW_TIMER             0x0000FFFF

//MAC Interrupt Status register
#define EMAC_INTS_LPIINTS                              0x00000400
#define EMAC_INTS_PMTINTS                              0x00000008

//MAC Interrupt Mask register
#define EMAC_INTMASK_LPIINTMASK                        0x00000400
#define EMAC_INTMASK_PMTINTMASK                        0x00000008

//MAC Address 0 High register
#define EMAC_ADDR0HIGH_ADDRESS_ENABLE0                 0x80000000
#define EMAC_ADDR0HIGH_MAC_ADDRESS0_HI                 0x0000FFFF

//MAC Address 0 Low register
#define EMAC_ADDR0LOW_MAC_ADDRESS0_LO                  0xFFFFFFFF

//MAC Address 1 High register
#define EMAC_ADDR1HIGH_ADDRESS_ENABLE1                 0x80000000
#define EMAC_ADDR1HIGH_SOURCE_ADDRESS1                 0x40000000
#define EMAC_ADDR1HIGH_MASK_BYTE_CONTROL1              0x3F000000
#define EMAC_ADDR1HIGH_MAC_ADDRESS1_HI                 0x0000FFFF

//MAC Address 1 Low register
#define EMAC_ADDR1LOW_MAC_ADDRESS1_LO                  0xFFFFFFFF

//MAC Address 2 High register
#define EMAC_ADDR2HIGH_ADDRESS_ENABLE2                 0x80000000
#define EMAC_ADDR2HIGH_SOURCE_ADDRESS2                 0x40000000
#define EMAC_ADDR2HIGH_MASK_BYTE_CONTROL2              0x3F000000
#define EMAC_ADDR2HIGH_MAC_ADDRESS2_HI                 0x0000FFFF

//MAC Address 2 Low register
#define EMAC_ADDR2LOW_MAC_ADDRESS2_LO                  0xFFFFFFFF

//MAC Address 3 High register
#define EMAC_ADDR3HIGH_ADDRESS_ENABLE3                 0x80000000
#define EMAC_ADDR3HIGH_SOURCE_ADDRESS3                 0x40000000
#define EMAC_ADDR3HIGH_MASK_BYTE_CONTROL3              0x3F000000
#define EMAC_ADDR3HIGH_MAC_ADDRESS3_HI                 0x0000FFFF

//MAC Address 3 Low register
#define EMAC_ADDR3LOW_MAC_ADDRESS3_LO                  0xFFFFFFFF

//MAC Address 4 High register
#define EMAC_ADDR4HIGH_ADDRESS_ENABLE4                 0x80000000
#define EMAC_ADDR4HIGH_SOURCE_ADDRESS4                 0x40000000
#define EMAC_ADDR4HIGH_MASK_BYTE_CONTROL4              0x3F000000
#define EMAC_ADDR4HIGH_MAC_ADDRESS4_HI                 0x0000FFFF

//MAC Address 4 Low register
#define EMAC_ADDR4LOW_MAC_ADDRESS4_LO                  0xFFFFFFFF

//MAC Address 5 High register
#define EMAC_ADDR5HIGH_ADDRESS_ENABLE5                 0x80000000
#define EMAC_ADDR5HIGH_SOURCE_ADDRESS5                 0x40000000
#define EMAC_ADDR5HIGH_MASK_BYTE_CONTROL5              0x3F000000
#define EMAC_ADDR5HIGH_MAC_ADDRESS5_HI                 0x0000FFFF

//MAC Address 5 Low register
#define EMAC_ADDR5LOW_MAC_ADDRESS5_LO                  0xFFFFFFFF

//MAC Address 6 High register
#define EMAC_ADDR6HIGH_ADDRESS_ENABLE6                 0x80000000
#define EMAC_ADDR6HIGH_SOURCE_ADDRESS6                 0x40000000
#define EMAC_ADDR6HIGH_MASK_BYTE_CONTROL6              0x3F000000
#define EMAC_ADDR6HIGH_MAC_ADDRESS6_HI                 0x0000FFFF

//MAC Address 6 Low register
#define EMAC_ADDR6LOW_MAC_ADDRESS6_LO                  0xFFFFFFFF

//MAC Address 7 High register
#define EMAC_ADDR7HIGH_ADDRESS_ENABLE7                 0x80000000
#define EMAC_ADDR7HIGH_SOURCE_ADDRESS7                 0x40000000
#define EMAC_ADDR7HIGH_MASK_BYTE_CONTROL7              0x3F000000
#define EMAC_ADDR7HIGH_MAC_ADDRESS7_HI                 0x0000FFFF

//MAC Address 7 Low register
#define EMAC_ADDR7LOW_MAC_ADDRESS7_LO                  0xFFFFFFFF

//MAC Status register
#define EMAC_STATUS_SMIDRXS                            0x00010000
#define EMAC_STATUS_JABBER_TIMEOUT                     0x00000010
#define EMAC_STATUS_LINK_SPEED                         0x00000006
#define EMAC_STATUS_LINK_SPEED_2_5_MHZ                 0x00000000
#define EMAC_STATUS_LINK_SPEED_25_MHZ                  0x00000002
#define EMAC_STATUS_LINK_SPEED_125_MHZ                 0x00000004
#define EMAC_STATUS_LINK_MODE                          0x00000001
#define EMAC_STATUS_LINK_MODE_HALF_DUPLEX              0x00000000
#define EMAC_STATUS_LINK_MODE_FULL_DUPLEX              0x00000001

//Watchdog Timeout Control register
#define EMAC_WDOGTO_PWDOGEN                            0x00010000
#define EMAC_WDOGTO_WDOGTO                             0x00003FFF

//Ethernet Clock Output Configuration register
#define EMAC_EX_CLKOUT_CONF_EMAC_CLK_OUT_H_DIV_NUM     0x000000F0
#define EMAC_EX_CLKOUT_CONF_EMAC_CLK_OUT_DIV_NUM       0x0000000F

//Ethernet Clock Configuration register
#define EMAC_EX_OSCCLK_CONF_EMAC_OSC_CLK_SEL           0x01000000
#define EMAC_EX_OSCCLK_CONF_EMAC_OSC_H_DIV_NUM_100M    0x00FC0000
#define EMAC_EX_OSCCLK_CONF_EMAC_OSC_DIV_NUM_100M      0x0003F000
#define EMAC_EX_OSCCLK_CONF_EMAC_OSC_H_DIV_NUM_10M     0x00000FC0
#define EMAC_EX_OSCCLK_CONF_EMAC_OSC_DIV_NUM_10M       0x0000003F

//Ethernet Clock Control register
#define EMAC_EX_CLK_CTRL_EMAC_MII_CLK_RX_EN            0x00000010
#define EMAC_EX_CLK_CTRL_EMAC_MII_CLK_TX_EN            0x00000008
#define EMAC_EX_CLK_CTRL_EMAC_INT_OSC_EN               0x00000002
#define EMAC_EX_CLK_CTRL_EMAC_EXT_OSC_EN               0x00000001

//PHY Interface Selection register
#define EMAC_EX_PHYINF_CONF_EMAC_PHY_INTF_SEL          0x0000E000
#define EMAC_EX_PHYINF_CONF_EMAC_PHY_INTF_SEL_MII      0x00000000
#define EMAC_EX_PHYINF_CONF_EMAC_PHY_INTF_SEL_RMII     0x00008000

//Ethernet RAM Power-Down register
#define EMAC_PD_SEL_EMAC_RAM_PD_EN                     0x00000003

//Transmit DMA descriptor flags
#define EMAC_TDES0_OWN                                 0x80000000
#define EMAC_TDES0_IC                                  0x40000000
#define EMAC_TDES0_LS                                  0x20000000
#define EMAC_TDES0_FS                                  0x10000000
#define EMAC_TDES0_DC                                  0x08000000
#define EMAC_TDES0_DP                                  0x04000000
#define EMAC_TDES0_TTSE                                0x02000000
#define EMAC_TDES0_CIC                                 0x00C00000
#define EMAC_TDES0_TER                                 0x00200000
#define EMAC_TDES0_TCH                                 0x00100000
#define EMAC_TDES0_TTSS                                0x00020000
#define EMAC_TDES0_IHE                                 0x00010000
#define EMAC_TDES0_ES                                  0x00008000
#define EMAC_TDES0_JT                                  0x00004000
#define EMAC_TDES0_FF                                  0x00002000
#define EMAC_TDES0_IPE                                 0x00001000
#define EMAC_TDES0_LCA                                 0x00000800
#define EMAC_TDES0_NC                                  0x00000400
#define EMAC_TDES0_LCO                                 0x00000200
#define EMAC_TDES0_EC                                  0x00000100
#define EMAC_TDES0_VF                                  0x00000080
#define EMAC_TDES0_CC                                  0x00000078
#define EMAC_TDES0_ED                                  0x00000004
#define EMAC_TDES0_UF                                  0x00000002
#define EMAC_TDES0_DB                                  0x00000001
#define EMAC_TDES1_TBS2                                0x1FFF0000
#define EMAC_TDES1_TBS1                                0x00001FFF
#define EMAC_TDES2_TBAP1                               0xFFFFFFFF
#define EMAC_TDES3_TBAP2                               0xFFFFFFFF
#define EMAC_TDES6_TTSL                                0xFFFFFFFF
#define EMAC_TDES7_TTSH                                0xFFFFFFFF

//Receive DMA descriptor flags
#define EMAC_RDES0_OWN                                 0x80000000
#define EMAC_RDES0_AFM                                 0x40000000
#define EMAC_RDES0_FL                                  0x3FFF0000
#define EMAC_RDES0_ES                                  0x00008000
#define EMAC_RDES0_DE                                  0x00004000
#define EMAC_RDES0_SAF                                 0x00002000
#define EMAC_RDES0_LE                                  0x00001000
#define EMAC_RDES0_OE                                  0x00000800
#define EMAC_RDES0_VLAN                                0x00000400
#define EMAC_RDES0_FS                                  0x00000200
#define EMAC_RDES0_LS                                  0x00000100
#define EMAC_RDES0_IPHCE                               0x00000080
#define EMAC_RDES0_LCO                                 0x00000040
#define EMAC_RDES0_FT                                  0x00000020
#define EMAC_RDES0_RWT                                 0x00000010
#define EMAC_RDES0_RE                                  0x00000008
#define EMAC_RDES0_DBE                                 0x00000004
#define EMAC_RDES0_CE                                  0x00000002
#define EMAC_RDES0_PCE                                 0x00000001
#define EMAC_RDES1_DIC                                 0x80000000
#define EMAC_RDES1_RBS2                                0x1FFF0000
#define EMAC_RDES1_RER                                 0x00008000
#define EMAC_RDES1_RCH                                 0x00004000
#define EMAC_RDES1_RBS1                                0x00001FFF
#define EMAC_RDES2_RBAP1                               0xFFFFFFFF
#define EMAC_RDES3_RBAP2                               0xFFFFFFFF
#define EMAC_RDES4_PV                                  0x00002000
#define EMAC_RDES4_PFT                                 0x00001000
#define EMAC_RDES4_PMT                                 0x00000F00
#define EMAC_RDES4_IPV6PR                              0x00000080
#define EMAC_RDES4_IPV4PR                              0x00000040
#define EMAC_RDES4_IPCB                                0x00000020
#define EMAC_RDES4_IPPE                                0x00000010
#define EMAC_RDES4_IPHE                                0x00000008
#define EMAC_RDES4_IPPT                                0x00000007
#define EMAC_RDES6_RTSL                                0xFFFFFFFF
#define EMAC_RDES7_RTSH                                0xFFFFFFFF

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
} Esp32EthTxDmaDesc;


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
} Esp32EthRxDmaDesc;


//ESP32 Ethernet MAC driver
extern const NicDriver esp32EthDriver;

//ESP32 Ethernet MAC related functions
error_t esp32EthInit(NetInterface *interface);
void esp32EthInitGpio(NetInterface *interface);
void esp32EthInitDmaDesc(NetInterface *interface);

void esp32EthTick(NetInterface *interface);

void esp32EthEnableIrq(NetInterface *interface);
void esp32EthDisableIrq(NetInterface *interface);
void esp32EthIrqHandler(void *arg);
void esp32EthEventHandler(NetInterface *interface);

error_t esp32EthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t esp32EthReceivePacket(NetInterface *interface);

error_t esp32EthUpdateMacAddrFilter(NetInterface *interface);
error_t esp32EthUpdateMacConfig(NetInterface *interface);

void esp32EthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data);

uint16_t esp32EthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
