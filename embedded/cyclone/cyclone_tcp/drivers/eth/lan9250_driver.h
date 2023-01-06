/**
 * @file lan9250_driver.h
 * @brief LAN9250 Ethernet controller
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

#ifndef _LAN9250_DRIVER_H
#define _LAN9250_DRIVER_H

//Dependencies
#include "core/nic.h"

//TX buffer size
#ifndef LAN9250_ETH_TX_BUFFER_SIZE
   #define LAN9250_ETH_TX_BUFFER_SIZE 1536
#elif (LAN9250_ETH_TX_BUFFER_SIZE != 1536)
   #error LAN9250_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//RX buffer size
#ifndef LAN9250_ETH_RX_BUFFER_SIZE
   #define LAN9250_ETH_RX_BUFFER_SIZE 1536
#elif (LAN9250_ETH_RX_BUFFER_SIZE != 1536)
   #error LAN9250_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//TX command size
#define LAN9250_TX_CMD_SIZE 8

//SPI instructions
#define LAN9250_SPI_INSTR_EQIO            0x38
#define LAN9250_SPI_INSTR_RSTQIO          0xFF
#define LAN9250_SPI_INSTR_READ            0x03
#define LAN9250_SPI_INSTR_FASTREAD        0x0B
#define LAN9250_SPI_INSTR_SDOR            0x3B
#define LAN9250_SPI_INSTR_SDIOR           0xBB
#define LAN9250_SPI_INSTR_SQOR            0x6B
#define LAN9250_SPI_INSTR_SQIOR           0xEB
#define LAN9250_SPI_INSTR_WRITE           0x02
#define LAN9250_SPI_INSTR_SDDW            0x32
#define LAN9250_SPI_INSTR_SDADW           0xB2
#define LAN9250_SPI_INSTR_SQDW            0x62
#define LAN9250_SPI_INSTR_SQADW           0xE2

//TX command 'A' format
#define LAN9250_TX_CMD_A_INT_ON_COMP      0x80000000
#define LAN9250_TX_CMD_A_BUFFER_ALIGN     0x03000000
#define LAN9250_TX_CMD_A_BUFFER_ALIGN_4B  0x00000000
#define LAN9250_TX_CMD_A_BUFFER_ALIGN_16B 0x01000000
#define LAN9250_TX_CMD_A_BUFFER_ALIGN_32B 0x02000000
#define LAN9250_TX_CMD_A_START_OFFSET     0x001F0000
#define LAN9250_TX_CMD_A_START_OFFSET_0B  0x00000000
#define LAN9250_TX_CMD_A_FIRST_SEG        0x00002000
#define LAN9250_TX_CMD_A_LAST_SEG         0x00001000
#define LAN9250_TX_CMD_A_BUFFER_SIZE      0x000007FF

//TX command 'B' format
#define LAN9250_TX_CMD_B_PACKET_TAG       0xFFFF0000
#define LAN9250_TX_CMD_B_TX_CHECKSUM_EN   0x00004000
#define LAN9250_TX_CMD_B_ADD_CRC_DIS      0x00002000
#define LAN9250_TX_CMD_B_PADDING_DIS      0x00001000
#define LAN9250_TX_CMD_B_PACKET_LEN       0x000007FF

//TX status format
#define LAN9250_TX_STS_PACKET_TAG         0xFFFF0000
#define LAN9250_TX_STS_ERROR_STATUS       0x00008000
#define LAN9250_TX_STS_LOSS_OF_CARRIER    0x00000800
#define LAN9250_TX_STS_NO_CARRIER         0x00000400
#define LAN9250_TX_STS_LATE_COLLISION     0x00000200
#define LAN9250_TX_STS_EXCESS_COLLISIONS  0x00000100
#define LAN9250_TX_STS_COLLISION_COUNT    0x00000078
#define LAN9250_TX_STS_EXCESS_DEFERRAL    0x00000004
#define LAN9250_TX_STS_DEFERRED           0x00000001

//RX status format
#define LAN9250_RX_STS_PACKET_FILTER      0x80000000
#define LAN9250_RX_STS_FILTERING_FAIL     0x40000000
#define LAN9250_RX_STS_PACKET_LEN         0x3FFF0000
#define LAN9250_RX_STS_ERROR_STATUS       0x00008000
#define LAN9250_RX_STS_BROADCAST_FRAME    0x00002000
#define LAN9250_RX_STS_LENGTH_ERROR       0x00001000
#define LAN9250_RX_STS_RUNT_FRAME         0x00000800
#define LAN9250_RX_STS_MULTICAST_FRAME    0x00000400
#define LAN9250_RX_STS_FRAME_TOO_LONG     0x00000080
#define LAN9250_RX_STS_COLLISION_SEEN     0x00000040
#define LAN9250_RX_STS_FRAME_TYPE         0x00000020
#define LAN9250_RX_STS_RECEIVE_WDT        0x00000010
#define LAN9250_RX_STS_MII_ERROR          0x00000008
#define LAN9250_RX_STS_DRIBBLING_BIT      0x00000004
#define LAN9250_RX_STS_CRC_ERROR          0x00000002

//LAN9250 System registers
#define LAN9250_RX_DATA_FIFO                                   0x0000
#define LAN9250_TX_DATA_FIFO                                   0x0020
#define LAN9250_RX_STATUS_FIFO                                 0x0040
#define LAN9250_RX_STATUS_FIFO_PEEK                            0x0044
#define LAN9250_TX_STATUS_FIFO                                 0x0048
#define LAN9250_TX_STATUS_FIFO_PEEK                            0x004C
#define LAN9250_ID_REV                                         0x0050
#define LAN9250_IRQ_CFG                                        0x0054
#define LAN9250_INT_STS                                        0x0058
#define LAN9250_INT_EN                                         0x005C
#define LAN9250_BYTE_TEST                                      0x0064
#define LAN9250_FIFO_INT                                       0x0068
#define LAN9250_RX_CFG                                         0x006C
#define LAN9250_TX_CFG                                         0x0070
#define LAN9250_HW_CFG                                         0x0074
#define LAN9250_RX_DP_CTRL                                     0x0078
#define LAN9250_RX_FIFO_INF                                    0x007C
#define LAN9250_TX_FIFO_INF                                    0x0080
#define LAN9250_PMT_CTRL                                       0x0084
#define LAN9250_GPT_CFG                                        0x008C
#define LAN9250_GPT_CNT                                        0x0090
#define LAN9250_FREE_RUN                                       0x009C
#define LAN9250_RX_DROP                                        0x00A0
#define LAN9250_MAC_CSR_CMD                                    0x00A4
#define LAN9250_MAC_CSR_DATA                                   0x00A8
#define LAN9250_AFC_CFG                                        0x00AC
#define LAN9250_HMAC_RX_LPI_TRANSITION                         0x00B0
#define LAN9250_HMAC_RX_LPI_TIME                               0x00B4
#define LAN9250_HMAC_TX_LPI_TRANSITION                         0x00B8
#define LAN9250_HMAC_TX_LPI_TIME                               0x00BC
#define LAN9250_1588_CMD_CTL                                   0x0100
#define LAN9250_1588_GENERAL_CONFIG                            0x0104
#define LAN9250_1588_INT_STS                                   0x0108
#define LAN9250_1588_INT_EN                                    0x010C
#define LAN9250_1588_CLOCK_SEC                                 0x0110
#define LAN9250_1588_CLOCK_NS                                  0x0114
#define LAN9250_1588_CLOCK_SUBNS                               0x0118
#define LAN9250_1588_CLOCK_RATE_ADJ                            0x011C
#define LAN9250_1588_CLOCK_TEMP_RATE_ADJ                       0x0120
#define LAN9250_1588_CLOCK_TEMP_RATE_DURATION                  0x0124
#define LAN9250_1588_CLOCK_STEP_ADJ                            0x0128
#define LAN9250_1588_CLOCK_TARGET_SEC_A                        0x012C
#define LAN9250_1588_CLOCK_TARGET_NS_A                         0x0130
#define LAN9250_1588_CLOCK_TARGET_RELOAD_SEC_A                 0x0134
#define LAN9250_1588_CLOCK_TARGET_RELOAD_NS_A                  0x0138
#define LAN9250_1588_CLOCK_TARGET_SEC_B                        0x013C
#define LAN9250_1588_CLOCK_TARGET_NS_B                         0x0140
#define LAN9250_1588_CLOCK_TARGET_RELOAD_SEC_B                 0x0144
#define LAN9250_1588_CLOCK_TARGET_RELOAD_NS_B                  0x0148
#define LAN9250_1588_USER_MAC_HI                               0x014C
#define LAN9250_1588_USER_MAC_LO                               0x0150
#define LAN9250_1588_BANK_PORT_GPIO_SEL                        0x0154
#define LAN9250_1588_LATENCY                                   0x0158
#define LAN9250_1588_RX_PARSE_CONFIG                           0x0158
#define LAN9250_1588_TX_PARSE_CONFIG                           0x0158
#define LAN9250_1588_ASYM_PEERDLY                              0x015C
#define LAN9250_1588_RX_TIMESTAMP_CONFIG                       0x015C
#define LAN9250_1588_TX_TIMESTAMP_CONFIG                       0x015C
#define LAN9250_1588_GPIO_CAP_CONFIG                           0x015C
#define LAN9250_1588_CAP_INFO                                  0x0160
#define LAN9250_1588_RX_TS_INSERT_CONFIG                       0x0160
#define LAN9250_1588_TX_MOD                                    0x0164
#define LAN9250_1588_RX_FILTER_CONFIG                          0x0168
#define LAN9250_1588_TX_MOD2                                   0x0168
#define LAN9250_1588_RX_INGRESS_SEC                            0x016C
#define LAN9250_1588_TX_EGRESS_SEC                             0x016C
#define LAN9250_1588_GPIO_RE_CLOCK_SEC_CAP                     0x016C
#define LAN9250_1588_RX_INGRESS_NS                             0x0170
#define LAN9250_1588_TX_EGRESS_NS                              0x0170
#define LAN9250_1588_GPIO_RE_CLOCK_NS_CAP                      0x0170
#define LAN9250_1588_RX_MSG_HEADER                             0x0174
#define LAN9250_1588_TX_MSG_HEADER                             0x0174
#define LAN9250_1588_RX_PDREQ_SEC                              0x0178
#define LAN9250_1588_TX_DREQ_SEC                               0x0178
#define LAN9250_1588_GPIO_FE_CLOCK_SEC_CAP                     0x0178
#define LAN9250_1588_RX_PDREQ_NS                               0x017C
#define LAN9250_1588_TX_DREQ_NS                                0x017C
#define LAN9250_1588_GPIO_FE_CLOCK_NS_CAP                      0x017C
#define LAN9250_1588_RX_PDREQ_CF_HI                            0x0180
#define LAN9250_1588_TX_ONE_STEP_SYNC_SEC                      0x0180
#define LAN9250_1588_RX_PDREQ_CF_LOW                           0x0184
#define LAN9250_1588_RX_CHKSUM_DROPPED_CNT                     0x0188
#define LAN9250_1588_RX_FILTERED_CNT                           0x018C
#define LAN9250_E2P_CMD                                        0x01B4
#define LAN9250_E2P_DATA                                       0x01B8
#define LAN9250_LED_CFG                                        0x01BC
#define LAN9250_GPIO_CFG                                       0x01E0
#define LAN9250_GPIO_DATA_DIR                                  0x01E4
#define LAN9250_GPIO_INT_STS_EN                                0x01E8
#define LAN9250_RESET_CTL                                      0x01F8

//LAN9250 Host MAC registers
#define LAN9250_HMAC_CR                                        0x01
#define LAN9250_HMAC_ADDRH                                     0x02
#define LAN9250_HMAC_ADDRL                                     0x03
#define LAN9250_HMAC_HASHH                                     0x04
#define LAN9250_HMAC_HASHL                                     0x05
#define LAN9250_HMAC_MII_ACC                                   0x06
#define LAN9250_HMAC_MII_DATA                                  0x07
#define LAN9250_HMAC_FLOW                                      0x08
#define LAN9250_HMAC_VLAN1                                     0x09
#define LAN9250_HMAC_VLAN2                                     0x0A
#define LAN9250_HMAC_WUFF                                      0x0B
#define LAN9250_HMAC_WUCSR                                     0x0C
#define LAN9250_HMAC_COE_CR                                    0x0D
#define LAN9250_HMAC_EEE_TW_TX_SYS                             0x0E
#define LAN9250_HMAC_EEE_TX_LPI_REQ_DELAY                      0x0F

//LAN9250 PHY registers
#define LAN9250_PHY_BASIC_CONTROL                              0x00
#define LAN9250_PHY_BASIC_STATUS                               0x01
#define LAN9250_PHY_ID_MSB                                     0x02
#define LAN9250_PHY_ID_LSB                                     0x03
#define LAN9250_PHY_AN_ADV                                     0x04
#define LAN9250_PHY_AN_LP_BASE_ABILITY                         0x05
#define LAN9250_PHY_AN_EXP                                     0x06
#define LAN9250_PHY_AN_NP_TX                                   0x07
#define LAN9250_PHY_AN_NP_RX                                   0x08
#define LAN9250_PHY_MMD_ACCESS                                 0x0D
#define LAN9250_PHY_MMD_ADDR_DATA                              0x0E
#define LAN9250_PHY_EDPD_CFG                                   0x10
#define LAN9250_PHY_MODE_CONTROL_STATUS                        0x11
#define LAN9250_PHY_SPECIAL_MODES                              0x12
#define LAN9250_PHY_TDR_PAT_DELAY                              0x18
#define LAN9250_PHY_TDR_CONTROL_STAT                           0x19
#define LAN9250_PHY_SYMBOL_ERR_COUNTER                         0x1A
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND                   0x1B
#define LAN9250_PHY_CABLE_LEN                                  0x1C
#define LAN9250_PHY_INTERRUPT_SOURCE                           0x1D
#define LAN9250_PHY_INTERRUPT_MASK                             0x1E
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS                     0x1F

//LAN9250 MMD registers
#define LAN9250_PHY_PCS_CTL1                                   0x03, 0x00
#define LAN9250_PHY_PCS_STAT1                                  0x03, 0x01
#define LAN9250_PHY_PCS_MMD_PRESENT1                           0x03, 0x05
#define LAN9250_PHY_PCS_MMD_PRESENT2                           0x03, 0x06
#define LAN9250_PHY_EEE_CAP                                    0x03, 0x14
#define LAN9250_PHY_EEE_WAKE_ERR                               0x03, 0x16
#define LAN9250_PHY_AN_MMD_PRESENT1                            0x07, 0x05
#define LAN9250_PHY_AN_MMD_PRESENT2                            0x07, 0x06
#define LAN9250_PHY_EEE_ADV                                    0x07, 0x3C
#define LAN9250_PHY_EEE_LP_ADV                                 0x07, 0x3D
#define LAN9250_PHY_VEND_SPEC_MMD1_DEVID1                      0x1E, 0x02
#define LAN9250_PHY_VEND_SPEC_MMD1_DEVID2                      0x1E, 0x03
#define LAN9250_PHY_VEND_SPEC_MMD1_PRESENT1                    0x1E, 0x05
#define LAN9250_PHY_VEND_SPEC_MMD1_PRESENT2                    0x1E, 0x06
#define LAN9250_PHY_VEND_SPEC_MMD1_STAT                        0x1E, 0x08
#define LAN9250_PHY_VEND_SPEC_MMD1_PKG_ID1                     0x1E, 0x0E
#define LAN9250_PHY_VEND_SPEC_MMD1_PKG_ID2                     0x1E, 0x0F

//Chip ID and Revision register
#define LAN9250_ID_REV_CHIP_ID                                 0xFFFF0000
#define LAN9250_ID_REV_CHIP_ID_DEFAULT                         0x92500000
#define LAN9250_ID_REV_CHIP_REV                                0x0000FFFF

//Interrupt Configuration register
#define LAN9250_IRQ_CFG_INT_DEAS                               0xFF000000
#define LAN9250_IRQ_CFG_INT_DEAS_10US                          0x01000000
#define LAN9250_IRQ_CFG_INT_DEAS_100US                         0x0A000000
#define LAN9250_IRQ_CFG_INT_DEAS_1MS                           0x64000000
#define LAN9250_IRQ_CFG_INT_DEAS_CLR                           0x00004000
#define LAN9250_IRQ_CFG_INT_DEAS_STS                           0x00002000
#define LAN9250_IRQ_CFG_IRQ_INT                                0x00001000
#define LAN9250_IRQ_CFG_IRQ_EN                                 0x00000100
#define LAN9250_IRQ_CFG_IRQ_POL                                0x00000010
#define LAN9250_IRQ_CFG_IRQ_POL_LOW                            0x00000000
#define LAN9250_IRQ_CFG_IRQ_POL_HIGH                           0x00000010
#define LAN9250_IRQ_CFG_IRQ_CLK_SELECT                         0x00000002
#define LAN9250_IRQ_CFG_IRQ_TYPE                               0x00000001
#define LAN9250_IRQ_CFG_IRQ_TYPE_OD                            0x00000000
#define LAN9250_IRQ_CFG_IRQ_TYPE_PP                            0x00000001

//Interrupt Status register
#define LAN9250_INT_STS_SW_INT                                 0x80000000
#define LAN9250_INT_STS_READY                                  0x40000000
#define LAN9250_INT_STS_1588_EVNT                              0x20000000
#define LAN9250_INT_STS_PHY_INT                                0x04000000
#define LAN9250_INT_STS_TXSTOP_INT                             0x02000000
#define LAN9250_INT_STS_RXSTOP_INT                             0x01000000
#define LAN9250_INT_STS_RXDFH_INT                              0x00800000
#define LAN9250_INT_STS_TX_IOC                                 0x00200000
#define LAN9250_INT_STS_RXD_INT                                0x00100000
#define LAN9250_INT_STS_GPT_INT                                0x00080000
#define LAN9250_INT_STS_PME_INT                                0x00020000
#define LAN9250_INT_STS_TXSO                                   0x00010000
#define LAN9250_INT_STS_RWT                                    0x00008000
#define LAN9250_INT_STS_RXE                                    0x00004000
#define LAN9250_INT_STS_TXE                                    0x00002000
#define LAN9250_INT_STS_GPIO                                   0x00001000
#define LAN9250_INT_STS_TDFO                                   0x00000400
#define LAN9250_INT_STS_TDFA                                   0x00000200
#define LAN9250_INT_STS_TSFF                                   0x00000100
#define LAN9250_INT_STS_TSFL                                   0x00000080
#define LAN9250_INT_STS_RXDF_INT                               0x00000040
#define LAN9250_INT_STS_RSFF                                   0x00000010
#define LAN9250_INT_STS_RSFL                                   0x00000008

//Interrupt Enable register
#define LAN9250_INT_EN_SW_INT_EN                               0x80000000
#define LAN9250_INT_EN_READY_EN                                0x40000000
#define LAN9250_INT_EN_1588_EVNT_EN                            0x20000000
#define LAN9250_INT_EN_PHY_INT_EN                              0x04000000
#define LAN9250_INT_EN_TXSTOP_INT_EN                           0x02000000
#define LAN9250_INT_EN_RXSTOP_INT_EN                           0x01000000
#define LAN9250_INT_EN_RXDFH_INT_EN                            0x00800000
#define LAN9250_INT_EN_TIOC_INT_EN                             0x00200000
#define LAN9250_INT_EN_RXD_INT_EN                              0x00100000
#define LAN9250_INT_EN_GPT_INT_EN                              0x00080000
#define LAN9250_INT_EN_PME_INT_EN                              0x00020000
#define LAN9250_INT_EN_TXSO_EN                                 0x00010000
#define LAN9250_INT_EN_RWT_INT_EN                              0x00008000
#define LAN9250_INT_EN_RXE_INT_EN                              0x00004000
#define LAN9250_INT_EN_TXE_INT_EN                              0x00002000
#define LAN9250_INT_EN_GPIO_EN                                 0x00001000
#define LAN9250_INT_EN_TDFO_EN                                 0x00000400
#define LAN9250_INT_EN_TDFA_EN                                 0x00000200
#define LAN9250_INT_EN_TSFF_EN                                 0x00000100
#define LAN9250_INT_EN_TSFL_EN                                 0x00000080
#define LAN9250_INT_EN_RXDF_INT_EN                             0x00000040
#define LAN9250_INT_EN_RSFF_EN                                 0x00000010
#define LAN9250_INT_EN_RSFL_EN                                 0x00000008

//Byte Order Test register
#define LAN9250_BYTE_TEST_DEFAULT                              0x87654321

//FIFO Level Interrupt register
#define LAN9250_FIFO_INT_TX_DATA_AVAILABLE_LEVEL               0xFF000000
#define LAN9250_FIFO_INT_TX_STATUS_LEVEL                       0x00FF0000
#define LAN9250_FIFO_INT_RX_STATUS_LEVEL                       0x000000FF

//Receive Configuration register
#define LAN9250_RX_CFG_RX_EA                                   0xC0000000
#define LAN9250_RX_CFG_RX_EA_4_BYTES                           0x00000000
#define LAN9250_RX_CFG_RX_EA_16_BYTES                          0x40000000
#define LAN9250_RX_CFG_RX_EA_32_BYTES                          0x80000000
#define LAN9250_RX_CFG_RX_DMA_CNT                              0x0FFF0000
#define LAN9250_RX_CFG_RX_DUMP                                 0x00008000
#define LAN9250_RX_CFG_RXDOFF                                  0x00001F00

//Transmit Configuration register
#define LAN9250_TX_CFG_TXS_DUMP                                0x00008000
#define LAN9250_TX_CFG_TXD_DUMP                                0x00004000
#define LAN9250_TX_CFG_TXSAO                                   0x00000004
#define LAN9250_TX_CFG_TX_ON                                   0x00000002
#define LAN9250_TX_CFG_STOP_TX                                 0x00000001

//Hardware Configuration register
#define LAN9250_HW_CFG_DEVICE_READY                            0x08000000
#define LAN9250_HW_CFG_AMDIX_EN_STRAP_STATE                    0x02000000
#define LAN9250_HW_CFG_MBO                                     0x00100000
#define LAN9250_HW_CFG_TX_FIF_SZ                               0x000F0000
#define LAN9250_HW_CFG_TX_FIF_SZ_2KB                           0x00020000
#define LAN9250_HW_CFG_TX_FIF_SZ_3KB                           0x00030000
#define LAN9250_HW_CFG_TX_FIF_SZ_4KB                           0x00040000
#define LAN9250_HW_CFG_TX_FIF_SZ_5KB                           0x00050000
#define LAN9250_HW_CFG_TX_FIF_SZ_6KB                           0x00060000
#define LAN9250_HW_CFG_TX_FIF_SZ_7KB                           0x00070000
#define LAN9250_HW_CFG_TX_FIF_SZ_8KB                           0x00080000
#define LAN9250_HW_CFG_TX_FIF_SZ_9KB                           0x00090000
#define LAN9250_HW_CFG_TX_FIF_SZ_10KB                          0x000A0000
#define LAN9250_HW_CFG_TX_FIF_SZ_11KB                          0x000B0000
#define LAN9250_HW_CFG_TX_FIF_SZ_12KB                          0x000C0000
#define LAN9250_HW_CFG_TX_FIF_SZ_13KB                          0x000D0000
#define LAN9250_HW_CFG_TX_FIF_SZ_14KB                          0x000E0000

//Receive Datapath Control register
#define LAN9250_RX_DP_CTRL_RX_FFWD                             0x80000000

//RX FIFO Information register
#define LAN9250_RX_FIFO_INF_RXSUSED                            0x00FF0000
#define LAN9250_RX_FIFO_INF_RXDUSED                            0x0000FFFF

//TX FIFO Information register
#define LAN9250_TX_FIFO_INF_TXSUSED                            0x00FF0000
#define LAN9250_TX_FIFO_INF_TXFREE                             0x0000FFFF

//Power Management Control register
#define LAN9250_PMT_CTRL_PM_MODE                               0xE0000000
#define LAN9250_PMT_CTRL_PM_SLEEP_EN                           0x10000000
#define LAN9250_PMT_CTRL_PM_WAKE                               0x08000000
#define LAN9250_PMT_CTRL_LED_DIS                               0x04000000
#define LAN9250_PMT_CTRL_1588_DIS                              0x02000000
#define LAN9250_PMT_CTRL_1588_TSU_DIS                          0x00400000
#define LAN9250_PMT_CTRL_HMAC_DIS                              0x00080000
#define LAN9250_PMT_CTRL_HMAC_SYS_ONLY_DIS                     0x00040000
#define LAN9250_PMT_CTRL_ED_STS                                0x00010000
#define LAN9250_PMT_CTRL_ED_EN                                 0x00004000
#define LAN9250_PMT_CTRL_WOL_EN                                0x00000200
#define LAN9250_PMT_CTRL_PME_TYPE                              0x00000040
#define LAN9250_PMT_CTRL_WOL_STS                               0x00000020
#define LAN9250_PMT_CTRL_PME_IND                               0x00000008
#define LAN9250_PMT_CTRL_PME_POL                               0x00000004
#define LAN9250_PMT_CTRL_PME_EN                                0x00000002
#define LAN9250_PMT_CTRL_READY                                 0x00000001

//General Purpose Timer Configuration register
#define LAN9250_GPT_CFG_TIMER_EN                               0x20000000
#define LAN9250_GPT_CFG_GPT_LOAD                               0x0000FFFF

//General Purpose Timer Count register
#define LAN9250_GPT_CNT_GPT_CNT                                0x0000FFFF

//Free Running 25MHz Counter register
#define LAN9250_FREE_RUN_FR_CNT                                0xFFFFFFFF

//Host MAC RX Dropped Frames Counter register
#define LAN9250_RX_DROP_RX_DFC                                 0xFFFFFFFF

//Host MAC CSR Interface Command register
#define LAN9250_MAC_CSR_CMD_BUSY                               0x80000000
#define LAN9250_MAC_CSR_CMD_WRITE                              0x00000000
#define LAN9250_MAC_CSR_CMD_READ                               0x40000000
#define LAN9250_MAC_CSR_CMD_ADDR                               0x000000FF

//Host MAC Automatic Flow Control Configuration register
#define LAN9250_AFC_CFG_AFC_HI                                 0x00FF0000
#define LAN9250_AFC_CFG_AFC_LO                                 0x0000FF00
#define LAN9250_AFC_CFG_BACK_DUR                               0x000000F0
#define LAN9250_AFC_CFG_FCMULT                                 0x00000008
#define LAN9250_AFC_CFG_FCBRD                                  0x00000004
#define LAN9250_AFC_CFG_FCADD                                  0x00000002
#define LAN9250_AFC_CFG_FCANY                                  0x00000001

//EEPROM Command register
#define LAN9250_E2P_CMD_EPC_BUSY                               0x80000000
#define LAN9250_E2P_CMD_EPC_COMMAND                            0x70000000
#define LAN9250_E2P_CMD_EPC_COMMAND_READ                       0x00000000
#define LAN9250_E2P_CMD_EPC_COMMAND_WRITE                      0x30000000
#define LAN9250_E2P_CMD_EPC_COMMAND_RELOAD                     0x70000000
#define LAN9250_E2P_CMD_LOADER_OVERFLOW                        0x00040000
#define LAN9250_E2P_CMD_EPC_TIMEOUT                            0x00020000
#define LAN9250_E2P_CMD_CFG_LOADED                             0x00010000
#define LAN9250_E2P_CMD_EPC_ADDR                               0x0000FFFF

//EEPROM Data register
#define LAN9250_E2P_DATA_EEPROM_DATA                           0x000000FF

//LED Configuration register
#define LAN9250_LED_CFG_LED_FUN                                0x00000700
#define LAN9250_LED_CFG_LED_FUN_0                              0x00000000
#define LAN9250_LED_CFG_LED_FUN_1                              0x00000100
#define LAN9250_LED_CFG_LED_FUN_2                              0x00000200
#define LAN9250_LED_CFG_LED_FUN_3                              0x00000300
#define LAN9250_LED_CFG_LED_FUN_4                              0x00000400
#define LAN9250_LED_CFG_LED_EN                                 0x00000007
#define LAN9250_LED_CFG_LED_EN_0                               0x00000001
#define LAN9250_LED_CFG_LED_EN_1                               0x00000002
#define LAN9250_LED_CFG_LED_EN_2                               0x00000004

//General Purpose I/O Configuration register
#define LAN9250_GPIO_CFG_GPIO_CH_SEL                           0x07000000
#define LAN9250_GPIO_CFG_GPIO_CH_SEL_0                         0x01000000
#define LAN9250_GPIO_CFG_GPIO_CH_SEL_1                         0x02000000
#define LAN9250_GPIO_CFG_GPIO_CH_SEL_2                         0x04000000
#define LAN9250_GPIO_CFG_GPIO_POL                              0x00070000
#define LAN9250_GPIO_CFG_GPIO_POL_0                            0x00010000
#define LAN9250_GPIO_CFG_GPIO_POL_1                            0x00020000
#define LAN9250_GPIO_CFG_GPIO_POL_2                            0x00040000
#define LAN9250_GPIO_CFG_1588_GPIO_OE                          0x00000700
#define LAN9250_GPIO_CFG_1588_GPIO_OE_0                        0x00000100
#define LAN9250_GPIO_CFG_1588_GPIO_OE_1                        0x00000200
#define LAN9250_GPIO_CFG_1588_GPIO_OE_2                        0x00000400
#define LAN9250_GPIO_CFG_GPIOBUF                               0x00000007
#define LAN9250_GPIO_CFG_GPIOBUF_0                             0x00000001
#define LAN9250_GPIO_CFG_GPIOBUF_1                             0x00000002
#define LAN9250_GPIO_CFG_GPIOBUF_2                             0x00000004

//General Purpose I/O Data & Direction register
#define LAN9250_GPIO_DATA_DIR_GPIODIR                          0x00070000
#define LAN9250_GPIO_DATA_DIR_GPIODIR_0                        0x00010000
#define LAN9250_GPIO_DATA_DIR_GPIODIR_1                        0x00020000
#define LAN9250_GPIO_DATA_DIR_GPIODIR_2                        0x00040000
#define LAN9250_GPIO_DATA_DIR_GPIOD                            0x00000007
#define LAN9250_GPIO_DATA_DIR_GPIOD_0                          0x00000001
#define LAN9250_GPIO_DATA_DIR_GPIOD_1                          0x00000002
#define LAN9250_GPIO_DATA_DIR_GPIOD_2                          0x00000004

//General Purpose I/O Interrupt Status and Enable register
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_EN                    0x00070000
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_EN_0                  0x00010000
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_EN_1                  0x00020000
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_EN_2                  0x00040000
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT                       0x00000007
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_0                     0x00000001
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_1                     0x00000002
#define LAN9250_GPIO_INT_STS_EN_GPIO_INT_2                     0x00000004

//Reset Control register
#define LAN9250_RESET_CTL_HMAC_RST                             0x00000020
#define LAN9250_RESET_CTL_PHY_RST                              0x00000002
#define LAN9250_RESET_CTL_DIGITAL_RST                          0x00000001

//Host MAC Control register
#define LAN9250_HMAC_CR_RXALL                                  0x80000000
#define LAN9250_HMAC_CR_HMAC_EEE_ENABLE                        0x02000000
#define LAN9250_HMAC_CR_RCVOWN                                 0x00800000
#define LAN9250_HMAC_CR_LOOPBK                                 0x00200000
#define LAN9250_HMAC_CR_FDPX                                   0x00100000
#define LAN9250_HMAC_CR_MCPAS                                  0x00080000
#define LAN9250_HMAC_CR_PRMS                                   0x00040000
#define LAN9250_HMAC_CR_INVFILT                                0x00020000
#define LAN9250_HMAC_CR_PASSBAD                                0x00010000
#define LAN9250_HMAC_CR_HO                                     0x00008000
#define LAN9250_HMAC_CR_HPFILT                                 0x00002000
#define LAN9250_HMAC_CR_BCAST                                  0x00000800
#define LAN9250_HMAC_CR_DISRTY                                 0x00000400
#define LAN9250_HMAC_CR_PADSTR                                 0x00000100
#define LAN9250_HMAC_CR_BOLMT                                  0x000000C0
#define LAN9250_HMAC_CR_BOLMT_10_BITS                          0x00000000
#define LAN9250_HMAC_CR_BOLMT_8_BITS                           0x00000040
#define LAN9250_HMAC_CR_BOLMT_4_BITS                           0x00000080
#define LAN9250_HMAC_CR_BOLMT_1_BIT                            0x000000C0
#define LAN9250_HMAC_CR_DFCHK                                  0x00000020
#define LAN9250_HMAC_CR_TXEN                                   0x00000008
#define LAN9250_HMAC_CR_RXEN                                   0x00000004

//Host MAC Address High register
#define LAN9250_HMAC_ADDRH_PHY_ADR_47_32                       0x0000FFFF

//Host MAC Address Low register
#define LAN9250_HMAC_ADDRL_PHY_ADR_31_0                        0xFFFFFFFF

//Host MAC MII Access register
#define LAN9250_HMAC_MII_ACC_PHY_ADDR                          0x0000F800
#define LAN9250_HMAC_MII_ACC_PHY_ADDR_DEFAULT                  0x00000800
#define LAN9250_HMAC_MII_ACC_MIIRINDA                          0x000007C0
#define LAN9250_HMAC_MII_ACC_MIIW_R                            0x00000002
#define LAN9250_HMAC_MII_ACC_MIIBZY                            0x00000001

//Host MAC MII Data register
#define LAN9250_HMAC_MII_DATA_MII_DATA                         0x0000FFFF

//Host MAC Flow Control register
#define LAN9250_HMAC_FLOW_FCPT                                 0xFFFF0000
#define LAN9250_HMAC_FLOW_FCPASS                               0x00000004
#define LAN9250_HMAC_FLOW_FCEN                                 0x00000002
#define LAN9250_HMAC_FLOW_FCBSY                                0x00000001

//Host MAC VLAN1 Tag register
#define LAN9250_HMAC_VLAN1_VTI1                                0x0000FFFF

//Host MAC VLAN2 Tag register
#define LAN9250_HMAC_VLAN2_VTI2                                0x0000FFFF

//Host MAC Wake-up Frame Filter register
#define LAN9250_HMAC_WUFF_WFF                                  0xFFFFFFFF

//Host MAC Wake-up Control and Status register
#define LAN9250_HMAC_WUCSR_WFF_PTR_RST                         0x80000000
#define LAN9250_HMAC_WUCSR_GUE                                 0x00000200
#define LAN9250_HMAC_WUCSR_WOL_WAIT_SLEEP                      0x00000100
#define LAN9250_HMAC_WUCSR_PFDA_FR                             0x00000080
#define LAN9250_HMAC_WUCSR_WUFR                                0x00000040
#define LAN9250_HMAC_WUCSR_MPR                                 0x00000020
#define LAN9250_HMAC_WUCSR_BCAST_FR                            0x00000010
#define LAN9250_HMAC_WUCSR_PFDA_EN                             0x00000008
#define LAN9250_HMAC_WUCSR_WUEN                                0x00000004
#define LAN9250_HMAC_WUCSR_MPEN                                0x00000002
#define LAN9250_HMAC_WUCSR_BCST_EN                             0x00000001

//Host MAC Checksum Offload Engine Control register
#define LAN9250_HMAC_COE_CR_TX_COE_EN                          0x00010000
#define LAN9250_HMAC_COE_CR_RX_COE_MODE                        0x00000002
#define LAN9250_HMAC_COE_CR_RX_COE_EN                          0x00000001

//Host MAC EEE Time Wait TX System register
#define LAN9250_HMAC_EEE_TW_TX_SYS_TX_DELAY                    0x00FFFFFF

//PHY Basic Control register
#define LAN9250_PHY_BASIC_CONTROL_PHY_SRST                     0x8000
#define LAN9250_PHY_BASIC_CONTROL_PHY_LOOPBACK                 0x4000
#define LAN9250_PHY_BASIC_CONTROL_PHY_SPEED_SEL_LSB            0x2000
#define LAN9250_PHY_BASIC_CONTROL_PHY_AN                       0x1000
#define LAN9250_PHY_BASIC_CONTROL_PHY_PWR_DWN                  0x0800
#define LAN9250_PHY_BASIC_CONTROL_PHY_RST_AN                   0x0200
#define LAN9250_PHY_BASIC_CONTROL_PHY_DUPLEX                   0x0100
#define LAN9250_PHY_BASIC_CONTROL_PHY_COL_TEST                 0x0080

//PHY Basic Status register
#define LAN9250_PHY_BASIC_STATUS_100BT4                        0x8000
#define LAN9250_PHY_BASIC_STATUS_100BTX_FD                     0x4000
#define LAN9250_PHY_BASIC_STATUS_100BTX_HD                     0x2000
#define LAN9250_PHY_BASIC_STATUS_10BT_FD                       0x1000
#define LAN9250_PHY_BASIC_STATUS_10BT_HD                       0x0800
#define LAN9250_PHY_BASIC_STATUS_100BT2_FD                     0x0400
#define LAN9250_PHY_BASIC_STATUS_100BT2_HD                     0x0200
#define LAN9250_PHY_BASIC_STATUS_EXTENDED_STATUS               0x0100
#define LAN9250_PHY_BASIC_STATUS_UNIDIRECTIONAL_ABLE           0x0080
#define LAN9250_PHY_BASIC_STATUS_MF_PREAMBLE_SUPPR             0x0040
#define LAN9250_PHY_BASIC_STATUS_AN_COMPLETE                   0x0020
#define LAN9250_PHY_BASIC_STATUS_REMOTE_FAULT                  0x0010
#define LAN9250_PHY_BASIC_STATUS_AN_CAPABLE                    0x0008
#define LAN9250_PHY_BASIC_STATUS_LINK_STATUS                   0x0004
#define LAN9250_PHY_BASIC_STATUS_JABBER_DETECT                 0x0002
#define LAN9250_PHY_BASIC_STATUS_EXTENDED_CAPABLE              0x0001

//PHY Identification MSB register
#define LAN9250_PHY_ID_MSB_PHY_ID_MSB                          0xFFFF
#define LAN9250_PHY_ID_MSB_PHY_ID_MSB_DEFAULT                  0x0007

//PHY Identification LSB register
#define LAN9250_PHY_ID_LSB_PHY_ID_LSB                          0xFC00
#define LAN9250_PHY_ID_LSB_PHY_ID_LSB_DEFAULT                  0xC000
#define LAN9250_PHY_ID_LSB_MODEL_NUM                           0x03F0
#define LAN9250_PHY_ID_LSB_MODEL_NUM_DEFAULT                   0x0140
#define LAN9250_PHY_ID_LSB_REVISION_NUM                        0x000F

//PHY Auto-Negotiation Advertisement register
#define LAN9250_PHY_AN_ADV_NEXT_PAGE                           0x8000
#define LAN9250_PHY_AN_ADV_REMOTE_FAULT                        0x2000
#define LAN9250_PHY_AN_ADV_EXTENDED_NEXT_PAGE                  0x1000
#define LAN9250_PHY_AN_ADV_ASYM_PAUSE                          0x0800
#define LAN9250_PHY_AN_ADV_SYM_PAUSE                           0x0400
#define LAN9250_PHY_AN_ADV_100BTX_FD                           0x0100
#define LAN9250_PHY_AN_ADV_100BTX_HD                           0x0080
#define LAN9250_PHY_AN_ADV_10BT_FD                             0x0040
#define LAN9250_PHY_AN_ADV_10BT_HD                             0x0020
#define LAN9250_PHY_AN_ADV_SELECTOR                            0x001F
#define LAN9250_PHY_AN_ADV_SELECTOR_DEFAULT                    0x0001

//PHY Auto-Negotiation Link Partner Base Page Ability register
#define LAN9250_PHY_AN_LP_BASE_ABILITY_NEXT_PAGE               0x8000
#define LAN9250_PHY_AN_LP_BASE_ABILITY_ACK                     0x4000
#define LAN9250_PHY_AN_LP_BASE_ABILITY_REMOTE_FAULT            0x2000
#define LAN9250_PHY_AN_LP_BASE_ABILITY_EXTENDED_NEXT_PAGE      0x1000
#define LAN9250_PHY_AN_LP_BASE_ABILITY_ASYM_PAUSE              0x0800
#define LAN9250_PHY_AN_LP_BASE_ABILITY_SYM_PAUSE               0x0400
#define LAN9250_PHY_AN_LP_BASE_ABILITY_100BT4                  0x0200
#define LAN9250_PHY_AN_LP_BASE_ABILITY_100BTX_FD               0x0100
#define LAN9250_PHY_AN_LP_BASE_ABILITY_100BTX_HD               0x0080
#define LAN9250_PHY_AN_LP_BASE_ABILITY_10BT_FD                 0x0040
#define LAN9250_PHY_AN_LP_BASE_ABILITY_10BT_HD                 0x0020
#define LAN9250_PHY_AN_LP_BASE_ABILITY_SELECTOR                0x001F
#define LAN9250_PHY_AN_LP_BASE_ABILITY_SELECTOR_DEFAULT        0x0001

//PHY Auto-Negotiation Expansion register
#define LAN9250_PHY_AN_EXP_RX_NEXT_PAGE_LOC_ABLE               0x0040
#define LAN9250_PHY_AN_EXP_RX_NEXT_PAGE_STOR_LOC               0x0020
#define LAN9250_PHY_AN_EXP_PAR_DETECT_FAULT                    0x0010
#define LAN9250_PHY_AN_EXP_LP_NEXT_PAGE_ABLE                   0x0008
#define LAN9250_PHY_AN_EXP_NEXT_PAGE_ABLE                      0x0004
#define LAN9250_PHY_AN_EXP_PAGE_RECEIVED                       0x0002
#define LAN9250_PHY_AN_EXP_LP_AN_ABLE                          0x0001

//PHY Auto Negotiation Next Page TX register
#define LAN9250_PHY_AN_NP_TX_NEXT_PAGE                         0x8000
#define LAN9250_PHY_AN_NP_TX_MSG_PAGE                          0x2000
#define LAN9250_PHY_AN_NP_TX_ACK2                              0x1000
#define LAN9250_PHY_AN_NP_TX_TOGGLE                            0x0800
#define LAN9250_PHY_AN_NP_TX_MESSAGE                           0x07FF

//PHY Auto Negotiation Next Page RX register
#define LAN9250_PHY_AN_NP_RX_NEXT_PAGE                         0x8000
#define LAN9250_PHY_AN_NP_RX_ACK                               0x4000
#define LAN9250_PHY_AN_NP_RX_MSG_PAGE                          0x2000
#define LAN9250_PHY_AN_NP_RX_ACK2                              0x1000
#define LAN9250_PHY_AN_NP_RX_TOGGLE                            0x0800
#define LAN9250_PHY_AN_NP_RX_MESSAGE                           0x07FF

//PHY MMD Access Control register
#define LAN9250_PHY_MMD_ACCESS_FUNC                            0xC000
#define LAN9250_PHY_MMD_ACCESS_FUNC_ADDR                       0x0000
#define LAN9250_PHY_MMD_ACCESS_FUNC_DATA_NO_POST_INC           0x4000
#define LAN9250_PHY_MMD_ACCESS_DEVAD                           0x001F

//PHY Mode Control/Status register
#define LAN9250_PHY_MODE_CONTROL_STATUS_EDPWRDOWN              0x2000
#define LAN9250_PHY_MODE_CONTROL_STATUS_ALTINT                 0x0040
#define LAN9250_PHY_MODE_CONTROL_STATUS_ENERGYON               0x0002

//PHY Special Modes register
#define LAN9250_PHY_SPECIAL_MODES_FX_MODE                      0x0400
#define LAN9250_PHY_SPECIAL_MODES_MODE                         0x00E0
#define LAN9250_PHY_SPECIAL_MODES_MODE_10BT_HD                 0x0000
#define LAN9250_PHY_SPECIAL_MODES_MODE_10BT_FD                 0x0020
#define LAN9250_PHY_SPECIAL_MODES_MODE_100BTX_HD               0x0040
#define LAN9250_PHY_SPECIAL_MODES_MODE_100BTX_FD               0x0060
#define LAN9250_PHY_SPECIAL_MODES_MODE_POWER_DOWN              0x00C0
#define LAN9250_PHY_SPECIAL_MODES_MODE_AN                      0x00E0
#define LAN9250_PHY_SPECIAL_MODES_PHYADD                       0x001F

//PHY TDR Patterns/Delay Control register
#define LAN9250_PHY_TDR_PAT_DELAY_TDR_DELAY_IN                 0x8000
#define LAN9250_PHY_TDR_PAT_DELAY_TDR_LINE_BREAK_COUNTER       0x7000
#define LAN9250_PHY_TDR_PAT_DELAY_TDR_PATTERN_HIGH             0x0FC0
#define LAN9250_PHY_TDR_PAT_DELAY_TDR_PATTERN_LOW              0x003F

//PHY TDR Control/Status register
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_EN                    0x8000
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_AD_FILTER_EN          0x4000
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_CABLE_TYPE         0x0600
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_CABLE_TYPE_DEFAULT 0x0000
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_CABLE_TYPE_SHORTED 0x0200
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_CABLE_TYPE_OPEN    0x0400
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_CABLE_TYPE_MATCH   0x0600
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_STATUS             0x0100
#define LAN9250_PHY_TDR_CONTROL_STAT_TDR_CH_LENGTH             0x00FF

//PHY Symbol Error Counter register
#define LAN9250_PHY_SYMBOL_ERR_COUNTER_SYM_ERR_CNT             0xFFFF

//PHY Special Control/Status Indication register
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_AMDIXCTRL         0x8000
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_AMDIXEN           0x4000
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_AMDIXSTATE        0x2000
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_SQEOFF            0x0800
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_FEFI_EN           0x0020
#define LAN9250_PHY_SPECIAL_CONTROL_STAT_IND_XPOL              0x0010

//PHY Cable Length register
#define LAN9250_PHY_CABLE_LEN_CBLN                             0xF000

//PHY Interrupt Source Flags register
#define LAN9250_PHY_INTERRUPT_SOURCE_LINK_UP                   0x0200
#define LAN9250_PHY_INTERRUPT_SOURCE_ENERGYON                  0x0080
#define LAN9250_PHY_INTERRUPT_SOURCE_AN_COMPLETE               0x0040
#define LAN9250_PHY_INTERRUPT_SOURCE_REMOTE_FAULT              0x0020
#define LAN9250_PHY_INTERRUPT_SOURCE_LINK_DOWN                 0x0010
#define LAN9250_PHY_INTERRUPT_SOURCE_AN_LP_ACK                 0x0008
#define LAN9250_PHY_INTERRUPT_SOURCE_PARALLEL_DETECT_FAULT     0x0004
#define LAN9250_PHY_INTERRUPT_SOURCE_AN_PAGE_RECEIVED          0x0002

//PHY Interrupt Mask register
#define LAN9250_PHY_INTERRUPT_MASK_LINK_UP                     0x0200
#define LAN9250_PHY_INTERRUPT_MASK_ENERGYON                    0x0080
#define LAN9250_PHY_INTERRUPT_MASK_AN_COMPLETE                 0x0040
#define LAN9250_PHY_INTERRUPT_MASK_REMOTE_FAULT                0x0020
#define LAN9250_PHY_INTERRUPT_MASK_LINK_DOWN                   0x0010
#define LAN9250_PHY_INTERRUPT_MASK_AN_LP_ACK                   0x0008
#define LAN9250_PHY_INTERRUPT_MASK_PARALLEL_DETECT_FAULT       0x0004
#define LAN9250_PHY_INTERRUPT_MASK_AN_PAGE_RECEIVED            0x0002

//PHY Special Control/Status register
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_AUTODONE            0x1000
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED               0x001C
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_10BT_HD       0x0004
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_100BTX_HD     0x0008
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_10BT_FD       0x0014
#define LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_100BTX_FD     0x0018

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//LAN9250 driver
extern const NicDriver lan9250Driver;

//LAN9250 related functions
error_t lan9250Init(NetInterface *interface);

void lan9250Tick(NetInterface *interface);

void lan9250EnableIrq(NetInterface *interface);
void lan9250DisableIrq(NetInterface *interface);
bool_t lan9250IrqHandler(NetInterface *interface);
void lan9250EventHandler(NetInterface *interface);

error_t lan9250SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t lan9250ReceivePacket(NetInterface *interface);
void lan9250DropPacket(NetInterface *interface, size_t length);

error_t lan9250UpdateMacAddrFilter(NetInterface *interface);

void lan9250WriteSysReg(NetInterface *interface, uint16_t address,
   uint32_t data);

uint32_t lan9250ReadSysReg(NetInterface *interface, uint16_t address);
void lan9250DumpSysReg(NetInterface *interface);

void lan9250WriteMacReg(NetInterface *interface, uint8_t address,
   uint32_t data);

uint32_t lan9250ReadMacReg(NetInterface *interface, uint8_t address);
void lan9250DumpMacReg(NetInterface *interface);

void lan9250WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t lan9250ReadPhyReg(NetInterface *interface, uint8_t address);
void lan9250DumpPhyReg(NetInterface *interface);

void lan9250WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t lan9250ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

void lan9250WriteFifo(NetInterface *interface, const uint8_t *data,
   size_t length);

void lan9250ReadFifo(NetInterface *interface, uint8_t *data, size_t length);

uint32_t lan9250CalcCrc(const void *data, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
