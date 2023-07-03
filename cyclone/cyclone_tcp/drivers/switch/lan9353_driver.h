/**
 * @file lan9353_driver.h
 * @brief LAN9353 3-port Ethernet switch driver
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

#ifndef _LAN9353_DRIVER_H
#define _LAN9353_DRIVER_H

//Dependencies
#include "core/nic.h"

//Port identifiers
#define LAN9353_PORT0 3
#define LAN9353_PORT1 1
#define LAN9353_PORT2 2

//Port masks
#define LAN9353_PORT_MASK      0x07
#define LAN9353_PORT0_MASK     0x04
#define LAN9353_PORT1_MASK     0x01
#define LAN9353_PORT2_MASK     0x02
#define LAN9353_PORT0_1_MASK   0x05
#define LAN9353_PORT0_2_MASK   0x06
#define LAN9353_PORT1_2_MASK   0x03
#define LAN9353_PORT0_1_2_MASK 0x07

//Size of of the MAC address lookup table
#define LAN9353_ALR_TABLE_SIZE 512

//Special VLAN tag (host to LAN9353)
#define LAN9353_VID_VLAN_RULES    0x0040
#define LAN9353_VID_CALC_PRIORITY 0x0020
#define LAN9353_VID_STP_OVERRIDE  0x0010
#define LAN9353_VID_ALR_LOOKUP    0x0008
#define LAN9353_VID_BROADCAST     0x0003
#define LAN9353_VID_DEST_PORT2    0x0002
#define LAN9353_VID_DEST_PORT1    0x0001
#define LAN9353_VID_DEST_PORT0    0x0000

//Special VLAN tag (LAN9353 to host)
#define LAN9353_VID_PRIORITY      0x0380
#define LAN9353_VID_PRIORITY_EN   0x0040
#define LAN9353_VID_STATIC        0x0020
#define LAN9353_VID_STP_OVERRIDE  0x0010
#define LAN9353_VID_IGMP_PACKET   0x0008
#define LAN9353_VID_SRC_PORT      0x0003

//LAN9353 PHY registers
#define LAN9353_BMCR                                          0x00
#define LAN9353_BMSR                                          0x01
#define LAN9353_PHYID1                                        0x02
#define LAN9353_PHYID2                                        0x03
#define LAN9353_ANAR                                          0x04
#define LAN9353_ANLPAR                                        0x05
#define LAN9353_ANER                                          0x06
#define LAN9353_PMCSR                                         0x11
#define LAN9353_PSMR                                          0x12
#define LAN9353_PSCSIR                                        0x1B
#define LAN9353_PISR                                          0x1D
#define LAN9353_PIMR                                          0x1E
#define LAN9353_PSCSR                                         0x1F

//LAN9353 System registers
#define LAN9353_ID_REV                                        0x0050
#define LAN9353_IRQ_CFG                                       0x0054
#define LAN9353_INT_STS                                       0x0058
#define LAN9353_INT_EN                                        0x005C
#define LAN9353_BYTE_TEST                                     0x0064
#define LAN9353_HW_CFG                                        0x0074
#define LAN9353_PMT_CTRL                                      0x0084
#define LAN9353_GPT_CFG                                       0x008C
#define LAN9353_GPT_CNT                                       0x0090
#define LAN9353_FREE_RUN                                      0x009C
#define LAN9353_PMI_DATA                                      0x00A4
#define LAN9353_PMI_ACCESS                                    0x00A8
#define LAN9353_VPHY_BASIC_CTRL_1                             0x00C0
#define LAN9353_VPHY_BASIC_STATUS_1                           0x00C4
#define LAN9353_VPHY_ID_MSB_1                                 0x00C8
#define LAN9353_VPHY_ID_LSB_1                                 0x00CC
#define LAN9353_VPHY_AN_ADV_1                                 0x00D0
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1                     0x00D4
#define LAN9353_VPHY_AN_EXP_1                                 0x00D8
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1                    0x00DC
#define LAN9353_1588_CMD_CTL                                  0x0100
#define LAN9353_1588_GENERAL_CONFIG                           0x0104
#define LAN9353_1588_INT_STS                                  0x0108
#define LAN9353_1588_INT_EN                                   0x010C
#define LAN9353_1588_CLOCK_SEC                                0x0110
#define LAN9353_1588_CLOCK_NS                                 0x0114
#define LAN9353_1588_CLOCK_SUBNS                              0x0118
#define LAN9353_1588_CLOCK_RATE_ADJ                           0x011C
#define LAN9353_1588_CLOCK_TEMP_RATE_ADJ                      0x0120
#define LAN9353_1588_CLOCK_TEMP_RATE_DURATION                 0x0124
#define LAN9353_1588_CLOCK_STEP_ADJ                           0x0128
#define LAN9353_1588_CLOCK_TARGET_SEC_A                       0x012C
#define LAN9353_1588_CLOCK_TARGET_NS_A                        0x0130
#define LAN9353_1588_CLOCK_TARGET_RELOAD_SEC_A                0x0134
#define LAN9353_1588_CLOCK_TARGET_RELOAD_NS_A                 0x0138
#define LAN9353_1588_CLOCK_TARGET_SEC_B                       0x013C
#define LAN9353_1588_CLOCK_TARGET_NS_B                        0x0140
#define LAN9353_1588_CLOCK_TARGET_RELOAD_SEC_B                0x0144
#define LAN9353_1588_CLOCK_TARGET_RELOAD_NS_B                 0x0148
#define LAN9353_1588_USER_MAC_HI                              0x014C
#define LAN9353_1588_USER_MAC_LO                              0x0150
#define LAN9353_1588_BANK_PORT_GPIO_SEL                       0x0154
#define LAN9353_1588_LATENCY                                  0x0158
#define LAN9353_1588_RX_PARSE_CONFIG                          0x0158
#define LAN9353_1588_TX_PARSE_CONFIG                          0x0158
#define LAN9353_1588_ASYM_PEERDLY                             0x015C
#define LAN9353_1588_RX_TIMESTAMP_CONFIG                      0x015C
#define LAN9353_1588_TX_TIMESTAMP_CONFIG                      0x015C
#define LAN9353_1588_GPIO_CAP_CONFIG                          0x015C
#define LAN9353_1588_CAP_INFO                                 0x0160
#define LAN9353_1588_RX_TS_INSERT_CONFIG                      0x0160
#define LAN9353_1588_RX_CF_MOD                                0x0164
#define LAN9353_1588_TX_MOD                                   0x0164
#define LAN9353_1588_RX_FILTER_CONFIG                         0x0168
#define LAN9353_1588_TX_MOD2                                  0x0168
#define LAN9353_1588_RX_INGRESS_SEC                           0x016C
#define LAN9353_1588_TX_EGRESS_SEC                            0x016C
#define LAN9353_1588_GPIO_RE_CLOCK_SEC_CAP                    0x016C
#define LAN9353_1588_RX_INGRESS_NS                            0x0170
#define LAN9353_1588_TX_EGRESS_NS                             0x0170
#define LAN9353_1588_GPIO_RE_CLOCK_NS_CAP                     0x0170
#define LAN9353_1588_RX_MSG_HEADER                            0x0174
#define LAN9353_1588_TX_MSG_HEADER                            0x0174
#define LAN9353_1588_RX_PDREQ_SEC                             0x0178
#define LAN9353_1588_TX_DREQ_SEC                              0x0178
#define LAN9353_1588_GPIO_FE_CLOCK_SEC_CAP                    0x0178
#define LAN9353_1588_RX_PDREQ_NS                              0x017C
#define LAN9353_1588_TX_DREQ_NS                               0x017C
#define LAN9353_1588_GPIO_FE_CLOCK_NS_CAP                     0x017C
#define LAN9353_1588_RX_PDREQ_CF_HI                           0x0180
#define LAN9353_1588_TX_ONE_STEP_SYNC_SEC                     0x0180
#define LAN9353_1588_RX_PDREQ_CF_LOW                          0x0184
#define LAN9353_1588_RX_CHKSUM_DROPPED_CNT                    0x0188
#define LAN9353_1588_RX_FILTERED_CNT                          0x018C
#define LAN9353_MANUAL_FC_1                                   0x01A0
#define LAN9353_MANUAL_FC_2                                   0x01A4
#define LAN9353_MANUAL_FC_0                                   0x01A8
#define LAN9353_SWITCH_CSR_DATA                               0x01AC
#define LAN9353_SWITCH_CSR_CMD                                0x01B0
#define LAN9353_E2P_CMD                                       0x01B4
#define LAN9353_E2P_DATA                                      0x01B8
#define LAN9353_LED_CFG                                       0x01BC
#define LAN9353_VPHY_BASIC_CTRL_0                             0x01C0
#define LAN9353_VPHY_BASIC_STATUS_0                           0x01C4
#define LAN9353_VPHY_ID_MSB_0                                 0x01C8
#define LAN9353_VPHY_ID_LSB_0                                 0x01CC
#define LAN9353_VPHY_AN_ADV_0                                 0x01D0
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0                     0x01D4
#define LAN9353_VPHY_AN_EXP_0                                 0x01D8
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0                    0x01DC
#define LAN9353_GPIO_CFG                                      0x01E0
#define LAN9353_GPIO_DATA_DIR                                 0x01E4
#define LAN9353_GPIO_INT_STS_EN                               0x01E8
#define LAN9353_SWITCH_MAC_ADDRH                              0x01F0
#define LAN9353_SWITCH_MAC_ADDRL                              0x01F4
#define LAN9353_RESET_CTL                                     0x01F8
#define LAN9353_SWITCH_CSR_DIRECT_DATA                        0x0200

//LAN9353 Switch Fabric registers
#define LAN9353_SW_DEV_ID                                     0x0000
#define LAN9353_SW_RESET                                      0x0001
#define LAN9353_SW_IMR                                        0x0004
#define LAN9353_SW_IPR                                        0x0005
#define LAN9353_MAC_VER_ID_0                                  0x0400
#define LAN9353_MAC_RX_CFG_0                                  0x0401
#define LAN9353_MAC_RX_UNDSZE_CNT_0                           0x0410
#define LAN9353_MAC_RX_64_CNT_0                               0x0411
#define LAN9353_MAC_RX_65_TO_127_CNT_0                        0x0412
#define LAN9353_MAC_RX_128_TO_255_CNT_0                       0x0413
#define LAN9353_MAC_RX_256_TO_511_CNT_0                       0x0414
#define LAN9353_MAC_RX_512_TO_1023_CNT_0                      0x0415
#define LAN9353_MAC_RX_1024_TO_MAX_CNT_0                      0x0416
#define LAN9353_MAC_RX_OVRSZE_CNT_0                           0x0417
#define LAN9353_MAC_RX_PKTOK_CNT_0                            0x0418
#define LAN9353_MAC_RX_CRCERR_CNT_0                           0x0419
#define LAN9353_MAC_RX_MULCST_CNT_0                           0x041A
#define LAN9353_MAC_RX_BRDCST_CNT_0                           0x041B
#define LAN9353_MAC_RX_PAUSE_CNT_0                            0x041C
#define LAN9353_MAC_RX_FRAG_CNT_0                             0x041D
#define LAN9353_MAC_RX_JABB_CNT_0                             0x041E
#define LAN9353_MAC_RX_ALIGN_CNT_0                            0x041F
#define LAN9353_MAC_RX_PKTLEN_CNT_0                           0x0420
#define LAN9353_MAC_RX_GOODPKTLEN_CNT_0                       0x0421
#define LAN9353_MAC_RX_SYMBOL_CNT_0                           0x0422
#define LAN9353_MAC_RX_CTLFRM_CNT_0                           0x0423
#define LAN9353_MAC_TX_CFG_0                                  0x0440
#define LAN9353_MAC_TX_FC_SETTINGS_0                          0x0441
#define LAN9353_MAC_TX_DEFER_CNT_0                            0x0451
#define LAN9353_MAC_TX_PAUSE_CNT_0                            0x0452
#define LAN9353_MAC_TX_PKTOK_CNT_0                            0x0453
#define LAN9353_MAC_TX_64_CNT_0                               0x0454
#define LAN9353_MAC_TX_65_TO_127_CNT_0                        0x0455
#define LAN9353_MAC_TX_128_TO_255_CNT_0                       0x0456
#define LAN9353_MAC_TX_256_TO_511_CNT_0                       0x0457
#define LAN9353_MAC_TX_512_TO_1023_CNT_0                      0x0458
#define LAN9353_MAC_TX_1024_TO_MAX_CNT_0                      0x0459
#define LAN9353_MAC_TX_UNDSZE_CNT_0                           0x045A
#define LAN9353_MAC_TX_PKTLEN_CNT_0                           0x045C
#define LAN9353_MAC_TX_BRDCST_CNT_0                           0x045D
#define LAN9353_MAC_TX_MULCST_CNT_0                           0x045E
#define LAN9353_MAC_TX_LATECOL_CNT_0                          0x045F
#define LAN9353_MAC_TX_EXCCOL_CNT_0                           0x0460
#define LAN9353_MAC_TX_SNGLECOL_CNT_0                         0x0461
#define LAN9353_MAC_TX_MULTICOL_CNT_0                         0x0462
#define LAN9353_MAC_TX_TOTALCOL_CNT_0                         0x0463
#define LAN9353_MAC_IMR_0                                     0x0480
#define LAN9353_MAC_IPR_0                                     0x0481
#define LAN9353_MAC_VER_ID_1                                  0x0800
#define LAN9353_MAC_RX_CFG_1                                  0x0801
#define LAN9353_MAC_RX_UNDSZE_CNT_1                           0x0810
#define LAN9353_MAC_RX_64_CNT_1                               0x0811
#define LAN9353_MAC_RX_65_TO_127_CNT_1                        0x0812
#define LAN9353_MAC_RX_128_TO_255_CNT_1                       0x0813
#define LAN9353_MAC_RX_256_TO_511_CNT_1                       0x0814
#define LAN9353_MAC_RX_512_TO_1023_CNT_1                      0x0815
#define LAN9353_MAC_RX_1024_TO_MAX_CNT_1                      0x0816
#define LAN9353_MAC_RX_OVRSZE_CNT_1                           0x0817
#define LAN9353_MAC_RX_PKTOK_CNT_1                            0x0818
#define LAN9353_MAC_RX_CRCERR_CNT_1                           0x0819
#define LAN9353_MAC_RX_MULCST_CNT_1                           0x081A
#define LAN9353_MAC_RX_BRDCST_CNT_1                           0x081B
#define LAN9353_MAC_RX_PAUSE_CNT_1                            0x081C
#define LAN9353_MAC_RX_FRAG_CNT_1                             0x081D
#define LAN9353_MAC_RX_JABB_CNT_1                             0x081E
#define LAN9353_MAC_RX_ALIGN_CNT_1                            0x081F
#define LAN9353_MAC_RX_PKTLEN_CNT_1                           0x0820
#define LAN9353_MAC_RX_GOODPKTLEN_CNT_1                       0x0821
#define LAN9353_MAC_RX_SYMBOL_CNT_1                           0x0822
#define LAN9353_MAC_RX_CTLFRM_CNT_1                           0x0823
#define LAN9353_RX_LPI_TRANSITION_1                           0x0824
#define LAN9353_RX_LPI_TIME_1                                 0x0825
#define LAN9353_MAC_TX_CFG_1                                  0x0840
#define LAN9353_MAC_TX_FC_SETTINGS_1                          0x0841
#define LAN9353_EEE_TW_TX_SYS_1                               0x0842
#define LAN9353_EEE_TX_LPI_REQ_DELAY_1                        0x0843
#define LAN9353_MAC_TX_DEFER_CNT_1                            0x0851
#define LAN9353_MAC_TX_PAUSE_CNT_1                            0x0852
#define LAN9353_MAC_TX_PKTOK_CNT_1                            0x0853
#define LAN9353_MAC_TX_64_CNT_1                               0x0854
#define LAN9353_MAC_TX_65_TO_127_CNT_1                        0x0855
#define LAN9353_MAC_TX_128_TO_255_CNT_1                       0x0856
#define LAN9353_MAC_TX_256_TO_511_CNT_1                       0x0857
#define LAN9353_MAC_TX_512_TO_1023_CNT_1                      0x0858
#define LAN9353_MAC_TX_1024_TO_MAX_CNT_1                      0x0859
#define LAN9353_MAC_TX_UNDSZE_CNT_1                           0x085A
#define LAN9353_MAC_TX_PKTLEN_CNT_1                           0x085C
#define LAN9353_MAC_TX_BRDCST_CNT_1                           0x085D
#define LAN9353_MAC_TX_MULCST_CNT_1                           0x085E
#define LAN9353_MAC_TX_LATECOL_CNT_1                          0x085F
#define LAN9353_MAC_TX_EXCCOL_CNT_1                           0x0860
#define LAN9353_MAC_TX_SNGLECOL_CNT_1                         0x0861
#define LAN9353_MAC_TX_MULTICOL_CNT_1                         0x0862
#define LAN9353_MAC_TX_TOTALCOL_CNT_1                         0x0863
#define LAN9353_TX_LPI_TRANSITION_1                           0x0864
#define LAN9353_TX_LPI_TIME_1                                 0x0865
#define LAN9353_MAC_IMR_1                                     0x0880
#define LAN9353_MAC_IPR_1                                     0x0881
#define LAN9353_MAC_VER_ID_2                                  0x0C00
#define LAN9353_MAC_RX_CFG_2                                  0x0C01
#define LAN9353_MAC_RX_UNDSZE_CNT_2                           0x0C10
#define LAN9353_MAC_RX_64_CNT_2                               0x0C11
#define LAN9353_MAC_RX_65_TO_127_CNT_2                        0x0C12
#define LAN9353_MAC_RX_128_TO_255_CNT_2                       0x0C13
#define LAN9353_MAC_RX_256_TO_511_CNT_2                       0x0C14
#define LAN9353_MAC_RX_512_TO_1023_CNT_2                      0x0C15
#define LAN9353_MAC_RX_1024_TO_MAX_CNT_2                      0x0C16
#define LAN9353_MAC_RX_OVRSZE_CNT_2                           0x0C17
#define LAN9353_MAC_RX_PKTOK_CNT_2                            0x0C18
#define LAN9353_MAC_RX_CRCERR_CNT_2                           0x0C19
#define LAN9353_MAC_RX_MULCST_CNT_2                           0x0C1A
#define LAN9353_MAC_RX_BRDCST_CNT_2                           0x0C1B
#define LAN9353_MAC_RX_PAUSE_CNT_2                            0x0C1C
#define LAN9353_MAC_RX_FRAG_CNT_2                             0x0C1D
#define LAN9353_MAC_RX_JABB_CNT_2                             0x0C1E
#define LAN9353_MAC_RX_ALIGN_CNT_2                            0x0C1F
#define LAN9353_MAC_RX_PKTLEN_CNT_2                           0x0C20
#define LAN9353_MAC_RX_GOODPKTLEN_CNT_2                       0x0C21
#define LAN9353_MAC_RX_SYMBOL_CNT_2                           0x0C22
#define LAN9353_MAC_RX_CTLFRM_CNT_2                           0x0C23
#define LAN9353_RX_LPI_TRANSITION_2                           0x0C24
#define LAN9353_RX_LPI_TIME_2                                 0x0C25
#define LAN9353_MAC_TX_CFG_2                                  0x0C40
#define LAN9353_MAC_TX_FC_SETTINGS_2                          0x0C41
#define LAN9353_EEE_TW_TX_SYS_2                               0x0C42
#define LAN9353_EEE_TX_LPI_REQ_DELAY_2                        0x0C43
#define LAN9353_MAC_TX_DEFER_CNT_2                            0x0C51
#define LAN9353_MAC_TX_PAUSE_CNT_2                            0x0C52
#define LAN9353_MAC_TX_PKTOK_CNT_2                            0x0C53
#define LAN9353_MAC_TX_64_CNT_2                               0x0C54
#define LAN9353_MAC_TX_65_TO_127_CNT_2                        0x0C55
#define LAN9353_MAC_TX_128_TO_255_CNT_2                       0x0C56
#define LAN9353_MAC_TX_256_TO_511_CNT_2                       0x0C57
#define LAN9353_MAC_TX_512_TO_1023_CNT_2                      0x0C58
#define LAN9353_MAC_TX_1024_TO_MAX_CNT_2                      0x0C59
#define LAN9353_MAC_TX_UNDSZE_CNT_2                           0x0C5A
#define LAN9353_MAC_TX_PKTLEN_CNT_2                           0x0C5C
#define LAN9353_MAC_TX_BRDCST_CNT_2                           0x0C5D
#define LAN9353_MAC_TX_MULCST_CNT_2                           0x0C5E
#define LAN9353_MAC_TX_LATECOL_CNT_2                          0x0C5F
#define LAN9353_MAC_TX_EXCCOL_CNT_2                           0x0C60
#define LAN9353_MAC_TX_SNGLECOL_CNT_2                         0x0C61
#define LAN9353_MAC_TX_MULTICOL_CNT_2                         0x0C62
#define LAN9353_MAC_TX_TOTALCOL_CNT_2                         0x0C63
#define LAN9353_TX_LPI_TRANSITION_2                           0x0C64
#define LAN9353_TX_LPI_TIME_2                                 0x0C65
#define LAN9353_MAC_IMR_2                                     0x0C80
#define LAN9353_MAC_IPR_2                                     0x0C81
#define LAN9353_SWE_ALR_CMD                                   0x1800
#define LAN9353_SWE_ALR_WR_DAT_0                              0x1801
#define LAN9353_SWE_ALR_WR_DAT_1                              0x1802
#define LAN9353_SWE_ALR_RD_DAT_0                              0x1805
#define LAN9353_SWE_ALR_RD_DAT_1                              0x1806
#define LAN9353_SWE_ALR_CMD_STS                               0x1808
#define LAN9353_SWE_ALR_CFG                                   0x1809
#define LAN9353_SWE_ALR_OVERRIDE                              0x180A
#define LAN9353_SWE_VLAN_CMD                                  0x180B
#define LAN9353_SWE_VLAN_WR_DATA                              0x180C
#define LAN9353_SWE_VLAN_RD_DATA                              0x180E
#define LAN9353_SWE_VLAN_CMD_STS                              0x1810
#define LAN9353_SWE_DIFFSERV_TBL_CFG                          0x1811
#define LAN9353_SWE_DIFFSERV_TBL_WR_DATA                      0x1812
#define LAN9353_SWE_DIFFSERV_TBL_RD_DATA                      0x1813
#define LAN9353_SWE_DIFFSERV_TBL_CMD_STS                      0x1814
#define LAN9353_SWE_GLOBAL_INGRSS_CFG                         0x1840
#define LAN9353_SWE_PORT_INGRSS_CFG                           0x1841
#define LAN9353_SWE_ADMT_ONLY_VLAN                            0x1842
#define LAN9353_SWE_PORT_STATE                                0x1843
#define LAN9353_SWE_PRI_TO_QUE                                0x1845
#define LAN9353_SWE_PORT_MIRROR                               0x1846
#define LAN9353_SWE_INGRSS_PORT_TYP                           0x1847
#define LAN9353_SWE_BCST_THROT                                0x1848
#define LAN9353_SWE_ADMT_N_MEMBER                             0x1849
#define LAN9353_SWE_INGRSS_RATE_CFG                           0x184A
#define LAN9353_SWE_INGRSS_RATE_CMD                           0x184B
#define LAN9353_SWE_INGRSS_RATE_CMD_STS                       0x184C
#define LAN9353_SWE_INGRSS_RATE_WR_DATA                       0x184D
#define LAN9353_SWE_INGRSS_RATE_RD_DATA                       0x184E
#define LAN9353_SWE_FILTERED_CNT_0                            0x1850
#define LAN9353_SWE_FILTERED_CNT_1                            0x1851
#define LAN9353_SWE_FILTERED_CNT_2                            0x1852
#define LAN9353_SWE_INGRSS_REGEN_TBL_0                        0x1855
#define LAN9353_SWE_INGRSS_REGEN_TBL_1                        0x1856
#define LAN9353_SWE_INGRSS_REGEN_TBL_2                        0x1857
#define LAN9353_SWE_LRN_DISCRD_CNT_0                          0x1858
#define LAN9353_SWE_LRN_DISCRD_CNT_1                          0x1859
#define LAN9353_SWE_LRN_DISCRD_CNT_2                          0x185A
#define LAN9353_SWE_IMR                                       0x1880
#define LAN9353_SWE_IPR                                       0x1881
#define LAN9353_BM_CFG                                        0x1C00
#define LAN9353_BM_DROP_LVL                                   0x1C01
#define LAN9353_BM_FC_PAUSE_LVL                               0x1C02
#define LAN9353_BM_FC_RESUME_LVL                              0x1C03
#define LAN9353_BM_BCST_LVL                                   0x1C04
#define LAN9353_BM_DRP_CNT_SRC_0                              0x1C05
#define LAN9353_BM_DRP_CNT_SRC_1                              0x1C06
#define LAN9353_BM_DRP_CNT_SRC_2                              0x1C07
#define LAN9353_BM_RST_STS                                    0x1C08
#define LAN9353_BM_RNDM_DSCRD_TBL_CMD                         0x1C09
#define LAN9353_BM_RNDM_DSCRD_TBL_WDATA                       0x1C0A
#define LAN9353_BM_RNDM_DSCRD_TBL_RDATA                       0x1C0B
#define LAN9353_BM_EGRSS_PORT_TYPE                            0x1C0C
#define LAN9353_BM_EGRSS_RATE_00_01                           0x1C0D
#define LAN9353_BM_EGRSS_RATE_02_03                           0x1C0E
#define LAN9353_BM_EGRSS_RATE_10_11                           0x1C0F
#define LAN9353_BM_EGRSS_RATE_12_13                           0x1C10
#define LAN9353_BM_EGRSS_RATE_20_21                           0x1C11
#define LAN9353_BM_EGRSS_RATE_22_23                           0x1C12
#define LAN9353_BM_VLAN_0                                     0x1C13
#define LAN9353_BM_VLAN_1                                     0x1C14
#define LAN9353_BM_VLAN_2                                     0x1C15
#define LAN9353_BM_RATE_DRP_CNT_SRC_0                         0x1C16
#define LAN9353_BM_RATE_DRP_CNT_SRC_1                         0x1C17
#define LAN9353_BM_RATE_DRP_CNT_SRC_2                         0x1C18
#define LAN9353_BM_IMR                                        0x1C20
#define LAN9353_BM_IPR                                        0x1C21

//LAN9353 Switch Fabric register access macros
#define LAN9353_MAC_VER_ID(port)                              (0x0400 + ((port) * 0x0400))
#define LAN9353_MAC_RX_CFG(port)                              (0x0401 + ((port) * 0x0400))
#define LAN9353_MAC_RX_UNDSZE_CNT(port)                       (0x0410 + ((port) * 0x0400))
#define LAN9353_MAC_RX_64_CNT(port)                           (0x0411 + ((port) * 0x0400))
#define LAN9353_MAC_RX_65_TO_127_CNT(port)                    (0x0412 + ((port) * 0x0400))
#define LAN9353_MAC_RX_128_TO_255_CNT(port)                   (0x0413 + ((port) * 0x0400))
#define LAN9353_MAC_RX_256_TO_511_CNT(port)                   (0x0414 + ((port) * 0x0400))
#define LAN9353_MAC_RX_512_TO_1023_CNT(port)                  (0x0415 + ((port) * 0x0400))
#define LAN9353_MAC_RX_1024_TO_MAX_CNT(port)                  (0x0416 + ((port) * 0x0400))
#define LAN9353_MAC_RX_OVRSZE_CNT(port)                       (0x0417 + ((port) * 0x0400))
#define LAN9353_MAC_RX_PKTOK_CNT(port)                        (0x0418 + ((port) * 0x0400))
#define LAN9353_MAC_RX_CRCERR_CNT(port)                       (0x0419 + ((port) * 0x0400))
#define LAN9353_MAC_RX_MULCST_CNT(port)                       (0x041A + ((port) * 0x0400))
#define LAN9353_MAC_RX_BRDCST_CNT(port)                       (0x041B + ((port) * 0x0400))
#define LAN9353_MAC_RX_PAUSE_CNT(port)                        (0x041C + ((port) * 0x0400))
#define LAN9353_MAC_RX_FRAG_CNT(port)                         (0x041D + ((port) * 0x0400))
#define LAN9353_MAC_RX_JABB_CNT(port)                         (0x041E + ((port) * 0x0400))
#define LAN9353_MAC_RX_ALIGN_CNT(port)                        (0x041F + ((port) * 0x0400))
#define LAN9353_MAC_RX_PKTLEN_CNT(port)                       (0x0420 + ((port) * 0x0400))
#define LAN9353_MAC_RX_GOODPKTLEN_CNT(port)                   (0x0421 + ((port) * 0x0400))
#define LAN9353_MAC_RX_SYMBOL_CNT(port)                       (0x0422 + ((port) * 0x0400))
#define LAN9353_MAC_RX_CTLFRM_CNT(port)                       (0x0423 + ((port) * 0x0400))
#define LAN9353_RX_LPI_TRANSITION(port)                       (0x0424 + ((port) * 0x0400))
#define LAN9353_RX_LPI_TIME(port)                             (0x0425 + ((port) * 0x0400))
#define LAN9353_MAC_TX_CFG(port)                              (0x0440 + ((port) * 0x0400))
#define LAN9353_MAC_TX_FC_SETTINGS(port)                      (0x0441 + ((port) * 0x0400))
#define LAN9353_EEE_TW_TX_SYS(port)                           (0x0442 + ((port) * 0x0400))
#define LAN9353_EEE_TX_LPI_REQ_DELAY(port)                    (0x0443 + ((port) * 0x0400))
#define LAN9353_MAC_TX_DEFER_CNT(port)                        (0x0451 + ((port) * 0x0400))
#define LAN9353_MAC_TX_PAUSE_CNT(port)                        (0x0452 + ((port) * 0x0400))
#define LAN9353_MAC_TX_PKTOK_CNT(port)                        (0x0453 + ((port) * 0x0400))
#define LAN9353_MAC_TX_64_CNT(port)                           (0x0454 + ((port) * 0x0400))
#define LAN9353_MAC_TX_65_TO_127_CNT(port)                    (0x0455 + ((port) * 0x0400))
#define LAN9353_MAC_TX_128_TO_255_CNT(port)                   (0x0456 + ((port) * 0x0400))
#define LAN9353_MAC_TX_256_TO_511_CNT(port)                   (0x0457 + ((port) * 0x0400))
#define LAN9353_MAC_TX_512_TO_1023_CNT(port)                  (0x0458 + ((port) * 0x0400))
#define LAN9353_MAC_TX_1024_TO_MAX_CNT(port)                  (0x0459 + ((port) * 0x0400))
#define LAN9353_MAC_TX_UNDSZE_CNT(port)                       (0x045A + ((port) * 0x0400))
#define LAN9353_MAC_TX_PKTLEN_CNT(port)                       (0x045C + ((port) * 0x0400))
#define LAN9353_MAC_TX_BRDCST_CNT(port)                       (0x045D + ((port) * 0x0400))
#define LAN9353_MAC_TX_MULCST_CNT(port)                       (0x045E + ((port) * 0x0400))
#define LAN9353_MAC_TX_LATECOL_CNT(port)                      (0x045F + ((port) * 0x0400))
#define LAN9353_MAC_TX_EXCCOL_CNT(port)                       (0x0460 + ((port) * 0x0400))
#define LAN9353_MAC_TX_SNGLECOL_CNT(port)                     (0x0461 + ((port) * 0x0400))
#define LAN9353_MAC_TX_MULTICOL_CNT(port)                     (0x0462 + ((port) * 0x0400))
#define LAN9353_MAC_TX_TOTALCOL_CNT(port)                     (0x0463 + ((port) * 0x0400))
#define LAN9353_TX_LPI_TRANSITION(port)                       (0x0464 + ((port) * 0x0400))
#define LAN9353_TX_LPI_TIME(port)                             (0x0465 + ((port) * 0x0400))
#define LAN9353_MAC_IMR(port)                                 (0x0480 + ((port) * 0x0400))
#define LAN9353_MAC_IPR(port)                                 (0x0481 + ((port) * 0x0400))

//PHY Basic Control register
#define LAN9353_BMCR_RESET                                    0x8000
#define LAN9353_BMCR_LOOPBACK                                 0x4000
#define LAN9353_BMCR_SPEED_SEL                                0x2000
#define LAN9353_BMCR_AN_EN                                    0x1000
#define LAN9353_BMCR_POWER_DOWN                               0x0800
#define LAN9353_BMCR_RESTART_AN                               0x0200
#define LAN9353_BMCR_DUPLEX_MODE                              0x0100
#define LAN9353_BMCR_COL_TEST                                 0x0080

//PHY Basic Status register
#define LAN9353_BMSR_100BT4                                   0x8000
#define LAN9353_BMSR_100BTX_FD                                0x4000
#define LAN9353_BMSR_100BTX_HD                                0x2000
#define LAN9353_BMSR_10BT_FD                                  0x1000
#define LAN9353_BMSR_10BT_HD                                  0x0800
#define LAN9353_BMSR_100BT2_FD                                0x0400
#define LAN9353_BMSR_100BT2_HD                                0x0200
#define LAN9353_BMSR_EXTENDED_STATUS                          0x0100
#define LAN9353_BMSR_UNIDIRECTIONAL_ABLE                      0x0080
#define LAN9353_BMSR_MF_PREAMBLE_SUPPR                        0x0040
#define LAN9353_BMSR_AN_COMPLETE                              0x0020
#define LAN9353_BMSR_REMOTE_FAULT                             0x0010
#define LAN9353_BMSR_AN_CAPABLE                               0x0008
#define LAN9353_BMSR_LINK_STATUS                              0x0004
#define LAN9353_BMSR_JABBER_DETECT                            0x0002
#define LAN9353_BMSR_EXTENDED_CAPABLE                         0x0001

//PHY Identification MSB register
#define LAN9353_PHYID1_PHY_ID_MSB                             0xFFFF
#define LAN9353_PHYID1_PHY_ID_MSB_DEFAULT                     0x0007

//PHY Identification LSB register
#define LAN9353_PHYID2_PHY_ID_LSB                             0xFC00
#define LAN9353_PHYID2_PHY_ID_LSB_DEFAULT                     0xC000
#define LAN9353_PHYID2_MODEL_NUM                              0x03F0
#define LAN9353_PHYID2_MODEL_NUM_DEFAULT                      0x0140
#define LAN9353_PHYID2_REVISION_NUM                           0x000F

//PHY Auto-Negotiation Advertisement register
#define LAN9353_ANAR_REMOTE_FAULT                             0x2000
#define LAN9353_ANAR_ASYM_PAUSE                               0x0800
#define LAN9353_ANAR_SYM_PAUSE                                0x0400
#define LAN9353_ANAR_100BTX_FD                                0x0100
#define LAN9353_ANAR_100BTX_HD                                0x0080
#define LAN9353_ANAR_10BT_FD                                  0x0040
#define LAN9353_ANAR_10BT_HD                                  0x0020
#define LAN9353_ANAR_SELECTOR                                 0x001F
#define LAN9353_ANAR_SELECTOR_DEFAULT                         0x0001

//PHY Auto-Negotiation Link Partner Base Page Ability register
#define LAN9353_ANLPAR_NEXT_PAGE                              0x8000
#define LAN9353_ANLPAR_ACK                                    0x4000
#define LAN9353_ANLPAR_REMOTE_FAULT                           0x2000
#define LAN9353_ANLPAR_ASYM_PAUSE                             0x0800
#define LAN9353_ANLPAR_SYM_PAUSE                              0x0400
#define LAN9353_ANLPAR_100BT4                                 0x0200
#define LAN9353_ANLPAR_100BTX_FD                              0x0100
#define LAN9353_ANLPAR_100BTX_HD                              0x0080
#define LAN9353_ANLPAR_10BT_FD                                0x0040
#define LAN9353_ANLPAR_10BT_HD                                0x0020
#define LAN9353_ANLPAR_SELECTOR                               0x001F
#define LAN9353_ANLPAR_SELECTOR_DEFAULT                       0x0001

//PHY Auto-Negotiation Expansion register
#define LAN9353_ANER_PAR_DETECT_FAULT                         0x0010
#define LAN9353_ANER_LP_NEXT_PAGE_ABLE                        0x0008
#define LAN9353_ANER_NEXT_PAGE_ABLE                           0x0004
#define LAN9353_ANER_PAGE_RECEIVED                            0x0002
#define LAN9353_ANER_LP_AN_ABLE                               0x0001

//PHY Mode Control/Status register
#define LAN9353_PMCSR_EDPWRDOWN                               0x2000
#define LAN9353_PMCSR_ENERGYON                                0x0002

//PHY Special Modes register
#define LAN9353_PSMR_MODE                                     0x00E0
#define LAN9353_PSMR_MODE_10BT_HD                             0x0000
#define LAN9353_PSMR_MODE_10BT_FD                             0x0020
#define LAN9353_PSMR_MODE_100BTX_HD                           0x0040
#define LAN9353_PSMR_MODE_100BTX_FD                           0x0060
#define LAN9353_PSMR_MODE_POWER_DOWN                          0x00C0
#define LAN9353_PSMR_MODE_AN                                  0x00E0
#define LAN9353_PSMR_PHYAD                                    0x001F

//PHY Special Control/Status Indication register
#define LAN9353_PSCSIR_AMDIXCTRL                              0x8000
#define LAN9353_PSCSIR_AMDIXEN                                0x4000
#define LAN9353_PSCSIR_AMDIXSTATE                             0x2000
#define LAN9353_PSCSIR_SQEOFF                                 0x0800
#define LAN9353_PSCSIR_VCOOFF_LP                              0x0400
#define LAN9353_PSCSIR_XPOL                                   0x0010

//PHY Interrupt Source Flags register
#define LAN9353_PISR_ENERGYON                                 0x0080
#define LAN9353_PISR_AN_COMPLETE                              0x0040
#define LAN9353_PISR_REMOTE_FAULT                             0x0020
#define LAN9353_PISR_LINK_DOWN                                0x0010
#define LAN9353_PISR_AN_LP_ACK                                0x0008
#define LAN9353_PISR_PAR_DETECT_FAULT                         0x0004
#define LAN9353_PISR_AN_PAGE_RECEIVED                         0x0002

//PHY Interrupt Mask register
#define LAN9353_PIMR_ENERGYON                                 0x0080
#define LAN9353_PIMR_AN_COMPLETE                              0x0040
#define LAN9353_PIMR_REMOTE_FAULT                             0x0020
#define LAN9353_PIMR_LINK_DOWN                                0x0010
#define LAN9353_PIMR_AN_LP_ACK                                0x0008
#define LAN9353_PIMR_PAR_DETECT_FAULT                         0x0004
#define LAN9353_PIMR_AN_PAGE_RECEIVED                         0x0002

//PHY Special Control/Status register
#define LAN9353_PSCSR_AUTODONE                                0x1000
#define LAN9353_PSCSR_SPEED                                   0x001C
#define LAN9353_PSCSR_SPEED_10BT_HD                           0x0004
#define LAN9353_PSCSR_SPEED_100BTX_HD                         0x0008
#define LAN9353_PSCSR_SPEED_10BT_FD                           0x0014
#define LAN9353_PSCSR_SPEED_100BTX_FD                         0x0018

//Chip ID and Revision register
#define LAN9353_ID_REV_CHIP_ID                                0xFFFF0000
#define LAN9353_ID_REV_CHIP_ID_DEFAULT                        0x93530000
#define LAN9353_ID_REV_CHIP_REV                               0x0000FFFF

//Interrupt Configuration register
#define LAN9353_IRQ_CFG_INT_DEAS                              0xFF000000
#define LAN9353_IRQ_CFG_INT_DEAS_CLR                          0x00004000
#define LAN9353_IRQ_CFG_INT_DEAS_STS                          0x00002000
#define LAN9353_IRQ_CFG_IRQ_INT                               0x00001000
#define LAN9353_IRQ_CFG_IRQ_EN                                0x00000100
#define LAN9353_IRQ_CFG_IRQ_POL                               0x00000010
#define LAN9353_IRQ_CFG_IRQ_CLK_SELECT                        0x00000002
#define LAN9353_IRQ_CFG_IRQ_TYPE                              0x00000001

//Interrupt Status register
#define LAN9353_INT_STS_SW_INT                                0x80000000
#define LAN9353_INT_STS_READY                                 0x40000000
#define LAN9353_INT_STS_1588_EVNT                             0x20000000
#define LAN9353_INT_STS_SWITCH_INT                            0x10000000
#define LAN9353_INT_STS_PHY_INT_B                             0x08000000
#define LAN9353_INT_STS_PHY_INT_A                             0x04000000
#define LAN9353_INT_STS_GPT_INT                               0x00080000
#define LAN9353_INT_STS_PME_INT                               0x00020000
#define LAN9353_INT_STS_GPIO                                  0x00001000

//Interrupt Enable register
#define LAN9353_INT_EN_SW_INT_EN                              0x80000000
#define LAN9353_INT_EN_READY_EN                               0x40000000
#define LAN9353_INT_EN_1588_EVNT_EN                           0x20000000
#define LAN9353_INT_EN_SWITCH_INT_EN                          0x10000000
#define LAN9353_INT_EN_PHY_INT_B_EN                           0x08000000
#define LAN9353_INT_EN_PHY_INT_A_EN                           0x04000000
#define LAN9353_INT_EN_GPT_INT_EN                             0x00080000
#define LAN9353_INT_EN_GPIO_EN                                0x00001000

//Byte Order Test register
#define LAN9353_BYTE_TEST_DEFAULT                             0x87654321

//Hardware Configuration register
#define LAN9353_HW_CFG_DEVICE_READY                           0x08000000
#define LAN9353_HW_CFG_AMDIX_EN_STRAP_STATE_PORT_B            0x04000000
#define LAN9353_HW_CFG_AMDIX_EN_STRAP_STATE_PORT_A            0x02000000

//General Purpose Timer Configuration register
#define LAN9353_GPT_CFG_TIMER_EN                              0x20000000
#define LAN9353_GPT_CFG_GPT_LOAD                              0x0000FFFF

//General Purpose Timer Count register
#define LAN9353_GPT_CNT_GPT_CNT                               0x0000FFFF

//Free Running 25MHz Counter register
#define LAN9353_FREE_RUN_FR_CNT                               0xFFFFFFFF

//PHY Management Interface Data register
#define LAN9353_PMI_DATA_MII_DATA                             0x0000FFFF

//PHY Management Interface Access register
#define LAN9353_PMI_ACCESS_PHY_ADDR                           0x0000F800
#define LAN9353_PMI_ACCESS_MIIRINDA                           0x000007C0
#define LAN9353_PMI_ACCESS_MIIW_R                             0x00000002
#define LAN9353_PMI_ACCESS_MIIBZY                             0x00000001

//Port 1 Virtual PHY Basic Control register
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_RST                    0x00008000
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_LOOPBACK               0x00004000
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_SPEED_SEL_LSB          0x00002000
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_AN                     0x00001000
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_PWR_DWN                0x00000800
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_ISO                    0x00000400
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_RST_AN                 0x00000200
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_DUPLEX                 0x00000100
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_COL_TEST               0x00000080
#define LAN9353_VPHY_BASIC_CTRL_1_VPHY_SPEED_SEL_MSB          0x00000040

//Port 1 Virtual PHY Basic Status register
#define LAN9353_VPHY_BASIC_STATUS_1_100BT4                    0x00008000
#define LAN9353_VPHY_BASIC_STATUS_1_100BTX_FD                 0x00004000
#define LAN9353_VPHY_BASIC_STATUS_1_100BTX_HD                 0x00002000
#define LAN9353_VPHY_BASIC_STATUS_1_10BT_FD                   0x00001000
#define LAN9353_VPHY_BASIC_STATUS_1_10BT_HD                   0x00000800
#define LAN9353_VPHY_BASIC_STATUS_1_100BT2_FD                 0x00000400
#define LAN9353_VPHY_BASIC_STATUS_1_100BT2_HD                 0x00000200
#define LAN9353_VPHY_BASIC_STATUS_1_EXTENDED_STATUS           0x00000100
#define LAN9353_VPHY_BASIC_STATUS_1_MF_PREAMBLE_SUPPR         0x00000040
#define LAN9353_VPHY_BASIC_STATUS_1_AN_COMPLETE               0x00000020
#define LAN9353_VPHY_BASIC_STATUS_1_REMOTE_FAULT              0x00000010
#define LAN9353_VPHY_BASIC_STATUS_1_AN_CAPABLE                0x00000008
#define LAN9353_VPHY_BASIC_STATUS_1_LINK_STATUS               0x00000004
#define LAN9353_VPHY_BASIC_STATUS_1_JABBER_DETECT             0x00000002
#define LAN9353_VPHY_BASIC_STATUS_1_EXTENDED_CAPABLE          0x00000001

//Port 1 Virtual PHY Identification MSB register
#define LAN9353_VPHY_ID_MSB_1_PHY_ID_MSB                      0x0000FFFF

//Port 1 Virtual PHY Identification LSB register
#define LAN9353_VPHY_ID_LSB_1_PHY_ID_LSB                      0x0000FC00
#define LAN9353_VPHY_ID_LSB_1_MODEL_NUM                       0x000003F0
#define LAN9353_VPHY_ID_LSB_1_REVISION_NUM                    0x0000000F

//Port 1 Virtual PHY Auto-Negotiation Advertisement register
#define LAN9353_VPHY_AN_ADV_1_NEXT_PAGE                       0x00008000
#define LAN9353_VPHY_AN_ADV_1_REMOTE_FAULT                    0x00002000
#define LAN9353_VPHY_AN_ADV_1_ASYM_PAUSE                      0x00000800
#define LAN9353_VPHY_AN_ADV_1_SYM_PAUSE                       0x00000400
#define LAN9353_VPHY_AN_ADV_1_100BTX_FD                       0x00000100
#define LAN9353_VPHY_AN_ADV_1_100BTX_HD                       0x00000080
#define LAN9353_VPHY_AN_ADV_1_10BT_FD                         0x00000040
#define LAN9353_VPHY_AN_ADV_1_10BT_HD                         0x00000020
#define LAN9353_VPHY_AN_ADV_1_SELECTOR                        0x0000001F
#define LAN9353_VPHY_AN_ADV_1_SELECTOR_DEFAULT                0x00000001

//Port 1 Virtual PHY Auto-Negotiation Link Partner Base Page Ability register
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_NEXT_PAGE           0x00008000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_ACK                 0x00004000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_REMOTE_FAULT        0x00002000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_ASYM_PAUSE          0x00000800
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_SYM_PAUSE           0x00000400
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_100BT4              0x00000200
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_100BTX_FD           0x00000100
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_100BTX_HD           0x00000080
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_10BT_FD             0x00000040
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_10BT_HD             0x00000020
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_SELECTOR            0x0000001F
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_1_SELECTOR_DEFAULT    0x00000001

//Port 1 Virtual PHY Auto-Negotiation Expansion register
#define LAN9353_VPHY_AN_EXP_1_PAR_DETECT_FAULT                0x00000010
#define LAN9353_VPHY_AN_EXP_1_LP_NEXT_PAGE_ABLE               0x00000008
#define LAN9353_VPHY_AN_EXP_1_NEXT_PAGE_ABLE                  0x00000004
#define LAN9353_VPHY_AN_EXP_1_PAGE_RECEIVED                   0x00000002
#define LAN9353_VPHY_AN_EXP_1_LP_AN_ABLE                      0x00000001

//Port 1 Virtual PHY Special Control/Status register
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE2              0x00008000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_SW_LOOPBACK        0x00004000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_TURBO_MODE_EN      0x00000400
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE               0x00000300
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE_MII_MAC       0x00000000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE_MII_PHY       0x00000100
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE_RMII_MAC      0x00000200
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_MODE_RMII_PHY      0x00000300
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_SW_COL_TEST        0x00000080
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_RMII_CLK_DIR       0x00000040
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_RMII_CLK_DIR_IN    0x00000000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_RMII_CLK_DIR_OUT   0x00000040
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_RMII_CLK_STRENGTH  0x00000020
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_IND                0x0000001C
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_IND_10_HD          0x00000004
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_IND_100_200_HD     0x00000008
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_IND_10_FD          0x00000014
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_IND_100_200_FD     0x00000018
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_1_SQEOFF             0x00000001

//Port 1 Manual Flow Control register
#define LAN9353_MANUAL_FC_1_BP_EN_1                           0x00000040
#define LAN9353_MANUAL_FC_1_CUR_DUP_1                         0x00000020
#define LAN9353_MANUAL_FC_1_CUR_RX_FC_1                       0x00000010
#define LAN9353_MANUAL_FC_1_CUR_TX_FC_1                       0x00000008
#define LAN9353_MANUAL_FC_1_RX_FC_1                           0x00000004
#define LAN9353_MANUAL_FC_1_TX_FC_1                           0x00000002
#define LAN9353_MANUAL_FC_1_MANUAL_FC_1                       0x00000001

//Port 2 Manual Flow Control register
#define LAN9353_MANUAL_FC_2_BP_EN_2                           0x00000040
#define LAN9353_MANUAL_FC_2_CUR_DUP_2                         0x00000020
#define LAN9353_MANUAL_FC_2_CUR_RX_FC_2                       0x00000010
#define LAN9353_MANUAL_FC_2_CUR_TX_FC_2                       0x00000008
#define LAN9353_MANUAL_FC_2_RX_FC_2                           0x00000004
#define LAN9353_MANUAL_FC_2_TX_FC_2                           0x00000002
#define LAN9353_MANUAL_FC_2_MANUAL_FC_2                       0x00000001

//Port 0 Manual Flow Control register
#define LAN9353_MANUAL_FC_0_BP_EN_0                           0x00000040
#define LAN9353_MANUAL_FC_0_CUR_DUP_0                         0x00000020
#define LAN9353_MANUAL_FC_0_CUR_RX_FC_0                       0x00000010
#define LAN9353_MANUAL_FC_0_CUR_TX_FC_0                       0x00000008
#define LAN9353_MANUAL_FC_0_RX_FC_0                           0x00000004
#define LAN9353_MANUAL_FC_0_TX_FC_0                           0x00000002
#define LAN9353_MANUAL_FC_0_MANUAL_FC_0                       0x00000001

//Switch Fabric CSR Interface Command register
#define LAN9353_SWITCH_CSR_CMD_BUSY                           0x80000000
#define LAN9353_SWITCH_CSR_CMD_WRITE                          0x00000000
#define LAN9353_SWITCH_CSR_CMD_READ                           0x40000000
#define LAN9353_SWITCH_CSR_CMD_AUTO_INC                       0x20000000
#define LAN9353_SWITCH_CSR_CMD_AUTO_DEC                       0x10000000
#define LAN9353_SWITCH_CSR_CMD_BE                             0x000F0000
#define LAN9353_SWITCH_CSR_CMD_BE_0                           0x00010000
#define LAN9353_SWITCH_CSR_CMD_BE_1                           0x00020000
#define LAN9353_SWITCH_CSR_CMD_BE_2                           0x00040000
#define LAN9353_SWITCH_CSR_CMD_BE_3                           0x00080000
#define LAN9353_SWITCH_CSR_CMD_ADDR                           0x0000FFFF

//EEPROM Command register
#define LAN9353_E2P_CMD_EPC_BUSY                              0x80000000
#define LAN9353_E2P_CMD_EPC_COMMAND                           0x70000000
#define LAN9353_E2P_CMD_EPC_COMMAND_READ                      0x00000000
#define LAN9353_E2P_CMD_EPC_COMMAND_WRITE                     0x30000000
#define LAN9353_E2P_CMD_EPC_COMMAND_RELOAD                    0x70000000
#define LAN9353_E2P_CMD_LOADER_OVERFLOW                       0x00040000
#define LAN9353_E2P_CMD_EPC_TIMEOUT                           0x00020000
#define LAN9353_E2P_CMD_CFG_LOADED                            0x00010000
#define LAN9353_E2P_CMD_EPC_ADDR                              0x0000FFFF

//EEPROM Data register
#define LAN9353_E2P_DATA_EEPROM_DATA                          0x000000FF

//LED Configuration register
#define LAN9353_LED_CFG_LED_FUN                               0x00000700
#define LAN9353_LED_CFG_LED_FUN_0                             0x00000000
#define LAN9353_LED_CFG_LED_FUN_1                             0x00000100
#define LAN9353_LED_CFG_LED_FUN_2                             0x00000200
#define LAN9353_LED_CFG_LED_FUN_3                             0x00000300
#define LAN9353_LED_CFG_LED_FUN_4                             0x00000400
#define LAN9353_LED_CFG_LED_FUN_5                             0x00000500
#define LAN9353_LED_CFG_LED_FUN_RESERVED                      0x00000600
#define LAN9353_LED_CFG_LED_FUN_7                             0x00000700
#define LAN9353_LED_CFG_LED_EN                                0x0000003F
#define LAN9353_LED_CFG_LED_EN_0                              0x00000001
#define LAN9353_LED_CFG_LED_EN_1                              0x00000002
#define LAN9353_LED_CFG_LED_EN_2                              0x00000004
#define LAN9353_LED_CFG_LED_EN_3                              0x00000008
#define LAN9353_LED_CFG_LED_EN_4                              0x00000010
#define LAN9353_LED_CFG_LED_EN_5                              0x00000020

//Port 0 Virtual PHY Basic Control register
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_RST                    0x00008000
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_LOOPBACK               0x00004000
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_SPEED_SEL_LSB          0x00002000
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_AN                     0x00001000
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_PWR_DWN                0x00000800
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_ISO                    0x00000400
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_RST_AN                 0x00000200
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_DUPLEX                 0x00000100
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_COL_TEST               0x00000080
#define LAN9353_VPHY_BASIC_CTRL_0_VPHY_SPEED_SEL_MSB          0x00000040

//Port 0 Virtual PHY Basic Status register
#define LAN9353_VPHY_BASIC_STATUS_0_100BT4                    0x00008000
#define LAN9353_VPHY_BASIC_STATUS_0_100BTX_FD                 0x00004000
#define LAN9353_VPHY_BASIC_STATUS_0_100BTX_HD                 0x00002000
#define LAN9353_VPHY_BASIC_STATUS_0_10BT_FD                   0x00001000
#define LAN9353_VPHY_BASIC_STATUS_0_10BT_HD                   0x00000800
#define LAN9353_VPHY_BASIC_STATUS_0_100BT2_FD                 0x00000400
#define LAN9353_VPHY_BASIC_STATUS_0_100BT2_HD                 0x00000200
#define LAN9353_VPHY_BASIC_STATUS_0_EXTENDED_STATUS           0x00000100
#define LAN9353_VPHY_BASIC_STATUS_0_MF_PREAMBLE_SUPPR         0x00000040
#define LAN9353_VPHY_BASIC_STATUS_0_AN_COMPLETE               0x00000020
#define LAN9353_VPHY_BASIC_STATUS_0_REMOTE_FAULT              0x00000010
#define LAN9353_VPHY_BASIC_STATUS_0_AN_CAPABLE                0x00000008
#define LAN9353_VPHY_BASIC_STATUS_0_LINK_STATUS               0x00000004
#define LAN9353_VPHY_BASIC_STATUS_0_JABBER_DETECT             0x00000002
#define LAN9353_VPHY_BASIC_STATUS_0_EXTENDED_CAPABLE          0x00000001

//Port 0 Virtual PHY Identification MSB register
#define LAN9353_VPHY_ID_MSB_0_PHY_ID_MSB                      0x0000FFFF

//Port 0 Virtual PHY Identification LSB register
#define LAN9353_VPHY_ID_LSB_0_PHY_ID_LSB                      0x0000FC00
#define LAN9353_VPHY_ID_LSB_0_MODEL_NUM                       0x000003F0
#define LAN9353_VPHY_ID_LSB_0_REVISION_NUM                    0x0000000F

//Port 0 Virtual PHY Auto-Negotiation Advertisement register
#define LAN9353_VPHY_AN_ADV_0_NEXT_PAGE                       0x00008000
#define LAN9353_VPHY_AN_ADV_0_REMOTE_FAULT                    0x00002000
#define LAN9353_VPHY_AN_ADV_0_ASYM_PAUSE                      0x00000800
#define LAN9353_VPHY_AN_ADV_0_SYM_PAUSE                       0x00000400
#define LAN9353_VPHY_AN_ADV_0_100BTX_FD                       0x00000100
#define LAN9353_VPHY_AN_ADV_0_100BTX_HD                       0x00000080
#define LAN9353_VPHY_AN_ADV_0_10BT_FD                         0x00000040
#define LAN9353_VPHY_AN_ADV_0_10BT_HD                         0x00000020
#define LAN9353_VPHY_AN_ADV_0_SELECTOR                        0x0000001F
#define LAN9353_VPHY_AN_ADV_0_SELECTOR_DEFAULT                0x00000001

//Port 0 Virtual PHY Auto-Negotiation Link Partner Base Page Ability register
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_NEXT_PAGE           0x00008000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_ACK                 0x00004000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_REMOTE_FAULT        0x00002000
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_ASYM_PAUSE          0x00000800
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_SYM_PAUSE           0x00000400
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_100BT4              0x00000200
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_100BTX_FD           0x00000100
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_100BTX_HD           0x00000080
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_10BT_FD             0x00000040
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_10BT_HD             0x00000020
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_SELECTOR            0x0000001F
#define LAN9353_VPHY_AN_LP_BASE_ABILITY_0_SELECTOR_DEFAULT    0x00000001

//Port 0 Virtual PHY Auto-Negotiation Expansion register
#define LAN9353_VPHY_AN_EXP_0_PAR_DETECT_FAULT                0x00000010
#define LAN9353_VPHY_AN_EXP_0_LP_NEXT_PAGE_ABLE               0x00000008
#define LAN9353_VPHY_AN_EXP_0_NEXT_PAGE_ABLE                  0x00000004
#define LAN9353_VPHY_AN_EXP_0_PAGE_RECEIVED                   0x00000002
#define LAN9353_VPHY_AN_EXP_0_LP_AN_ABLE                      0x00000001

//Port 0 Virtual PHY Special Control/Status register
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE2              0x00008000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_SW_LOOPBACK        0x00004000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_TURBO_MODE_EN      0x00000400
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE               0x00000300
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE_MII_MAC       0x00000000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE_MII_PHY       0x00000100
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE_RMII_MAC      0x00000200
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_MODE_RMII_PHY      0x00000300
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_SW_COL_TEST        0x00000080
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_RMII_CLK_DIR       0x00000040
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_RMII_CLK_DIR_IN    0x00000000
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_RMII_CLK_DIR_OUT   0x00000040
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_RMII_CLK_STRENGTH  0x00000020
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_IND                0x0000001C
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_IND_10_HD          0x00000004
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_IND_100_200_HD     0x00000008
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_IND_10_FD          0x00000014
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_IND_100_200_FD     0x00000018
#define LAN9353_VPHY_SPECIAL_CTRL_STATUS_0_SQEOFF             0x00000001

//General Purpose I/O Configuration register
#define LAN9353_GPIO_CFG_GPIO_CH_SEL                          0xFF000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_0                        0x01000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_1                        0x02000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_2                        0x04000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_3                        0x08000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_4                        0x10000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_5                        0x20000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_6                        0x40000000
#define LAN9353_GPIO_CFG_GPIO_CH_SEL_7                        0x80000000
#define LAN9353_GPIO_CFG_GPIO_INT_POL                         0x00FF0000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_0                       0x00010000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_1                       0x00020000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_2                       0x00040000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_3                       0x00080000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_4                       0x00100000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_5                       0x00200000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_6                       0x00400000
#define LAN9353_GPIO_CFG_GPIO_INT_POL_7                       0x00800000
#define LAN9353_GPIO_CFG_1588_GPIO_OE                         0x0000FF00
#define LAN9353_GPIO_CFG_1588_GPIO_OE_0                       0x00000100
#define LAN9353_GPIO_CFG_1588_GPIO_OE_1                       0x00000200
#define LAN9353_GPIO_CFG_1588_GPIO_OE_2                       0x00000400
#define LAN9353_GPIO_CFG_1588_GPIO_OE_3                       0x00000800
#define LAN9353_GPIO_CFG_1588_GPIO_OE_4                       0x00001000
#define LAN9353_GPIO_CFG_1588_GPIO_OE_5                       0x00002000
#define LAN9353_GPIO_CFG_1588_GPIO_OE_6                       0x00004000
#define LAN9353_GPIO_CFG_1588_GPIO_OE_7                       0x00008000
#define LAN9353_GPIO_CFG_GPIOBUF                              0x000000FF
#define LAN9353_GPIO_CFG_GPIOBUF_0                            0x00000001
#define LAN9353_GPIO_CFG_GPIOBUF_1                            0x00000002
#define LAN9353_GPIO_CFG_GPIOBUF_2                            0x00000004
#define LAN9353_GPIO_CFG_GPIOBUF_3                            0x00000008
#define LAN9353_GPIO_CFG_GPIOBUF_4                            0x00000010
#define LAN9353_GPIO_CFG_GPIOBUF_5                            0x00000020
#define LAN9353_GPIO_CFG_GPIOBUF_6                            0x00000040
#define LAN9353_GPIO_CFG_GPIOBUF_7                            0x00000080

//General Purpose I/O Data and Direction register
#define LAN9353_GPIO_DATA_DIR_GPDIR                           0x00FF0000
#define LAN9353_GPIO_DATA_DIR_GPDIR_0                         0x00010000
#define LAN9353_GPIO_DATA_DIR_GPDIR_1                         0x00020000
#define LAN9353_GPIO_DATA_DIR_GPDIR_2                         0x00040000
#define LAN9353_GPIO_DATA_DIR_GPDIR_3                         0x00080000
#define LAN9353_GPIO_DATA_DIR_GPDIR_4                         0x00100000
#define LAN9353_GPIO_DATA_DIR_GPDIR_5                         0x00200000
#define LAN9353_GPIO_DATA_DIR_GPDIR_6                         0x00400000
#define LAN9353_GPIO_DATA_DIR_GPDIR_7                         0x00800000
#define LAN9353_GPIO_DATA_DIR_GPIOD                           0x000000FF
#define LAN9353_GPIO_DATA_DIR_GPIOD_0                         0x00000001
#define LAN9353_GPIO_DATA_DIR_GPIOD_1                         0x00000002
#define LAN9353_GPIO_DATA_DIR_GPIOD_2                         0x00000004
#define LAN9353_GPIO_DATA_DIR_GPIOD_3                         0x00000008
#define LAN9353_GPIO_DATA_DIR_GPIOD_4                         0x00000010
#define LAN9353_GPIO_DATA_DIR_GPIOD_5                         0x00000020
#define LAN9353_GPIO_DATA_DIR_GPIOD_6                         0x00000040
#define LAN9353_GPIO_DATA_DIR_GPIOD_7                         0x00000080

//General Purpose I/O Interrupt Status and Enable register
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN                   0x00FF0000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_0                 0x00010000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_1                 0x00020000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_2                 0x00040000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_3                 0x00080000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_4                 0x00100000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_5                 0x00200000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_6                 0x00400000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_EN_7                 0x00800000
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT                      0x000000FF
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_0                    0x00000001
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_1                    0x00000002
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_2                    0x00000004
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_3                    0x00000008
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_4                    0x00000010
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_5                    0x00000020
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_6                    0x00000040
#define LAN9353_GPIO_INT_STS_EN_GPIO_INT_7                    0x00000080

//Switch Fabric MAC Address High register
#define LAN9353_SWITCH_MAC_ADDRH_DIFF_PAUSE_ADDR              0x00400000
#define LAN9353_SWITCH_MAC_ADDRH_PORT2_PHY_ADDR_41_40         0x00300000
#define LAN9353_SWITCH_MAC_ADDRH_PORT1_PHY_ADDR_41_40         0x000C0000
#define LAN9353_SWITCH_MAC_ADDRH_PORT0_PHY_ADDR_41_40         0x00030000
#define LAN9353_SWITCH_MAC_ADDRH_PHY_ADDR_47_32               0x0000FFFF

//Switch Fabric MAC Address Low register
#define LAN9353_SWITCH_MAC_ADDRL_PHY_ADDR_31_0                0xFFFFFFFF

//Reset Control register
#define LAN9353_RESET_CTL_VPHY_1_RST                          0x00000010
#define LAN9353_RESET_CTL_VPHY_0_RST                          0x00000008
#define LAN9353_RESET_CTL_PHY_B_RST                           0x00000004
#define LAN9353_RESET_CTL_PHY_A_RST                           0x00000002
#define LAN9353_RESET_CTL_DIGITAL_RST                         0x00000001

//Switch Device ID register
#define LAN9353_SW_DEV_ID_DEVICE_TYPE                         0x00FF0000
#define LAN9353_SW_DEV_ID_DEVICE_TYPE_DEFAULT                 0x00030000
#define LAN9353_SW_DEV_ID_CHIP_VERSION                        0x0000FF00
#define LAN9353_SW_DEV_ID_CHIP_VERSION_DEFAULT                0x00000600
#define LAN9353_SW_DEV_ID_REVISION                            0x000000FF
#define LAN9353_SW_DEV_ID_REVISION_DEFAULT                    0x00000007

//Switch Reset register
#define LAN9353_SW_RESET_SW_RESET                             0x00000001

//Switch Global Interrupt Mask register
#define LAN9353_SW_IMR_BM                                     0x00000040
#define LAN9353_SW_IMR_SWE                                    0x00000020
#define LAN9353_SW_IMR_MAC2                                   0x00000004
#define LAN9353_SW_IMR_MAC1                                   0x00000002
#define LAN9353_SW_IMR_MAC0                                   0x00000001

//Switch Global Interrupt Pending register
#define LAN9353_SW_IPR_BM                                     0x00000040
#define LAN9353_SW_IPR_SWE                                    0x00000020
#define LAN9353_SW_IPR_MAC2                                   0x00000004
#define LAN9353_SW_IPR_MAC1                                   0x00000002
#define LAN9353_SW_IPR_MAC0                                   0x00000001

//Port x MAC Version ID register
#define LAN9353_MAC_VER_ID_DEVICE_TYPE                        0x00000F00
#define LAN9353_MAC_VER_ID_DEVICE_TYPE_DEFAULT                0x00000500
#define LAN9353_MAC_VER_ID_CHIP_VERSION                       0x000000F0
#define LAN9353_MAC_VER_ID_CHIP_VERSION_DEFAULT               0x00000090
#define LAN9353_MAC_VER_ID_REVISION                           0x0000000F
#define LAN9353_MAC_VER_ID_REVISION_DEFAULT                   0x00000003

//Port x MAC Receive Configuration register
#define LAN9353_MAC_RX_CFG_RECEIVE_OWN_TRANSMIT_EN            0x00000020
#define LAN9353_MAC_RX_CFG_JUMBO_2K                           0x00000008
#define LAN9353_MAC_RX_CFG_REJECT_MAC_TYPES                   0x00000002
#define LAN9353_MAC_RX_CFG_RX_EN                              0x00000001

//Port x MAC Transmit Configuration register
#define LAN9353_MAC_TX_CFG_EEE_EN                             0x00000100
#define LAN9353_MAC_TX_CFG_MAC_COUNTER_TEST                   0x00000080
#define LAN9353_MAC_TX_CFG_IFG_CONFIG                         0x0000007C
#define LAN9353_MAC_TX_CFG_IFG_CONFIG_DEFAULT                 0x00000054
#define LAN9353_MAC_TX_CFG_TX_PAD_EN                          0x00000002
#define LAN9353_MAC_TX_CFG_TX_EN                              0x00000001

//Switch Engine ALR Command register
#define LAN9353_SWE_ALR_CMD_MAKE_ENTRY                        0x00000004
#define LAN9353_SWE_ALR_CMD_GET_FIRST_ENTRY                   0x00000002
#define LAN9353_SWE_ALR_CMD_GET_NEXT_ENTRY                    0x00000001

//Switch Engine ALR Write Data 0 register
#define LAN9353_SWE_ALR_WR_DAT_0_MAC_ADDR                     0xFFFFFFFF

//Switch Engine ALR Write Data 1 register
#define LAN9353_SWE_ALR_WR_DAT_1_VALID                        0x04000000
#define LAN9353_SWE_ALR_WR_DAT_1_AGE1_OVERRIDE                0x02000000
#define LAN9353_SWE_ALR_WR_DAT_1_STATIC                       0x01000000
#define LAN9353_SWE_ALR_WR_DAT_1_AGE0_FILTER                  0x00800000
#define LAN9353_SWE_ALR_WR_DAT_1_PRIORITY_EN                  0x00400000
#define LAN9353_SWE_ALR_WR_DAT_1_PRIORITY                     0x00380000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT                         0x00070000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_0                       0x00000000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_1                       0x00010000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_2                       0x00020000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_RESERVED                0x00030000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_0_1                     0x00040000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_0_2                     0x00050000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_1_2                     0x00060000
#define LAN9353_SWE_ALR_WR_DAT_1_PORT_0_1_2                   0x00070000
#define LAN9353_SWE_ALR_WR_DAT_1_MAC_ADDR                     0x0000FFFF

//Switch Engine ALR Read Data 0 register
#define LAN9353_SWE_ALR_RD_DAT_0_MAC_ADDR                     0xFFFFFFFF

//Switch Engine ALR Read Data 1 register
#define LAN9353_SWE_ALR_RD_DAT_1_END_OF_TABLE                 0x08000000
#define LAN9353_SWE_ALR_RD_DAT_1_VALID                        0x04000000
#define LAN9353_SWE_ALR_RD_DAT_1_AGE1_OVERRIDE                0x02000000
#define LAN9353_SWE_ALR_RD_DAT_1_STATIC                       0x01000000
#define LAN9353_SWE_ALR_RD_DAT_1_AGE0_FILTER                  0x00800000
#define LAN9353_SWE_ALR_RD_DAT_1_PRIORITY_EN                  0x00400000
#define LAN9353_SWE_ALR_RD_DAT_1_PRIORITY                     0x00380000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT                         0x00070000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_0                       0x00000000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_1                       0x00010000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_2                       0x00020000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_RESERVED                0x00030000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_0_1                     0x00040000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_0_2                     0x00050000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_1_2                     0x00060000
#define LAN9353_SWE_ALR_RD_DAT_1_PORT_0_1_2                   0x00070000
#define LAN9353_SWE_ALR_RD_DAT_1_MAC_ADDR                     0x0000FFFF

//Switch Engine ALR Command Status register
#define LAN9353_SWE_ALR_CMD_STS_ALR_INIT_DONE                 0x00000002
#define LAN9353_SWE_ALR_CMD_STS_OPERATION_PENDING             0x00000001

//Switch Engine ALR Configuration register
#define LAN9353_SWE_ALR_CFG_AGING_TIME                        0x0FFF0000
#define LAN9353_SWE_ALR_CFG_AGING_TIME_DEFAULT                0x01290000
#define LAN9353_SWE_ALR_CFG_ALLOW_BROADCAST                   0x00000004
#define LAN9353_SWE_ALR_CFG_ALR_AGE_EN                        0x00000002
#define LAN9353_SWE_ALR_CFG_ALR_AGE_TEST                      0x00000001

//Switch Engine ALR Override register
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT2           0x00000600
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT2_PORT0     0x00000000
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT2_PORT1     0x00000200
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT2_EN        0x00000100
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT1           0x00000060
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT1_PORT0     0x00000000
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT1_PORT2     0x00000040
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT1_EN        0x00000010
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT0           0x00000006
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT0_PORT1     0x00000002
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT0_PORT2     0x00000004
#define LAN9353_SWE_ALR_OVERRIDE_ALR_OVERRIDE_PORT0_EN        0x00000001

//Switch Engine VLAN Command register
#define LAN9353_SWE_VLAN_CMD_WRITE                            0x00000000
#define LAN9353_SWE_VLAN_CMD_READ                             0x00000020
#define LAN9353_SWE_VLAN_CMD_VLAN                             0x00000000
#define LAN9353_SWE_VLAN_CMD_PVID                             0x00000010
#define LAN9353_SWE_VLAN_CMD_VLAN_PORT                        0x0000000F

//Switch Engine Global Ingress Configuration register
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_OTHER_MLD_NEXT_HDR_EN   0x00020000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_ANY_HOP_BY_HOP_NEXT_HDR 0x00010000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_802_1Q_VLAN_DIS         0x00008000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_USE_TAG                 0x00004000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_ALLOW_MONITOR_ECHO      0x00002000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_MLD_IGMP_MONITOR_PORT   0x00001C00
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_MLD_IGMP_MONITOR_PORT_0 0x00000400
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_MLD_IGMP_MONITOR_PORT_1 0x00000800
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_MLD_IGMP_MONITOR_PORT_2 0x00001000
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_USE_IP                  0x00000200
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_MLD_MONITORING_EN       0x00000100
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_IGMP_MONITORING_EN      0x00000080
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_SWE_COUNTER_TEST        0x00000040
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_DA_HIGHEST_PRIORITY     0x00000020
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_FILTER_MULTICAST        0x00000010
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_DROP_UNKNOWN            0x00000008
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_USE_PRECEDENCE          0x00000004
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_VL_HIGHER_PRIORITY      0x00000002
#define LAN9353_SWE_GLOBAL_INGRSS_CFG_VLAN_EN                 0x00000001

//Switch Engine Port Ingress Configuration register
#define LAN9353_SWE_PORT_INGRSS_CFG_LEARN_ON_INGRESS          0x00000038
#define LAN9353_SWE_PORT_INGRSS_CFG_LEARN_ON_INGRESS_PORT0    0x00000000
#define LAN9353_SWE_PORT_INGRSS_CFG_LEARN_ON_INGRESS_PORT1    0x00000008
#define LAN9353_SWE_PORT_INGRSS_CFG_LEARN_ON_INGRESS_PORT2    0x00000010
#define LAN9353_SWE_PORT_INGRSS_CFG_MEMBERSHIP_CHECK          0x00000007
#define LAN9353_SWE_PORT_INGRSS_CFG_MEMBERSHIP_CHECK_PORT0    0x00000000
#define LAN9353_SWE_PORT_INGRSS_CFG_MEMBERSHIP_CHECK_PORT1    0x00000001
#define LAN9353_SWE_PORT_INGRSS_CFG_MEMBERSHIP_CHECK_PORT2    0x00000002

//Switch Engine Admit Only VLAN register
#define LAN9353_SWE_ADMT_ONLY_VLAN_ADMIT_ONLY_VLAN            0x00000007
#define LAN9353_SWE_ADMT_ONLY_VLAN_ADMIT_ONLY_VLAN_PORT0      0x00000001
#define LAN9353_SWE_ADMT_ONLY_VLAN_ADMIT_ONLY_VLAN_PORT1      0x00000002
#define LAN9353_SWE_ADMT_ONLY_VLAN_ADMIT_ONLY_VLAN_PORT2      0x00000004

//Switch Engine Port State register
#define LAN9353_SWE_PORT_STATE_PORT2                          0x00000030
#define LAN9353_SWE_PORT_STATE_PORT2_FORWARDING               0x00000000
#define LAN9353_SWE_PORT_STATE_PORT2_LISTENING                0x00000010
#define LAN9353_SWE_PORT_STATE_PORT2_LEARNING                 0x00000020
#define LAN9353_SWE_PORT_STATE_PORT2_DISABLED                 0x00000030
#define LAN9353_SWE_PORT_STATE_PORT1                          0x0000000C
#define LAN9353_SWE_PORT_STATE_PORT1_FORWARDING               0x00000000
#define LAN9353_SWE_PORT_STATE_PORT1_LISTENING                0x00000004
#define LAN9353_SWE_PORT_STATE_PORT1_LEARNING                 0x00000008
#define LAN9353_SWE_PORT_STATE_PORT1_DISABLED                 0x0000000C
#define LAN9353_SWE_PORT_STATE_PORT0                          0x00000003
#define LAN9353_SWE_PORT_STATE_PORT0_FORWARDING               0x00000000
#define LAN9353_SWE_PORT_STATE_PORT0_LISTENING                0x00000001
#define LAN9353_SWE_PORT_STATE_PORT0_LEARNING                 0x00000002
#define LAN9353_SWE_PORT_STATE_PORT0_DISABLED                 0x00000003

//Switch Engine Priority to Queue register
#define LAN9353_SWE_PRI_TO_QUE_PRIO_7_TRAFFIC_CLASS           0x0000C000
#define LAN9353_SWE_PRI_TO_QUE_PRIO_6_TRAFFIC_CLASS           0x00003000
#define LAN9353_SWE_PRI_TO_QUE_PRIO_5_TRAFFIC_CLASS           0x00000C00
#define LAN9353_SWE_PRI_TO_QUE_PRIO_4_TRAFFIC_CLASS           0x00000300
#define LAN9353_SWE_PRI_TO_QUE_PRIO_3_TRAFFIC_CLASS           0x000000C0
#define LAN9353_SWE_PRI_TO_QUE_PRIO_2_TRAFFIC_CLASS           0x00000030
#define LAN9353_SWE_PRI_TO_QUE_PRIO_1_TRAFFIC_CLASS           0x0000000C
#define LAN9353_SWE_PRI_TO_QUE_PRIO_0_TRAFFIC_CLASS           0x00000003

//Switch Engine Port Mirroring register
#define LAN9353_SWE_PORT_MIRROR_RX_MIRRORING_FILT_EN          0x00000100
#define LAN9353_SWE_PORT_MIRROR_SNIFFER_PORT                  0x000000E0
#define LAN9353_SWE_PORT_MIRROR_SNIFFER_PORT_0                0x00000020
#define LAN9353_SWE_PORT_MIRROR_SNIFFER_PORT_1                0x00000040
#define LAN9353_SWE_PORT_MIRROR_SNIFFER_PORT_2                0x00000080
#define LAN9353_SWE_PORT_MIRROR_MIRRORED_PORT                 0x0000001C
#define LAN9353_SWE_PORT_MIRROR_MIRRORED_PORT_0               0x00000004
#define LAN9353_SWE_PORT_MIRROR_MIRRORED_PORT_1               0x00000008
#define LAN9353_SWE_PORT_MIRROR_MIRRORED_PORT_2               0x00000010
#define LAN9353_SWE_PORT_MIRROR_RX_MIRRORING_EN               0x00000002
#define LAN9353_SWE_PORT_MIRROR_TX_MIRRORING_EN               0x00000001

//Switch Engine Ingress Port Type register
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT2                     0x00000030
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT2_DIS                 0x00000000
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT2_EN                  0x00000030
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT1                     0x0000000C
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT1_DIS                 0x00000000
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT1_EN                  0x0000000C
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT0                     0x00000003
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT0_DIS                 0x00000000
#define LAN9353_SWE_INGRSS_PORT_TYP_PORT0_EN                  0x00000003

//Buffer Manager Egress Port Type register
#define LAN9353_BM_EGRSS_PORT_TYPE_VID_SEL_PORT2              0x00400000
#define LAN9353_BM_EGRSS_PORT_TYPE_INSERT_TAG_PORT2           0x00200000
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_VID_PORT2           0x00100000
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_PRIO_PORT2          0x00080000
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_TAG_PORT2           0x00040000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT2_TYPE                 0x00030000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT2_TYPE_DUMB            0x00000000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT2_TYPE_ACCESS          0x00010000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT2_TYPE_HYBRID          0x00020000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT2_TYPE_CPU             0x00030000
#define LAN9353_BM_EGRSS_PORT_TYPE_VID_SEL_PORT1              0x00004000
#define LAN9353_BM_EGRSS_PORT_TYPE_INSERT_TAG_PORT1           0x00002000
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_VID_PORT1           0x00001000
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_PRIO_PORT1          0x00000800
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_TAG_PORT1           0x00000400
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT1_TYPE                 0x00000300
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT1_TYPE_DUMB            0x00000000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT1_TYPE_ACCESS          0x00000100
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT1_TYPE_HYBRID          0x00000200
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT1_TYPE_CPU             0x00000300
#define LAN9353_BM_EGRSS_PORT_TYPE_VID_SEL_PORT0              0x00000040
#define LAN9353_BM_EGRSS_PORT_TYPE_INSERT_TAG_PORT0           0x00000020
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_VID_PORT0           0x00000010
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_PRIO_PORT0          0x00000008
#define LAN9353_BM_EGRSS_PORT_TYPE_CHANGE_TAG_PORT0           0x00000004
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT0_TYPE                 0x00000003
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT0_TYPE_DUMB            0x00000000
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT0_TYPE_ACCESS          0x00000001
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT0_TYPE_HYBRID          0x00000002
#define LAN9353_BM_EGRSS_PORT_TYPE_PORT0_TYPE_CPU             0x00000003

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//LAN9353 Ethernet switch driver
extern const SwitchDriver lan9353SwitchDriver;

//LAN9353 related functions
error_t lan9353Init(NetInterface *interface);
void lan9353InitHook(NetInterface *interface);

void lan9353Tick(NetInterface *interface);

void lan9353EnableIrq(NetInterface *interface);
void lan9353DisableIrq(NetInterface *interface);

void lan9353EventHandler(NetInterface *interface);

error_t lan9353TagFrame(NetInterface *interface, NetBuffer *buffer,
   size_t *offset, NetTxAncillary *ancillary);

error_t lan9353UntagFrame(NetInterface *interface, uint8_t **frame,
   size_t *length, NetRxAncillary *ancillary);

bool_t lan9353GetLinkState(NetInterface *interface, uint8_t port);
uint32_t lan9353GetLinkSpeed(NetInterface *interface, uint8_t port);
NicDuplexMode lan9353GetDuplexMode(NetInterface *interface, uint8_t port);

void lan9353SetPortState(NetInterface *interface, uint8_t port,
   SwitchPortState state);

SwitchPortState lan9353GetPortState(NetInterface *interface, uint8_t port);

void lan9353SetAgingTime(NetInterface *interface, uint32_t agingTime);

void lan9353EnableIgmpSnooping(NetInterface *interface, bool_t enable);
void lan9353EnableMldSnooping(NetInterface *interface, bool_t enable);
void lan9353EnableRsvdMcastTable(NetInterface *interface, bool_t enable);

error_t lan9353AddStaticFdbEntry(NetInterface *interface,
   const SwitchFdbEntry *entry);

error_t lan9353DeleteStaticFdbEntry(NetInterface *interface,
   const SwitchFdbEntry *entry);

error_t lan9353GetStaticFdbEntry(NetInterface *interface, uint_t index,
   SwitchFdbEntry *entry);

void lan9353FlushStaticFdbTable(NetInterface *interface);

error_t lan9353GetDynamicFdbEntry(NetInterface *interface, uint_t index,
   SwitchFdbEntry *entry);

void lan9353FlushDynamicFdbTable(NetInterface *interface, uint8_t port);

void lan9353SetUnknownMcastFwdPorts(NetInterface *interface,
   bool_t enable, uint32_t forwardPorts);

void lan9353WritePhyReg(NetInterface *interface, uint8_t port,
   uint8_t address, uint16_t data);

uint16_t lan9353ReadPhyReg(NetInterface *interface, uint8_t port,
   uint8_t address);

void lan9353DumpPhyReg(NetInterface *interface, uint8_t port);

void lan9353WriteSysReg(NetInterface *interface, uint16_t address,
   uint32_t data);

uint32_t lan9353ReadSysReg(NetInterface *interface, uint16_t address);

void lan9353DumpSysReg(NetInterface *interface);

void lan9353WriteSwitchReg(NetInterface *interface, uint16_t address,
   uint32_t data);

uint32_t lan9353ReadSwitchReg(NetInterface *interface, uint16_t address);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
