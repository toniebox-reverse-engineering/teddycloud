/**
 * @file dp83867_driver.h
 * @brief DP83867 Gigabit Ethernet PHY driver
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

#ifndef _DP83867_DRIVER_H
#define _DP83867_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef DP83867_PHY_ADDR
   #define DP83867_PHY_ADDR 0
#elif (DP83867_PHY_ADDR < 0 || DP83867_PHY_ADDR > 31)
   #error DP83867_PHY_ADDR parameter is not valid
#endif

//DP83867 PHY registers
#define DP83867_BMCR                                       0x00
#define DP83867_BMSR                                       0x01
#define DP83867_PHYIDR1                                    0x02
#define DP83867_PHYIDR2                                    0x03
#define DP83867_ANAR                                       0x04
#define DP83867_ANLPAR                                     0x05
#define DP83867_ANER                                       0x06
#define DP83867_ANNPTR                                     0x07
#define DP83867_ANNPRR                                     0x08
#define DP83867_CFG1                                       0x09
#define DP83867_STS1                                       0x0A
#define DP83867_REGCR                                      0x0D
#define DP83867_ADDAR                                      0x0E
#define DP83867_1KSCR                                      0x0F
#define DP83867_PHYCR                                      0x10
#define DP83867_PHYSTS                                     0x11
#define DP83867_MICR                                       0x12
#define DP83867_MISR                                       0x13
#define DP83867_CFG2                                       0x14
#define DP83867_RECR                                       0x15
#define DP83867_BISCR                                      0x16
#define DP83867_STS2                                       0x17
#define DP83867_LEDCR1                                     0x18
#define DP83867_LEDCR2                                     0x19
#define DP83867_LEDCR3                                     0x1A
#define DP83867_CFG3                                       0x1E
#define DP83867_CTRL                                       0x1F

//DP83867 MMD registers
#define DP83867_TMCH_CTRL                                  0x1F, 0x0025
#define DP83867_AMDIX_TMR_CFG                              0x1F, 0x002C
#define DP83867_FLD_CFG                                    0x1F, 0x002D
#define DP83867_FLD_THR_CFG                                0x1F, 0x002E
#define DP83867_CFG4                                       0x1F, 0x0031
#define DP83867_RGMIICTL                                   0x1F, 0x0032
#define DP83867_RGMIICTL2                                  0x1F, 0x0033
#define DP83867_100CR                                      0x1F, 0x0043
#define DP83867_VTM_CFG                                    0x1F, 0x0053
#define DP83867_SKEW_FIFO                                  0x1F, 0x0055
#define DP83867_STRAP_STS1                                 0x1F, 0x006E
#define DP83867_STRAP_STS2                                 0x1F, 0x006F
#define DP83867_BICSR1                                     0x1F, 0x0071
#define DP83867_BICSR2                                     0x1F, 0x0072
#define DP83867_BICSR3                                     0x1F, 0x007B
#define DP83867_BICSR4                                     0x1F, 0x007C
#define DP83867_RGMIIDCTL                                  0x1F, 0x0086
#define DP83867_PLLCTL                                     0x1F, 0x00C6
#define DP83867_SYNC_FIFO_CTRL                             0x1F, 0x00E9
#define DP83867_LOOPCR                                     0x1F, 0x00FE
#define DP83867_DSP_FFE_CFG                                0x1F, 0x012C
#define DP83867_RXFCFG                                     0x1F, 0x0134
#define DP83867_RXFSTS                                     0x1F, 0x0135
#define DP83867_RXFPMD1                                    0x1F, 0x0136
#define DP83867_RXFPMD2                                    0x1F, 0x0137
#define DP83867_RXFPMD3                                    0x1F, 0x0138
#define DP83867_RXFSOP1                                    0x1F, 0x0139
#define DP83867_RXFSOP2                                    0x1F, 0x013A
#define DP83867_RXFSOP3                                    0x1F, 0x013B
#define DP83867_RXFPAT1                                    0x1F, 0x013C
#define DP83867_RXFPAT2                                    0x1F, 0x013D
#define DP83867_RXFPAT3                                    0x1F, 0x013E
#define DP83867_RXFPAT4                                    0x1F, 0x013F
#define DP83867_RXFPAT5                                    0x1F, 0x0140
#define DP83867_RXFPAT6                                    0x1F, 0x0141
#define DP83867_RXFPAT7                                    0x1F, 0x0142
#define DP83867_RXFPAT8                                    0x1F, 0x0143
#define DP83867_RXFPAT9                                    0x1F, 0x0144
#define DP83867_RXFPAT10                                   0x1F, 0x0145
#define DP83867_RXFPAT11                                   0x1F, 0x0146
#define DP83867_RXFPAT12                                   0x1F, 0x0147
#define DP83867_RXFPAT13                                   0x1F, 0x0148
#define DP83867_RXFPAT14                                   0x1F, 0x0149
#define DP83867_RXFPAT15                                   0x1F, 0x014A
#define DP83867_RXFPAT16                                   0x1F, 0x014B
#define DP83867_RXFPAT17                                   0x1F, 0x014C
#define DP83867_RXFPAT18                                   0x1F, 0x014D
#define DP83867_RXFPAT19                                   0x1F, 0x014E
#define DP83867_RXFPAT20                                   0x1F, 0x014F
#define DP83867_RXFPAT21                                   0x1F, 0x0150
#define DP83867_RXFPAT22                                   0x1F, 0x0151
#define DP83867_RXFPAT23                                   0x1F, 0x0152
#define DP83867_RXFPAT24                                   0x1F, 0x0153
#define DP83867_RXFPAT25                                   0x1F, 0x0154
#define DP83867_RXFPAT26                                   0x1F, 0x0155
#define DP83867_RXFPAT27                                   0x1F, 0x0156
#define DP83867_RXFPAT28                                   0x1F, 0x0157
#define DP83867_RXFPAT29                                   0x1F, 0x0158
#define DP83867_RXFPAT30                                   0x1F, 0x0159
#define DP83867_RXFPAT31                                   0x1F, 0x015A
#define DP83867_RXFPAT32                                   0x1F, 0x015B
#define DP83867_RXFPBM1                                    0x1F, 0x015C
#define DP83867_RXFPBM2                                    0x1F, 0x015D
#define DP83867_RXFPBM3                                    0x1F, 0x015E
#define DP83867_RXFPBM4                                    0x1F, 0x015F
#define DP83867_RXFPATC                                    0x1F, 0x0161
#define DP83867_IO_MUX_CFG                                 0x1F, 0x0170
#define DP83867_GPIO_MUX_CTRL1                             0x1F, 0x0171
#define DP83867_GPIO_MUX_CTRL2                             0x1F, 0x0172
#define DP83867_GPIO_MUX_CTRL                              0x1F, 0x0172
#define DP83867_TDR_GEN_CFG1                               0x1F, 0x0180
#define DP83867_TDR_PEAKS_LOC_1                            0x1F, 0x0190
#define DP83867_TDR_PEAKS_LOC_2                            0x1F, 0x0191
#define DP83867_TDR_PEAKS_LOC_3                            0x1F, 0x0192
#define DP83867_TDR_PEAKS_LOC_4                            0x1F, 0x0193
#define DP83867_TDR_PEAKS_LOC_5                            0x1F, 0x0194
#define DP83867_TDR_PEAKS_LOC_6                            0x1F, 0x0195
#define DP83867_TDR_PEAKS_LOC_7                            0x1F, 0x0196
#define DP83867_TDR_PEAKS_LOC_8                            0x1F, 0x0197
#define DP83867_TDR_PEAKS_LOC_9                            0x1F, 0x0198
#define DP83867_TDR_PEAKS_LOC_10                           0x1F, 0x0199
#define DP83867_TDR_PEAKS_AMP_1                            0x1F, 0x019A
#define DP83867_TDR_PEAKS_AMP_2                            0x1F, 0x019B
#define DP83867_TDR_PEAKS_AMP_3                            0x1F, 0x019C
#define DP83867_TDR_PEAKS_AMP_4                            0x1F, 0x019D
#define DP83867_TDR_PEAKS_AMP_5                            0x1F, 0x019E
#define DP83867_TDR_PEAKS_AMP_6                            0x1F, 0x019F
#define DP83867_TDR_PEAKS_AMP_7                            0x1F, 0x01A0
#define DP83867_TDR_PEAKS_AMP_8                            0x1F, 0x01A1
#define DP83867_TDR_PEAKS_AMP_9                            0x1F, 0x01A2
#define DP83867_TDR_PEAKS_AMP_10                           0x1F, 0x01A3
#define DP83867_PROG_GAIN                                  0x1F, 0x01D5

//Basic Mode Control register
#define DP83867_BMCR_RESET                                 0x8000
#define DP83867_BMCR_LOOPBACK                              0x4000
#define DP83867_BMCR_SPEED_SEL_LSB                         0x2000
#define DP83867_BMCR_AN_EN                                 0x1000
#define DP83867_BMCR_POWER_DOWN                            0x0800
#define DP83867_BMCR_ISOLATE                               0x0400
#define DP83867_BMCR_RESTART_AN                            0x0200
#define DP83867_BMCR_DUPLEX_MODE                           0x0100
#define DP83867_BMCR_COL_TEST                              0x0080
#define DP83867_BMCR_SPEED_SEL_MSB                         0x0040

//Basic Mode Status register
#define DP83867_BMSR_100BT4                                0x8000
#define DP83867_BMSR_100BTX_FD                             0x4000
#define DP83867_BMSR_100BTX_HD                             0x2000
#define DP83867_BMSR_10BT_FD                               0x1000
#define DP83867_BMSR_10BT_HD                               0x0800
#define DP83867_BMSR_100BT2_FD                             0x0400
#define DP83867_BMSR_100BT2_HD                             0x0200
#define DP83867_BMSR_EXTENDED_STATUS                       0x0100
#define DP83867_BMSR_MF_PREAMBLE_SUPPR                     0x0040
#define DP83867_BMSR_AN_COMPLETE                           0x0020
#define DP83867_BMSR_REMOTE_FAULT                          0x0010
#define DP83867_BMSR_AN_CAPABLE                            0x0008
#define DP83867_BMSR_LINK_STATUS                           0x0004
#define DP83867_BMSR_JABBER_DETECT                         0x0002
#define DP83867_BMSR_EXTENDED_CAPABLE                      0x0001

//PHY Identifier 1 register
#define DP83867_PHYIDR1_OUI_MSB                            0xFFFF
#define DP83867_PHYIDR1_OUI_MSB_DEFAULT                    0x2000

//PHY Identifier 2 register
#define DP83867_PHYIDR2_OUI_LSB                            0xFC00
#define DP83867_PHYIDR2_OUI_LSB_DEFAULT                    0xA000
#define DP83867_PHYIDR2_VNDR_MDL                           0x03F0
#define DP83867_PHYIDR2_VNDR_MDL_DEFAULT                   0x0230
#define DP83867_PHYIDR2_MDL_REV                            0x000F

//Auto-Negotiation Advertisement register
#define DP83867_ANAR_NEXT_PAGE                             0x8000
#define DP83867_ANAR_REMOTE_FAULT                          0x2000
#define DP83867_ANAR_ASM_DIR                               0x0800
#define DP83867_ANAR_PAUSE                                 0x0400
#define DP83867_ANAR_100BT4                                0x0200
#define DP83867_ANAR_100BTX_FD                             0x0100
#define DP83867_ANAR_100BTX_HD                             0x0080
#define DP83867_ANAR_10BT_FD                               0x0040
#define DP83867_ANAR_10BT_HD                               0x0020
#define DP83867_ANAR_SELECTOR                              0x001F
#define DP83867_ANAR_SELECTOR_DEFAULT                      0x0001

//Auto-Negotiation Link Partner Ability register
#define DP83867_ANLPAR_NEXT_PAGE                           0x8000
#define DP83867_ANLPAR_ACK                                 0x4000
#define DP83867_ANLPAR_REMOTE_FAULT                        0x2000
#define DP83867_ANLPAR_ASM_DIR                             0x0800
#define DP83867_ANLPAR_PAUSE                               0x0400
#define DP83867_ANLPAR_100BT4                              0x0200
#define DP83867_ANLPAR_100BTX_FD                           0x0100
#define DP83867_ANLPAR_100BTX_HD                           0x0080
#define DP83867_ANLPAR_10BT_FD                             0x0040
#define DP83867_ANLPAR_10BT_HD                             0x0020
#define DP83867_ANLPAR_SELECTOR                            0x001F

//Auto-Negotiation Expansion register
#define DP83867_ANER_RX_NEXT_PAGE_LOC_ABLE                 0x0040
#define DP83867_ANER_RX_NEXT_PAGE_STOR_LOC                 0x0020
#define DP83867_ANER_PAR_DETECT_FAULT                      0x0010
#define DP83867_ANER_LP_NP_ABLE                            0x0008
#define DP83867_ANER_NP_ABLE                               0x0004
#define DP83867_ANER_PAGE_RX                               0x0002
#define DP83867_ANER_LP_AN_ABLE                            0x0001

//Auto-Negotiation Next Page Transmit register
#define DP83867_ANNPTR_NEXT_PAGE                           0x8000
#define DP83867_ANNPTR_ACK                                 0x4000
#define DP83867_ANNPTR_MSG_PAGE                            0x2000
#define DP83867_ANNPTR_ACK2                                0x1000
#define DP83867_ANNPTR_TOGGLE                              0x0800
#define DP83867_ANNPTR_CODE                                0x07FF

//Auto-Negotiation Next Page Receive register
#define DP83867_ANNPRR_NEXT_PAGE                           0x8000
#define DP83867_ANNPRR_ACK                                 0x4000
#define DP83867_ANNPRR_MSG_PAGE                            0x2000
#define DP83867_ANNPRR_ACK2                                0x1000
#define DP83867_ANNPRR_TOGGLE                              0x0800
#define DP83867_ANNPRR_CODE                                0x07FF

//1000BASE-T Configuration register
#define DP83867_CFG1_TEST_MODE                             0xE000
#define DP83867_CFG1_MS_MAN_CONF_EN                        0x1000
#define DP83867_CFG1_MS_MAN_CONF_VAL                       0x0800
#define DP83867_CFG1_PORT_TYPE                             0x0400
#define DP83867_CFG1_1000BT_FD                             0x0200
#define DP83867_CFG1_1000BT_HD                             0x0100
#define DP83867_CFG1_TDR_AUTO_RUN                          0x0080

//Status 1 register
#define DP83867_STS1_MS_CONF_FAULT                         0x8000
#define DP83867_STS1_MS_CONF_RES                           0x4000
#define DP83867_STS1_LOCAL_RECEIVER_STATUS                 0x2000
#define DP83867_STS1_REMOTE_RECEIVER_STATUS                0x1000
#define DP83867_STS1_LP_1000BT_FD                          0x0800
#define DP83867_STS1_LP_1000BT_HD                          0x0400
#define DP83867_STS1_IDLE_ERR_COUNT                        0x00FF

//Register Control register
#define DP83867_REGCR_FUNC                                 0xC000
#define DP83867_REGCR_FUNC_ADDR                            0x0000
#define DP83867_REGCR_FUNC_DATA_NO_POST_INC                0x4000
#define DP83867_REGCR_FUNC_DATA_POST_INC_RW                0x8000
#define DP83867_REGCR_FUNC_DATA_POST_INC_W                 0xC000
#define DP83867_REGCR_DEVAD                                0x001F

//1000BASE-T Status register
#define DP83867_1KSCR_1000BX_FD                            0x8000
#define DP83867_1KSCR_1000BX_HD                            0x4000
#define DP83867_1KSCR_1000BT_FD                            0x2000
#define DP83867_1KSCR_1000BT_HD                            0x1000

//PHY Control register
#define DP83867_PHYCR_TX_FIFO_DEPTH                        0xC000
#define DP83867_PHYCR_FORCE_LINK_GOOD                      0x0400
#define DP83867_PHYCR_POWER_SAVE_MODE                      0x0300
#define DP83867_PHYCR_DEEP_POWER_DOWN_EN                   0x0080
#define DP83867_PHYCR_MDI_CROSSOVER                        0x0060
#define DP83867_PHYCR_DISABLE_CLK_125                      0x0010
#define DP83867_PHYCR_STANDBY_MODE                         0x0004
#define DP83867_PHYCR_LINE_DRIVER_INV_EN                   0x0002
#define DP83867_PHYCR_DISABLE_JABBER                       0x0001

//PHY Status register
#define DP83867_PHYSTS_SPEED_SEL                           0xC000
#define DP83867_PHYSTS_SPEED_SEL_10MBPS                    0x0000
#define DP83867_PHYSTS_SPEED_SEL_100MBPS                   0x4000
#define DP83867_PHYSTS_SPEED_SEL_1000MBPS                  0x8000
#define DP83867_PHYSTS_DUPLEX_MODE                         0x2000
#define DP83867_PHYSTS_PAGE_RECEIVED                       0x1000
#define DP83867_PHYSTS_SPEED_DUPLEX_RESOLVED               0x0800
#define DP83867_PHYSTS_LINK_STATUS                         0x0400
#define DP83867_PHYSTS_MDI_X_MODE_CD                       0x0200
#define DP83867_PHYSTS_MDI_X_MODE_AB                       0x0100
#define DP83867_PHYSTS_SPEED_OPT_STATUS                    0x0080
#define DP83867_PHYSTS_SLEEP_MODE                          0x0040
#define DP83867_PHYSTS_WIRE_CROSS                          0x003C
#define DP83867_PHYSTS_POLARITY_STATUS                     0x0002
#define DP83867_PHYSTS_JABBER_DETECT                       0x0001

//MII Interrupt Control register
#define DP83867_MICR_AUTONEG_ERR_INT_EN                    0x8000
#define DP83867_MICR_SPEED_CHNG_INT_EN                     0x4000
#define DP83867_MICR_DUPLEX_MODE_CHNG_INT_EN               0x2000
#define DP83867_MICR_PAGE_RECEIVED_INT_EN                  0x1000
#define DP83867_MICR_AUTONEG_COMP_INT_EN                   0x0800
#define DP83867_MICR_LINK_STATUS_CHNG_INT_EN               0x0400
#define DP83867_MICR_FALSE_CARRIER_INT_EN                  0x0100
#define DP83867_MICR_MDI_CROSSOVER_CHNG_INT_EN             0x0040
#define DP83867_MICR_SPEED_OPT_EVENT_INT_EN                0x0020
#define DP83867_MICR_SLEEP_MODE_CHNG_INT_EN                0x0010
#define DP83867_MICR_WOL_INT_EN                            0x0008
#define DP83867_MICR_XGMII_ERR_INT_EN                      0x0004
#define DP83867_MICR_POLARITY_CHNG_INT_EN                  0x0002
#define DP83867_MICR_JABBER_INT_EN                         0x0001

//MII Interrupt Status register
#define DP83867_MISR_AUTONEG_ERR_INT                       0x8000
#define DP83867_MISR_SPEED_CHNG_INT                        0x4000
#define DP83867_MISR_DUPLEX_MODE_CHNG_INT                  0x2000
#define DP83867_MISR_PAGE_RECEIVED_INT                     0x1000
#define DP83867_MISR_AUTONEG_COMP_INT                      0x0800
#define DP83867_MISR_LINK_STATUS_CHNG_INT                  0x0400
#define DP83867_MISR_FALSE_CARRIER_INT                     0x0100
#define DP83867_MISR_MDI_CROSSOVER_CHNG_INT                0x0040
#define DP83867_MISR_SPEED_OPT_EVENT_INT                   0x0020
#define DP83867_MISR_SLEEP_MODE_CHNG_INT                   0x0010
#define DP83867_MISR_WOL_INT                               0x0008
#define DP83867_MISR_XGMII_ERR_INT                         0x0004
#define DP83867_MISR_POLARITY_CHNG_INT                     0x0002
#define DP83867_MISR_JABBER_INT                            0x0001

//Configuration 2 register
#define DP83867_CFG2_INTERRUPT_POLARITY                    0x2000
#define DP83867_CFG2_SPEED_OPT_ATTEMPT_CNT                 0x0C00
#define DP83867_CFG2_SPEED_OPT_EN                          0x0200
#define DP83867_CFG2_SPEED_OPT_ENHANCED_EN                 0x0100
#define DP83867_CFG2_SPEED_OPT_10M_EN                      0x0040

//Receive Error Counter register
#define DP83867_RECR_RXERCNT                               0xFFFF

//BIST Control register
#define DP83867_BISCR_PRBS_COUNT_MODE                      0x8000
#define DP83867_BISCR_GEN_PRBS_PACKET                      0x4000
#define DP83867_BISCR_PACKET_GEN_64BIT_MODE                0x2000
#define DP83867_BISCR_PACKET_GEN_EN                        0x1000
#define DP83867_BISCR_REV_LOOP_RX_DATA_CTRL                0x0080
#define DP83867_BISCR_MII_LOOP_TX_DATA_CTRL                0x0040
#define DP83867_BISCR_LOOPBACK_MODE                        0x003C
#define DP83867_BISCR_PCS_LOOPBACK                         0x0003
#define DP83867_BISCR_PCS_LOOPBACK_BEFORE_SCRAMBLER        0x0001
#define DP83867_BISCR_PCS_LOOPBACK_AFTER_SCRAMBLER         0x0002
#define DP83867_BISCR_PCS_LOOPBACK_AFTER_MLT3_ENCODER      0x0003

//Status 2 register
#define DP83867_STS2_PRBS_LOCK                             0x0800
#define DP83867_STS2_PRBS_LOCK_LOST                        0x0400
#define DP83867_STS2_PKT_GEN_BUSY                          0x0200
#define DP83867_STS2_SCR_MODE_MASTER_1G                    0x0100
#define DP83867_STS2_SCR_MODE_SLAVE_1G                     0x0080
#define DP83867_STS2_CORE_PWR_MODE                         0x0040

//LED Configuration 1 register
#define DP83867_LEDCR1_LED_GPIO_SEL                        0xF000
#define DP83867_LEDCR1_LED_GPIO_SEL_LINK                   0x0000
#define DP83867_LEDCR1_LED_GPIO_SEL_ACT                    0x1000
#define DP83867_LEDCR1_LED_GPIO_SEL_TX_ACT                 0x2000
#define DP83867_LEDCR1_LED_GPIO_SEL_RX_ACT                 0x3000
#define DP83867_LEDCR1_LED_GPIO_SEL_COL                    0x4000
#define DP83867_LEDCR1_LED_GPIO_SEL_1000                   0x5000
#define DP83867_LEDCR1_LED_GPIO_SEL_100                    0x6000
#define DP83867_LEDCR1_LED_GPIO_SEL_10                     0x7000
#define DP83867_LEDCR1_LED_GPIO_SEL_10_100                 0x8000
#define DP83867_LEDCR1_LED_GPIO_SEL_100_1000               0x9000
#define DP83867_LEDCR1_LED_GPIO_SEL_FD                     0xA000
#define DP83867_LEDCR1_LED_GPIO_SEL_LINK_ACT               0xB000
#define DP83867_LEDCR1_LED_GPIO_SEL_ERR                    0xD000
#define DP83867_LEDCR1_LED_GPIO_SEL_RX_ERR                 0xE000
#define DP83867_LEDCR1_LED_2_SEL                           0x1F00
#define DP83867_LEDCR1_LED_2_SEL_LINK                      0x0000
#define DP83867_LEDCR1_LED_2_SEL_ACT                       0x0100
#define DP83867_LEDCR1_LED_2_SEL_TX_ACT                    0x0200
#define DP83867_LEDCR1_LED_2_SEL_RX_ACT                    0x0300
#define DP83867_LEDCR1_LED_2_SEL_COL                       0x0400
#define DP83867_LEDCR1_LED_2_SEL_1000                      0x0500
#define DP83867_LEDCR1_LED_2_SEL_100                       0x0600
#define DP83867_LEDCR1_LED_2_SEL_10                        0x0700
#define DP83867_LEDCR1_LED_2_SEL_10_100                    0x0800
#define DP83867_LEDCR1_LED_2_SEL_100_1000                  0x0900
#define DP83867_LEDCR1_LED_2_SEL_FD                        0x0A00
#define DP83867_LEDCR1_LED_2_SEL_LINK_ACT                  0x0B00
#define DP83867_LEDCR1_LED_2_SEL_ERR                       0x0D00
#define DP83867_LEDCR1_LED_2_SEL_RX_ERR                    0x0E00
#define DP83867_LEDCR1_LED_1_SEL                           0x00F0
#define DP83867_LEDCR1_LED_1_SEL_LINK                      0x0000
#define DP83867_LEDCR1_LED_1_SEL_ACT                       0x0010
#define DP83867_LEDCR1_LED_1_SEL_TX_ACT                    0x0020
#define DP83867_LEDCR1_LED_1_SEL_RX_ACT                    0x0030
#define DP83867_LEDCR1_LED_1_SEL_COL                       0x0040
#define DP83867_LEDCR1_LED_1_SEL_1000                      0x0050
#define DP83867_LEDCR1_LED_1_SEL_100                       0x0060
#define DP83867_LEDCR1_LED_1_SEL_10                        0x0070
#define DP83867_LEDCR1_LED_1_SEL_10_100                    0x0080
#define DP83867_LEDCR1_LED_1_SEL_100_1000                  0x0090
#define DP83867_LEDCR1_LED_1_SEL_FD                        0x00A0
#define DP83867_LEDCR1_LED_1_SEL_LINK_ACT                  0x00B0
#define DP83867_LEDCR1_LED_1_SEL_ERR                       0x00D0
#define DP83867_LEDCR1_LED_1_SEL_RX_ERR                    0x00E0
#define DP83867_LEDCR1_LED_0_SEL                           0x000F
#define DP83867_LEDCR1_LED_0_SEL_LINK                      0x0000
#define DP83867_LEDCR1_LED_0_SEL_ACT                       0x0001
#define DP83867_LEDCR1_LED_0_SEL_TX_ACT                    0x0002
#define DP83867_LEDCR1_LED_0_SEL_RX_ACT                    0x0003
#define DP83867_LEDCR1_LED_0_SEL_COL                       0x0004
#define DP83867_LEDCR1_LED_0_SEL_1000                      0x0005
#define DP83867_LEDCR1_LED_0_SEL_100                       0x0006
#define DP83867_LEDCR1_LED_0_SEL_10                        0x0007
#define DP83867_LEDCR1_LED_0_SEL_10_100                    0x0008
#define DP83867_LEDCR1_LED_0_SEL_100_1000                  0x0009
#define DP83867_LEDCR1_LED_0_SEL_FD                        0x000A
#define DP83867_LEDCR1_LED_0_SEL_LINK_ACT                  0x000B
#define DP83867_LEDCR1_LED_0_SEL_ERR                       0x000D
#define DP83867_LEDCR1_LED_0_SEL_RX_ERR                    0x000E

//LED Configuration 2 register
#define DP83867_LEDCR2_LED_GPIO_POLARITY                   0x4000
#define DP83867_LEDCR2_LED_GPIO_DRV_VAL                    0x2000
#define DP83867_LEDCR2_LED_GPIO_DRV_EN                     0x1000
#define DP83867_LEDCR2_LED_2_POLARITY                      0x0400
#define DP83867_LEDCR2_LED_2_DRV_VAL                       0x0200
#define DP83867_LEDCR2_LED_2_DRV_EN                        0x0100
#define DP83867_LEDCR2_LED_1_POLARITY                      0x0040
#define DP83867_LEDCR2_LED_1_DRV_VAL                       0x0020
#define DP83867_LEDCR2_LED_1_DRV_EN                        0x0010
#define DP83867_LEDCR2_LED_0_POLARITY                      0x0004
#define DP83867_LEDCR2_LED_0_DRV_VAL                       0x0002
#define DP83867_LEDCR2_LED_0_DRV_EN                        0x0001

//LED Configuration 3 register
#define DP83867_LEDCR3_LEDS_BYPASS_STRETCHING              0x0004
#define DP83867_LEDCR3_LEDS_BLINK_RATE                     0x0003
#define DP83867_LEDCR3_LEDS_BLINK_RATE_20HZ                0x0000
#define DP83867_LEDCR3_LEDS_BLINK_RATE_10HZ                0x0001
#define DP83867_LEDCR3_LEDS_BLINK_RATE_5HZ                 0x0002
#define DP83867_LEDCR3_LEDS_BLINK_RATE_2HZ                 0x0003

//Configuration 3 register
#define DP83867_CFG3_FAST_LINK_UP_PAR_DETECT               0x8000
#define DP83867_CFG3_FAST_AN_EN                            0x4000
#define DP83867_CFG3_FAST_AN_SEL                           0x3000
#define DP83867_CFG3_EXTENDED_FD_ABLE                      0x0800
#define DP83867_CFG3_ROBUST_AUTO_MDIX                      0x0200
#define DP83867_CFG3_FAST_AUTO_MDIX                        0x0100
#define DP83867_CFG3_INT_OE                                0x0080
#define DP83867_CFG3_FORCE_INTERRUPT                       0x0040
#define DP83867_CFG3_TDR_FAIL                              0x0004
#define DP83867_CFG3_TDR_DONE                              0x0002
#define DP83867_CFG3_TDR_START                             0x0001

//Control register
#define DP83867_CTRL_SW_RESET                              0x8000
#define DP83867_CTRL_SW_RESTART                            0x4000

//Testmode Channel Control register
#define DP83867_TMCH_CTRL_TM_CH_SEL                        0x00E0

//Robust Auto MDIX Timer Configuration register
#define DP83867_AMDIX_TMR_CFG_RAMDIX_TMR                   0x000F

//Fast Link Drop Configuration register
#define DP83867_FLD_CFG_FORCE_DROP                         0x8000
#define DP83867_FLD_CFG_FLD_EN                             0x4000
#define DP83867_FLD_CFG_FLD_STS                            0x1F00
#define DP83867_FLD_CFG_FLD_SRC_CFG                        0x001F

//Fast Link Drop Threshold Configuration register
#define DP83867_FLD_THR_CFG_ENERGY_LOST_FLD_THR            0x0007

//Configuration 4 register
#define DP83867_CFG4_INT_TST_MODE_1                        0x0080
#define DP83867_CFG4_PORT_MIRROR_EN                        0x0001

//RGMII Control register
#define DP83867_RGMIICTL_RGMII_EN                          0x0080
#define DP83867_RGMIICTL_RGMII_RX_HALF_FULL_THR            0x0060
#define DP83867_RGMIICTL_RGMII_TX_HALF_FULL_THR            0x0018
#define DP83867_RGMIICTL_RGMII_TX_CLK_DELAY                0x0002
#define DP83867_RGMIICTL_RGMII_RX_CLK_DELAY                0x0001

//RGMII Control 2 register
#define DP83867_RGMIICTL2_RGMII_AF_BYPASS_EN               0x0010

//100BASE-TX Configuration register
#define DP83867_100CR_DESCRAM_TIMEOUT_DIS                  0x0800
#define DP83867_100CR_DESCRAM_TIMEOUT                      0x0780
#define DP83867_100CR_FORCE_100_OK                         0x0040
#define DP83867_100CR_ENH_MLT3_DET_EN                      0x0020
#define DP83867_100CR_ENH_IPG_DET_EN                       0x0010
#define DP83867_100CR_BYPASS_4B5B_RX                       0x0008
#define DP83867_100CR_SCR_DIS                              0x0004
#define DP83867_100CR_ODD_NIBBLE_DETECT                    0x0002
#define DP83867_100CR_FAST_RX_DV                           0x0001

//Viterbi Module Configuration register
#define DP83867_VTM_CFG_VTM_IDLE_CHECK_CNT_THR             0x000F

//Skew FIFO Status register
#define DP83867_SKEW_FIFO_CH_B_SKEW                        0x00F0
#define DP83867_SKEW_FIFO_CH_A_SKEW                        0x000F

//Strap Configuration Status 1 register
#define DP83867_STRAP_STS1_STRAP_MIRROR_EN                 0x8000
#define DP83867_STRAP_STS1_STRAP_LINK_DOWNSHIFT_EN         0x4000
#define DP83867_STRAP_STS1_STRAP_CLK_OUT_DIS_PAP           0x2000
#define DP83867_STRAP_STS1_STRAP_RGMII_DIS                 0x1000
#define DP83867_STRAP_STS1_STRAP_AMDIX_DIS                 0x0400
#define DP83867_STRAP_STS1_STRAP_FORCE_MDI_X               0x0200
#define DP83867_STRAP_STS1_STRAP_HD_EN                     0x0100
#define DP83867_STRAP_STS1_STRAP_ANEG_DIS                  0x0080
#define DP83867_STRAP_STS1_STRAP_ANEG_SEL_PAP              0x0060
#define DP83867_STRAP_STS1_STRAP_PHY_ADD_PAP               0x001F
#define DP83867_STRAP_STS1_STRAP_SPEED_SEL_RGZ             0x0020
#define DP83867_STRAP_STS1_STRAP_PHY_ADD_RGZ               0x000F

//Strap Configuration Status 2 register
#define DP83867_STRAP_STS2_STRAP_RGMII_CLK_SKEW_TX_RGZ     0x0070
#define DP83867_STRAP_STS2_STRAP_RGMII_CLK_SKEW_RX_RGZ     0x0007

//BIST Control and Status 1 register
#define DP83867_BICSR1_PRBS_BYTE_CNT                       0xFFFF

//BIST Control and Status 2 register
#define DP83867_BICSR2_PRBS_PKT_CNT_OVF                    0x0400
#define DP83867_BICSR2_PRBS_BYTE_CNT_OVF                   0x0200
#define DP83867_BICSR2_PRBS_ERR_CNT                        0x00FF

//BIST Control and Status 3 register
#define DP83867_BICSR3_PKT_LEN_PRBS                        0xFFFF

//BIST Control and Status 4 register
#define DP83867_BICSR4_IPG_LEN                             0x00FF

//RGMII Delay Control register
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL              0x00F0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_0_25NS       0x0000
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_0_50NS       0x0010
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_0_75NS       0x0020
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_1_00NS       0x0030
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_1_25NS       0x0040
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_1_50NS       0x0050
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_1_75NS       0x0060
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_2_00NS       0x0070
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_2_25NS       0x0080
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_2_50NS       0x0090
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_2_75NS       0x00A0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_3_00NS       0x00B0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_3_25NS       0x00C0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_3_50NS       0x00D0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_3_75NS       0x00E0
#define DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_4_00NS       0x00F0
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL              0x000F
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_0_25NS       0x0000
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_0_50NS       0x0001
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_0_75NS       0x0002
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_1_00NS       0x0003
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_1_25NS       0x0004
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_1_50NS       0x0005
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_1_75NS       0x0006
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_2_00NS       0x0007
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_2_25NS       0x0008
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_2_50NS       0x0009
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_2_75NS       0x000A
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_3_00NS       0x000B
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_3_25NS       0x000C
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_3_50NS       0x000D
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_3_75NS       0x000E
#define DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_4_00NS       0x000F

//PLL Clock-out Control register
#define DP83867_PLLCTL_CLK_MUX                             0x0010

//Loopback Configuration register
#define DP83867_LOOPCR_LOOP_CFG_VAL                        0xFFFF

//DSP Feedforward Equalizer Configuration register
#define DP83867_DSP_FFE_CFG_FFE_EQ                         0x03FF

//Receive Configuration register
#define DP83867_RXFCFG_WOL_OUT_CLEAR                       0x0800
#define DP83867_RXFCFG_WOL_OUT_STRETCH                     0x0600
#define DP83867_RXFCFG_WOL_OUT_MODE                        0x0100
#define DP83867_RXFCFG_ENHANCED_MAC_SUPPORT                0x0080
#define DP83867_RXFCFG_SCRON_EN                            0x0020
#define DP83867_RXFCFG_WAKE_ON_UCAST                       0x0010
#define DP83867_RXFCFG_WAKE_ON_BCAST                       0x0004
#define DP83867_RXFCFG_WAKE_ON_PATTERN                     0x0002
#define DP83867_RXFCFG_WAKE_ON_MAGIC                       0x0001

//Receive Status register
#define DP83867_RXFSTS_SFD_ERR                             0x0080
#define DP83867_RXFSTS_BAD_CRC                             0x0040
#define DP83867_RXFSTS_SCRON_HACK                          0x0020
#define DP83867_RXFSTS_UCAST_RCVD                          0x0010
#define DP83867_RXFSTS_BCAST_RCVD                          0x0004
#define DP83867_RXFSTS_PATTERN_RCVD                        0x0002
#define DP83867_RXFSTS_MAGIC_RCVD                          0x0001

//Pattern Match Data 1 register
#define DP83867_RXFPMD1_PMATCH_DATA_15_0                   0xFFFF

//Pattern Match Data 2 register
#define DP83867_RXFPMD2_PMATCH_DATA_31_16                  0xFFFF

//Pattern Match Data 3 register
#define DP83867_RXFPMD3_PMATCH_DATA_47_32                  0xFFFF

//SecureOn Pass 1 register
#define DP83867_RXFSOP1_SCRON_PASSWORD_15_0                0xFFFF

//SecureOn Pass 2 register
#define DP83867_RXFSOP2_SCRON_PASSWORD_31_16               0xFFFF

//SecureOn Pass 3 register
#define DP83867_RXFSOP3_SCRON_PASSWORD_47_32               0xFFFF

//Receive Pattern 1 register
#define DP83867_RXFPAT1_PATTERN_BYTES_0_1                  0xFFFF

//Receive Pattern 2 register
#define DP83867_RXFPAT2_PATTERN_BYTES_2_3                  0xFFFF

//Receive Pattern 3 register
#define DP83867_RXFPAT3_PATTERN_BYTES_4_5                  0xFFFF

//Receive Pattern 4 register
#define DP83867_RXFPAT4_PATTERN_BYTES_6_7                  0xFFFF

//Receive Pattern 5 register
#define DP83867_RXFPAT5_PATTERN_BYTES_8_9                  0xFFFF

//Receive Pattern 6 register
#define DP83867_RXFPAT6_PATTERN_BYTES_10_11                0xFFFF

//Receive Pattern 7 register
#define DP83867_RXFPAT7_PATTERN_BYTES_12_13                0xFFFF

//Receive Pattern 8 register
#define DP83867_RXFPAT8_PATTERN_BYTES_14_15                0xFFFF

//Receive Pattern 9 register
#define DP83867_RXFPAT9_PATTERN_BYTES_16_17                0xFFFF

//Receive Pattern 10 register
#define DP83867_RXFPAT10_PATTERN_BYTES_18_19               0xFFFF

//Receive Pattern 11 register
#define DP83867_RXFPAT11_PATTERN_BYTES_20_21               0xFFFF

//Receive Pattern 12 register
#define DP83867_RXFPAT12_PATTERN_BYTES_22_23               0xFFFF

//Receive Pattern 13 register
#define DP83867_RXFPAT13_PATTERN_BYTES_24_25               0xFFFF

//Receive Pattern 14 register
#define DP83867_RXFPAT14_PATTERN_BYTES_26_27               0xFFFF

//Receive Pattern 15 register
#define DP83867_RXFPAT15_PATTERN_BYTES_28_29               0xFFFF

//Receive Pattern 16 register
#define DP83867_RXFPAT16_PATTERN_BYTES_30_31               0xFFFF

//Receive Pattern 17 register
#define DP83867_RXFPAT17_PATTERN_BYTES_32_33               0xFFFF

//Receive Pattern 18 register
#define DP83867_RXFPAT18_PATTERN_BYTES_34_35               0xFFFF

//Receive Pattern 19 register
#define DP83867_RXFPAT19_PATTERN_BYTES_36_37               0xFFFF

//Receive Pattern 20 register
#define DP83867_RXFPAT20_PATTERN_BYTES_38_39               0xFFFF

//Receive Pattern 21 register
#define DP83867_RXFPAT21_PATTERN_BYTES_40_41               0xFFFF

//Receive Pattern 22 register
#define DP83867_RXFPAT22_PATTERN_BYTES_42_43               0xFFFF

//Receive Pattern 23 register
#define DP83867_RXFPAT23_PATTERN_BYTES_44_45               0xFFFF

//Receive Pattern 24 register
#define DP83867_RXFPAT24_PATTERN_BYTES_46_47               0xFFFF

//Receive Pattern 25 register
#define DP83867_RXFPAT25_PATTERN_BYTES_48_49               0xFFFF

//Receive Pattern 26 register
#define DP83867_RXFPAT26_PATTERN_BYTES_50_51               0xFFFF

//Receive Pattern 27 register
#define DP83867_RXFPAT27_PATTERN_BYTES_52_53               0xFFFF

//Receive Pattern 28 register
#define DP83867_RXFPAT28_PATTERN_BYTES_54_55               0xFFFF

//Receive Pattern 29 register
#define DP83867_RXFPAT29_PATTERN_BYTES_56_57               0xFFFF

//Receive Pattern 30 register
#define DP83867_RXFPAT30_PATTERN_BYTES_58_59               0xFFFF

//Receive Pattern 31 register
#define DP83867_RXFPAT31_PATTERN_BYTES_60_61               0xFFFF

//Receive Pattern 32 register
#define DP83867_RXFPAT32_PATTERN_BYTES_62_63               0xFFFF

//Receive Pattern Byte Mask 1 register
#define DP83867_RXFPBM1_PATTERN_BYTES_MASK_0_15            0xFFFF

//Receive Pattern Byte Mask 2 register
#define DP83867_RXFPBM2_PATTERN_BYTES_MASK_16_31           0xFFFF

//Receive Pattern Byte Mask 3 register
#define DP83867_RXFPBM3_PATTERN_BYTES_MASK_32_47           0xFFFF

//Receive Pattern Byte Mask 4 register
#define DP83867_RXFPBM4_PATTERN_BYTES_MASK_48_63           0xFFFF

//Receive Status register
#define DP83867_RXFPATC_PATTERN_START_POINT                0x003F

//I/O Configuration register
#define DP83867_IO_MUX_CFG_CLK_O_SEL                       0x1F00
#define DP83867_IO_MUX_CFG_CLK_O_DISABLE                   0x0040
#define DP83867_IO_MUX_CFG_IO_IMPEDANCE_CTRL               0x001F

//GPIO Mux Control 1 register
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL             0xF000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_RX_D7       0x0000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_1588_TX_SFD 0x1000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_1588_RX_SFD 0x2000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_WOL         0x3000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_ED          0x4000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_LED_3       0x6000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_PRBS_ERR    0x7000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_CONST_0     0x8000
#define DP83867_GPIO_MUX_CTRL1_RX_D7_GPIO_CTRL_CONST_1     0x9000
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL             0x0F00
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_RX_D6       0x0000
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_1588_TX_SFD 0x0100
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_1588_RX_SFD 0x0200
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_WOL         0x0300
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_ED          0x0400
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_LED_3       0x0600
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_PRBS_ERR    0x0700
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_CONST_0     0x0800
#define DP83867_GPIO_MUX_CTRL1_RX_D6_GPIO_CTRL_CONST_1     0x0900
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL             0x00F0
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_RX_D5       0x0000
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_1588_TX_SFD 0x0010
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_1588_RX_SFD 0x0020
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_WOL         0x0030
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_ED          0x0040
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_LED_3       0x0060
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_PRBS_ERR    0x0070
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_CONST_0     0x0080
#define DP83867_GPIO_MUX_CTRL1_RX_D5_GPIO_CTRL_CONST_1     0x0090
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL             0x000F
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_RX_D4       0x0000
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_1588_TX_SFD 0x0001
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_1588_RX_SFD 0x0002
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_WOL         0x0003
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_ED          0x0004
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_LED_3       0x0006
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_PRBS_ERR    0x0007
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_CONST_0     0x0008
#define DP83867_GPIO_MUX_CTRL1_RX_D4_GPIO_CTRL_CONST_1     0x0009

//GPIO Mux Control 2 register
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL               0x0F00
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_CRS           0x0000
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_1588_TX_SFD   0x0100
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_1588_RX_SFD   0x0200
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_WOL           0x0300
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_ED            0x0400
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_LED_3         0x0600
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_PRBS_ERR      0x0700
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_CONST_0       0x0800
#define DP83867_GPIO_MUX_CTRL2_CRS_GPIO_CTRL_CONST_1       0x0900
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL               0x00F0
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_COL           0x0000
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_1588_TX_SFD   0x0010
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_1588_RX_SFD   0x0020
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_WOL           0x0030
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_ED            0x0040
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_LED_3         0x0060
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_PRBS_ERR      0x0070
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_CONST_0       0x0080
#define DP83867_GPIO_MUX_CTRL2_COL_GPIO_CTRL_CONST_1       0x0090
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL             0x000F
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_RX_ER       0x0000
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_1588_TX_SFD 0x0001
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_1588_RX_SFD 0x0002
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_WOL         0x0003
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_ED          0x0004
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_LED_3       0x0006
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_PRBS_ERR    0x0007
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_CONST_0     0x0008
#define DP83867_GPIO_MUX_CTRL2_RX_ER_GPIO_CTRL_CONST_1     0x0009

//GPIO Mux Control register
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL                  0x00F0
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_COL              0x0000
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_1588_TX_SFD      0x0010
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_1588_RX_SFD      0x0020
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_WOL              0x0030
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_ED               0x0040
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_LED_3            0x0060
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_PRBS_ERR         0x0070
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_CONST_0          0x0080
#define DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_CONST_1          0x0090
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL                  0x000F
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_RX_ER            0x0000
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_1588_TX_SFD      0x0001
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_1588_RX_SFD      0x0002
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_WOL              0x0003
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_ED               0x0004
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_LED_3            0x0006
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_PRBS_ERR         0x0007
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_CONST_0          0x0008
#define DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_CONST_1          0x0009

//TDR General Configuration 1 register
#define DP83867_TDR_GEN_CFG1_TDR_CH_CD_BYPASS              0x1000
#define DP83867_TDR_GEN_CFG1_TDR_CROSS_MODE_DIS            0x0800
#define DP83867_TDR_GEN_CFG1_TDR_NLP_CHECK                 0x0400
#define DP83867_TDR_GEN_CFG1_TDR_AVG_NUM                   0x0380
#define DP83867_TDR_GEN_CFG1_TDR_SEG_NUM                   0x0070
#define DP83867_TDR_GEN_CFG1_TDR_CYCLE_TIME                0x000F

//TDR Peak Locations 1 register
#define DP83867_TDR_PEAKS_LOC_1_TDR_PEAKS_LOC_A_1          0xFF00
#define DP83867_TDR_PEAKS_LOC_1_TDR_PEAKS_LOC_A_0          0x00FF

//TDR Peak Locations 2 register
#define DP83867_TDR_PEAKS_LOC_2_TDR_PEAKS_LOC_A_3          0xFF00
#define DP83867_TDR_PEAKS_LOC_2_TDR_PEAKS_LOC_A_2          0x00FF

//TDR Peak Locations 3 register
#define DP83867_TDR_PEAKS_LOC_3_TDR_PEAKS_LOC_B_0          0xFF00
#define DP83867_TDR_PEAKS_LOC_3_TDR_PEAKS_LOC_A_4          0x00FF

//TDR Peak Locations 4 register
#define DP83867_TDR_PEAKS_LOC_4_TDR_PEAKS_LOC_B_2          0xFF00
#define DP83867_TDR_PEAKS_LOC_4_TDR_PEAKS_LOC_B_1          0x00FF

//TDR Peak Locations 5 register
#define DP83867_TDR_PEAKS_LOC_5_TDR_PEAKS_LOC_B_4          0xFF00
#define DP83867_TDR_PEAKS_LOC_5_TDR_PEAKS_LOC_B_3          0x00FF

//TDR Peak Locations 6 register
#define DP83867_TDR_PEAKS_LOC_6_TDR_PEAKS_LOC_C_1          0xFF00
#define DP83867_TDR_PEAKS_LOC_6_TDR_PEAKS_LOC_C_0          0x00FF

//TDR Peak Locations 7 register
#define DP83867_TDR_PEAKS_LOC_7_TDR_PEAKS_LOC_C_3          0xFF00
#define DP83867_TDR_PEAKS_LOC_7_TDR_PEAKS_LOC_C_2          0x00FF

//TDR Peak Locations 8 register
#define DP83867_TDR_PEAKS_LOC_8_TDR_PEAKS_LOC_D_0          0xFF00
#define DP83867_TDR_PEAKS_LOC_8_TDR_PEAKS_LOC_C_4          0x00FF

//TDR Peak Locations 9 register
#define DP83867_TDR_PEAKS_LOC_9_TDR_PEAKS_LOC_D_2          0xFF00
#define DP83867_TDR_PEAKS_LOC_9_TDR_PEAKS_LOC_D_1          0x00FF

//TDR Peak Locations 10 register
#define DP83867_TDR_PEAKS_LOC_10_TDR_PEAKS_LOC_D_4         0xFF00
#define DP83867_TDR_PEAKS_LOC_10_TDR_PEAKS_LOC_D_3         0x00FF

//TDR Peak Amplitudes 1 register
#define DP83867_TDR_PEAKS_AMP_1_TDR_PEAKS_AMP_A_1          0x7F00
#define DP83867_TDR_PEAKS_AMP_1_TDR_PEAKS_AMP_A_0          0x007F

//TDR Peak Amplitudes 2 register
#define DP83867_TDR_PEAKS_AMP_2_TDR_PEAKS_AMP_A_3          0x7F00
#define DP83867_TDR_PEAKS_AMP_2_TDR_PEAKS_AMP_A_2          0x007F

//TDR Peak Amplitudes 3 register
#define DP83867_TDR_PEAKS_AMP_3_TDR_PEAKS_AMP_B_0          0x7F00
#define DP83867_TDR_PEAKS_AMP_3_TDR_PEAKS_AMP_A_4          0x007F

//TDR Peak Amplitudes 4 register
#define DP83867_TDR_PEAKS_AMP_4_TDR_PEAKS_AMP_B_2          0x7F00
#define DP83867_TDR_PEAKS_AMP_4_TDR_PEAKS_AMP_B_1          0x007F

//TDR Peak Amplitudes 5 register
#define DP83867_TDR_PEAKS_AMP_5_TDR_PEAKS_AMP_B_4          0x7F00
#define DP83867_TDR_PEAKS_AMP_5_TDR_PEAKS_AMP_B_3          0x007F

//TDR Peak Amplitudes 6 register
#define DP83867_TDR_PEAKS_AMP_6_TDR_PEAKS_AMP_C_1          0x7F00
#define DP83867_TDR_PEAKS_AMP_6_TDR_PEAKS_AMP_C_0          0x007F

//TDR Peak Amplitudes 7 register
#define DP83867_TDR_PEAKS_AMP_7_TDR_PEAKS_AMP_C_3          0x7F00
#define DP83867_TDR_PEAKS_AMP_7_TDR_PEAKS_AMP_C_2          0x007F

//TDR Peak Amplitudes 8 register
#define DP83867_TDR_PEAKS_AMP_8_TDR_PEAKS_AMP_D_0          0x7F00
#define DP83867_TDR_PEAKS_AMP_8_TDR_PEAKS_AMP_C_4          0x007F

//TDR Peak Amplitudes 9 register
#define DP83867_TDR_PEAKS_AMP_9_TDR_PEAKS_AMP_D_2          0x7F00
#define DP83867_TDR_PEAKS_AMP_9_TDR_PEAKS_AMP_D_1          0x007F

//TDR Peak Amplitudes 10 register
#define DP83867_TDR_PEAKS_AMP_10_TDR_PEAKS_AMP_D_4         0x7F00
#define DP83867_TDR_PEAKS_AMP_10_TDR_PEAKS_AMP_D_3         0x007F

//Programmable Gain register
#define DP83867_PROG_GAIN_UNF_FUNC_MODE                    0x0008
#define DP83867_PROG_GAIN_SGMII_TX_POL_IN                  0x0002
#define DP83867_PROG_GAIN_SGMII_RX_POL_IN                  0x0001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DP83867 Ethernet PHY driver
extern const PhyDriver dp83867PhyDriver;

//DP83867 related functions
error_t dp83867Init(NetInterface *interface);
void dp83867InitHook(NetInterface *interface);

void dp83867Tick(NetInterface *interface);

void dp83867EnableIrq(NetInterface *interface);
void dp83867DisableIrq(NetInterface *interface);

void dp83867EventHandler(NetInterface *interface);

void dp83867WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t dp83867ReadPhyReg(NetInterface *interface, uint8_t address);

void dp83867DumpPhyReg(NetInterface *interface);

void dp83867WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t dp83867ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
