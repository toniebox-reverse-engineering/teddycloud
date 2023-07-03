/**
 * @file dp83td510_driver.h
 * @brief DP83TD510 10Base-T1L Ethernet PHY driver
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

#ifndef _DP83TD510_DRIVER_H
#define _DP83TD510_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef DP83TD510_PHY_ADDR
   #define DP83TD510_PHY_ADDR 0
#elif (DP83TD510_PHY_ADDR < 0 || DP83TD510_PHY_ADDR > 31)
   #error DP83TD510_PHY_ADDR parameter is not valid
#endif

//DP83TD510 PHY registers
#define DP83TD510_MII_REG_0                                              0x00
#define DP83TD510_MII_REG_2                                              0x02
#define DP83TD510_MII_REG_3                                              0x03
#define DP83TD510_REGCR                                                  0x0D
#define DP83TD510_ADDAR                                                  0x0E
#define DP83TD510_PHY_STS                                                0x10
#define DP83TD510_GEN_CFG                                                0x11
#define DP83TD510_INTERRUPT_REG_1                                        0x12
#define DP83TD510_INTERRUPT_REG_2                                        0x13
#define DP83TD510_RX_ERR_CNT                                             0x15
#define DP83TD510_BISCR                                                  0x16
#define DP83TD510_MAC_CFG_1                                              0x17
#define DP83TD510_MAC_CFG_2                                              0x18
#define DP83TD510_SOR_PHYAD                                              0x19
#define DP83TD510_TDR_CFG                                                0x1E

//DP83TD510 MMD registers
#define DP83TD510_PAM_PMD_CTRL_1                                         0x01, 0x0000
#define DP83TD510_PMA_PMD_CTRL_2                                         0x01, 0x0007
#define DP83TD510_PMA_PMD_EXTENDED_ABILITY_2                             0x01, 0x000B
#define DP83TD510_PMA_PMD_EXTENDED_ABILITY                               0x01, 0x0012
#define DP83TD510_PMA_PMD_CTRL                                           0x01, 0x0834
#define DP83TD510_PMA_CTRL                                               0x01, 0x08F6
#define DP83TD510_PMA_STATUS                                             0x01, 0x08F7
#define DP83TD510_TEST_MODE_CTRL                                         0x01, 0x08F8
#define DP83TD510_PCS_CTRL                                               0x03, 0x0000
#define DP83TD510_PCS_CTRL_2                                             0x03, 0x08E6
#define DP83TD510_PCS_STATUS                                             0x03, 0x08E7
#define DP83TD510_AN_CONTROL                                             0x07, 0x0200
#define DP83TD510_AN_STATUS                                              0x07, 0x0201
#define DP83TD510_AN_ADV_1                                               0x07, 0x0202
#define DP83TD510_AN_ADV_2                                               0x07, 0x0203
#define DP83TD510_AN_ADV_3                                               0x07, 0x0204
#define DP83TD510_AN_LP_ADV_1                                            0x07, 0x0205
#define DP83TD510_AN_LP_ADV_2                                            0x07, 0x0206
#define DP83TD510_AN_LP_ADV_3                                            0x07, 0x0207
#define DP83TD510_AN_NP_ADV_1                                            0x07, 0x0208
#define DP83TD510_AN_NP_ADV_2                                            0x07, 0x0209
#define DP83TD510_AN_NP_ADV_3                                            0x07, 0x020A
#define DP83TD510_AN_LP_NP_ADV_1                                         0x07, 0x020B
#define DP83TD510_AN_LP_NP_ADV_2                                         0x07, 0x020C
#define DP83TD510_AN_LP_NP_ADV_3                                         0x07, 0x020D
#define DP83TD510_AN_CTRL_10BT1                                          0x07, 0x020E
#define DP83TD510_AN_STATUS_10BT1                                        0x07, 0x020F
#define DP83TD510_PRBS_CFG_1                                             0x1F, 0x0119
#define DP83TD510_PRBS_CFG_2                                             0x1F, 0x011A
#define DP83TD510_PRBS_CFG_3                                             0x1F, 0x011B
#define DP83TD510_PRBS_STATUS_1                                          0x1F, 0x011C
#define DP83TD510_PRBS_STATUS_2                                          0x1F, 0x011D
#define DP83TD510_PRBS_STATUS_3                                          0x1F, 0x011E
#define DP83TD510_PRBS_STATUS_4                                          0x1F, 0x011F
#define DP83TD510_PRBS_STATUS_5                                          0x1F, 0x0120
#define DP83TD510_PRBS_STATUS_6                                          0x1F, 0x0121
#define DP83TD510_PRBS_STATUS_7                                          0x1F, 0x0122
#define DP83TD510_PRBS_CFG_4                                             0x1F, 0x0123
#define DP83TD510_PRBS_CFG_5                                             0x1F, 0x0124
#define DP83TD510_PRBS_CFG_6                                             0x1F, 0x0125
#define DP83TD510_PRBS_CFG_7                                             0x1F, 0x0126
#define DP83TD510_PRBS_CFG_8                                             0x1F, 0x0127
#define DP83TD510_PRBS_CFG_9                                             0x1F, 0x0128
#define DP83TD510_PRBS_CFG_10                                            0x1F, 0x0129
#define DP83TD510_CRC_STATUS                                             0x1F, 0x012A
#define DP83TD510_PKT_STAT_1                                             0x1F, 0x012B
#define DP83TD510_PKT_STAT_2                                             0x1F, 0x012C
#define DP83TD510_PKT_STAT_3                                             0x1F, 0x012D
#define DP83TD510_PKT_STAT_4                                             0x1F, 0x012E
#define DP83TD510_PKT_STAT_5                                             0x1F, 0x012F
#define DP83TD510_PKT_STAT_6                                             0x1F, 0x0130
#define DP83TD510_TDR_CFG1                                               0x1F, 0x0300
#define DP83TD510_TDR_CFG2                                               0x1F, 0x0301
#define DP83TD510_TDR_CFG3                                               0x1F, 0x0302
#define DP83TD510_FAULT_CFG1                                             0x1F, 0x0303
#define DP83TD510_FAULT_CFG2                                             0x1F, 0x0304
#define DP83TD510_FAULT_STAT1                                            0x1F, 0x0305
#define DP83TD510_FAULT_STAT2                                            0x1F, 0x0306
#define DP83TD510_FAULT_STAT3                                            0x1F, 0x0307
#define DP83TD510_FAULT_STAT4                                            0x1F, 0x0308
#define DP83TD510_FAULT_STAT5                                            0x1F, 0x0309
#define DP83TD510_FAULT_STAT6                                            0x1F, 0x030A
#define DP83TD510_CHIP_SOR_0                                             0x1F, 0x0420
#define DP83TD510_LEDS_CFG_1                                             0x1F, 0x0460
#define DP83TD510_IO_MUX_CFG                                             0x1F, 0x0461
#define DP83TD510_IO_MUX_GPIO_CTRL_1                                     0x1F, 0x0462
#define DP83TD510_IO_MUX_GPIO_CTRL_2                                     0x1F, 0x0463
#define DP83TD510_CHIP_SOR_1                                             0x1F, 0x0467
#define DP83TD510_CHIP_SOR_2                                             0x1F, 0x0468
#define DP83TD510_LEDS_CFG_2                                             0x1F, 0x0469
#define DP83TD510_AN_STAT_1                                              0x1F, 0x060C
#define DP83TD510_DSP_REG_72                                             0x1F, 0x0872
#define DP83TD510_DSP_REG_8D                                             0x1F, 0x088D
#define DP83TD510_DSP_REG_8E                                             0x1F, 0x088E
#define DP83TD510_DSP_REG_8F                                             0x1F, 0x088F
#define DP83TD510_DSP_REG_90                                             0x1F, 0x0890
#define DP83TD510_DSP_REG_91                                             0x1F, 0x0891
#define DP83TD510_DSP_REG_92                                             0x1F, 0x0892
#define DP83TD510_DSP_REG_98                                             0x1F, 0x0898
#define DP83TD510_DSP_REG_99                                             0x1F, 0x0899
#define DP83TD510_DSP_REG_9A                                             0x1F, 0x089A
#define DP83TD510_DSP_REG_9B                                             0x1F, 0x089B
#define DP83TD510_DSP_REG_9C                                             0x1F, 0x089C
#define DP83TD510_DSP_REG_9D                                             0x1F, 0x089D
#define DP83TD510_DSP_REG_E9                                             0x1F, 0x08E9
#define DP83TD510_DSP_REG_EA                                             0x1F, 0x08EA
#define DP83TD510_DSP_REG_EB                                             0x1F, 0x08EB
#define DP83TD510_DSP_REG_EC                                             0x1F, 0x08EC
#define DP83TD510_DSP_REG_ED                                             0x1F, 0x08ED
#define DP83TD510_DSP_REG_EE                                             0x1F, 0x08EE
#define DP83TD510_MSE_DETECT                                             0x1F, 0x0A85
#define DP83TD510_ALCD_METRIC                                            0x1F, 0x0A9D
#define DP83TD510_ALCD_STATUS                                            0x1F, 0x0A9F
#define DP83TD510_SCAN_2                                                 0x1F, 0x0E01

//MII_REG_0 register
#define DP83TD510_MII_REG_0_MII_RESET                                    0x8000
#define DP83TD510_MII_REG_0_LOOPBACK                                     0x4000
#define DP83TD510_MII_REG_0_POWER_DOWN                                   0x0800
#define DP83TD510_MII_REG_0_ISOLATE                                      0x0400
#define DP83TD510_MII_REG_0_UNIDIRECTIONAL_ABILITY                       0x0020

//MII_REG_2 register
#define DP83TD510_MII_REG_2_OUI_21_16                                    0xFFFF
#define DP83TD510_MII_REG_2_OUI_21_16_DEFAULT                            0x2000

//MII_REG_3 register
#define DP83TD510_MII_REG_3_OUI_5_0                                      0xFC00
#define DP83TD510_MII_REG_3_OUI_5_0_DEFAULT                              0x0000
#define DP83TD510_MII_REG_3_MODEL_NUMBER                                 0x03E0
#define DP83TD510_MII_REG_3_MODEL_NUMBER_DEFAULT                         0x0180
#define DP83TD510_MII_REG_3_REVISION_NUMBER                              0x001F

//Register Control register
#define DP83TD510_REGCR_CMD                                              0xC000
#define DP83TD510_REGCR_CMD_ADDR                                         0x0000
#define DP83TD510_REGCR_CMD_DATA_NO_POST_INC                             0x4000
#define DP83TD510_REGCR_CMD_DATA_POST_INC_RW                             0x8000
#define DP83TD510_REGCR_CMD_DATA_POST_INC_W                              0xC000
#define DP83TD510_REGCR_DEVAD                                            0x001F

//PHY_STS register
#define DP83TD510_PHY_STS_MII_INTERRUPT                                  0x0080
#define DP83TD510_PHY_STS_LINK_STATUS                                    0x0001

//GEN_CFG register
#define DP83TD510_GEN_CFG_CHANNEL_DEBUG_MODE                             0x0800
#define DP83TD510_GEN_CFG_DEBUG_MODE                                     0x0400
#define DP83TD510_GEN_CFG_TX_FIFO_DEPTH                                  0x0060
#define DP83TD510_GEN_CFG_TX_FIFO_DEPTH_4_NIBBLES                        0x0000
#define DP83TD510_GEN_CFG_TX_FIFO_DEPTH_5_NIBBLES                        0x0020
#define DP83TD510_GEN_CFG_TX_FIFO_DEPTH_6_NIBBLES                        0x0040
#define DP83TD510_GEN_CFG_TX_FIFO_DEPTH_8_NIBBLES                        0x0060
#define DP83TD510_GEN_CFG_INT_POLARITY                                   0x0008
#define DP83TD510_GEN_CFG_INT_POLARITY_HIGH                              0x0000
#define DP83TD510_GEN_CFG_INT_POLARITY_LOW                               0x0008
#define DP83TD510_GEN_CFG_FORCE_INTERRUPT                                0x0004
#define DP83TD510_GEN_CFG_INT_EN                                         0x0002
#define DP83TD510_GEN_CFG_INT_OE                                         0x0001

//INTERRUPT_REG_1 register
#define DP83TD510_INTERRUPT_REG_1_RHF_INT                                0x8000
#define DP83TD510_INTERRUPT_REG_1_LINK_INT                               0x2000
#define DP83TD510_INTERRUPT_REG_1_ESD_INT                                0x0800
#define DP83TD510_INTERRUPT_REG_1_RHF_INT_EN                             0x0080
#define DP83TD510_INTERRUPT_REG_1_LINK_INT_EN                            0x0020
#define DP83TD510_INTERRUPT_REG_1_ESD_INT_EN                             0x0008

//INTERRUPT_REG_2 register
#define DP83TD510_INTERRUPT_REG_2_PAGE_INT                               0x2000
#define DP83TD510_INTERRUPT_REG_2_POL_INT                                0x0200
#define DP83TD510_INTERRUPT_REG_2_PAGE_INT_EN                            0x0020
#define DP83TD510_INTERRUPT_REG_2_POL_INT_EN                             0x0002

//RX_ERR_CNT register
#define DP83TD510_RX_ERR_CNT_RX_ERR_CNT                                  0xFFFF

//BISCR register
#define DP83TD510_BISCR_CORE_PWR_MODE                                    0x0100
#define DP83TD510_BISCR_LOOPBACK_MODE                                    0x007F
#define DP83TD510_BISCR_LOOPBACK_MODE_PCS                                0x0002
#define DP83TD510_BISCR_LOOPBACK_MODE_DIGITAL                            0x0004
#define DP83TD510_BISCR_LOOPBACK_MODE_ANALOG                             0x0008
#define DP83TD510_BISCR_LOOPBACK_MODE_REVERSE                            0x0010
#define DP83TD510_BISCR_LOOPBACK_MODE_TX_TO_MAC_IN_REVERSE               0x0020
#define DP83TD510_BISCR_LOOPBACK_MODE_TX_TO_MDI_IN_MAC                   0x0040

//MAC_CFG_1 register
#define DP83TD510_MAC_CFG_1_CFG_RMII_DIS_DELAYED_TXD_EN                  0x8000
#define DP83TD510_MAC_CFG_1_MIN_IPG_MODE_EN                              0x4000
#define DP83TD510_MAC_CFG_1_CFG_RMII_ENH                                 0x2000
#define DP83TD510_MAC_CFG_1_CFG_RGMII_RX_CLK_SHIFT_SEL                   0x1000
#define DP83TD510_MAC_CFG_1_CFG_RGMII_TX_CLK_SHIFT_SEL                   0x0800
#define DP83TD510_MAC_CFG_1_CFG_RGMII_EN                                 0x0200
#define DP83TD510_MAC_CFG_1_CFG_RMII_CLK_SHIFT_EN                        0x0100
#define DP83TD510_MAC_CFG_1_CFG_XI_50                                    0x0080
#define DP83TD510_MAC_CFG_1_CFG_RMII_SLOW_MODE                           0x0040
#define DP83TD510_MAC_CFG_1_CFG_RMII_MODE                                0x0020
#define DP83TD510_MAC_CFG_1_CFG_RMII_REV1_0                              0x0010
#define DP83TD510_MAC_CFG_1_RMII_OVF_STS                                 0x0008
#define DP83TD510_MAC_CFG_1_RMII_UNF_STS                                 0x0004
#define DP83TD510_MAC_CFG_1_CFG_RMII_ELAST_BUF                           0x0003
#define DP83TD510_MAC_CFG_1_CFG_RMII_ELAST_BUF_14_BIT_TOLERANCE          0x0000
#define DP83TD510_MAC_CFG_1_CFG_RMII_ELAST_BUF_2_BIT_TOLERANCE           0x0001
#define DP83TD510_MAC_CFG_1_CFG_RMII_ELAST_BUF_6_BIT_TOLERANCE           0x0002
#define DP83TD510_MAC_CFG_1_CFG_RMII_ELAST_BUF_10_BIT_TOLERANCE          0x0003

//MAC_CFG_2 register
#define DP83TD510_MAC_CFG_2_CFG_INV_RX_CLK                               0x0800
#define DP83TD510_MAC_CFG_2_CFG_RMII_CRS_DV_SEL                          0x0400
#define DP83TD510_MAC_CFG_2_RGMII_TX_AF_EMPTY_ERR                        0x0200
#define DP83TD510_MAC_CFG_2_RGMII_TX_AF_FULL_ERR                         0x0100
#define DP83TD510_MAC_CFG_2_INV_RGMII_RXD                                0x0020
#define DP83TD510_MAC_CFG_2_INV_RGMII_TXD                                0x0010
#define DP83TD510_MAC_CFG_2_SUP_TX_ERR_FD_RGMII                          0x0008
#define DP83TD510_MAC_CFG_2_CFG_RGMII_HALF_FULL_TH                       0x0007

//SOR_PHYAD register
#define DP83TD510_SOR_PHYAD_SOR_PHYADDR                                  0x001F

//TDR_CFG register
#define DP83TD510_TDR_CFG_TDR_START                                      0x8000
#define DP83TD510_TDR_CFG_TDR_DONE                                       0x0002
#define DP83TD510_TDR_CFG_TDR_FAIL                                       0x0001

//PAM_PMD_CTRL_1 register
#define DP83TD510_PAM_PMD_CTRL_1_PMA_RESET                               0x8000
#define DP83TD510_PAM_PMD_CTRL_1_CFG_LOW_POWER                           0x0800
#define DP83TD510_PAM_PMD_CTRL_1_PMA_LOOPBACK                            0x0001

//PMA_PMD_CTRL_2 register
#define DP83TD510_PMA_PMD_CTRL_2_CFG_PMA_TYPE_SELECTION                  0x003F
#define DP83TD510_PMA_PMD_CTRL_2_CFG_PMA_TYPE_SELECTION_BASE_T1          0x003D

//PMA_PMD_EXTENDED_ABILITY_2 register
#define DP83TD510_PMA_PMD_EXTENDED_ABILITY_2_BASE_T1_EXTENDED_ABILITIES  0x0800

//PMA_PMD_EXTENDED_ABILITY register
#define DP83TD510_PMA_PMD_EXTENDED_ABILITY_MR_10_BASE_T1L_ABILITY        0x0004

//PMA_PMD_CTRL register
#define DP83TD510_PMA_PMD_CTRL_CFG_MASTER_SLAVE_VAL                      0x4000
#define DP83TD510_PMA_PMD_CTRL_CFG_TYPE_SELECTION                        0x000F
#define DP83TD510_PMA_PMD_CTRL_CFG_TYPE_SELECTION_10BASE_T1L             0x0002

//PMA_CTRL register
#define DP83TD510_PMA_CTRL_PMA_RESET                                     0x8000
#define DP83TD510_PMA_CTRL_CFG_TRANSMIT_DISABLE                          0x4000
#define DP83TD510_PMA_CTRL_CFG_INCR_TX_LVL                               0x1000
#define DP83TD510_PMA_CTRL_CFG_INCR_TX_LVL_1V0                           0x0000
#define DP83TD510_PMA_CTRL_CFG_INCR_TX_LVL_2V4                           0x1000
#define DP83TD510_PMA_CTRL_CFG_LOW_POWER                                 0x0800
#define DP83TD510_PMA_CTRL_CFG_EEE_ENABLE                                0x0400
#define DP83TD510_PMA_CTRL_PMA_LOOPBACK                                  0x0001

//PMA_STATUS register
#define DP83TD510_PMA_STATUS_LOOPBACK_ABILITY                            0x2000
#define DP83TD510_PMA_STATUS_TX_LVL_INCR_ABILITY                         0x1000
#define DP83TD510_PMA_STATUS_LOW_POWER_ABILITY                           0x0800
#define DP83TD510_PMA_STATUS_EEE_ABILITY                                 0x0400
#define DP83TD510_PMA_STATUS_RECEIVE_FAULT_ABILITY                       0x0200
#define DP83TD510_PMA_STATUS_RECEIVE_POLARITY                            0x0004
#define DP83TD510_PMA_STATUS_RECEIVE_FAULT                               0x0002
#define DP83TD510_PMA_STATUS_RECEIVE_LINK_STATUS                         0x0001

//TEST_MODE_CTRL register
#define DP83TD510_TEST_MODE_CTRL_CFG_TEST_MODE                           0xE000
#define DP83TD510_TEST_MODE_CTRL_CFG_TEST_MODE_NORMAL                    0x0000
#define DP83TD510_TEST_MODE_CTRL_CFG_TEST_MODE_1                         0x2000
#define DP83TD510_TEST_MODE_CTRL_CFG_TEST_MODE_2                         0x4000
#define DP83TD510_TEST_MODE_CTRL_CFG_TEST_MODE_3                         0x6000

//PCS_CTRL register
#define DP83TD510_PCS_CTRL_PCS_RESET                                     0x8000
#define DP83TD510_PCS_CTRL_MMD3_LOOPBACK                                 0x4000

//PCS_CTRL_2 register
#define DP83TD510_PCS_CTRL_2_PCS_RESET                                   0x8000
#define DP83TD510_PCS_CTRL_2_MMD3_LOOPBACK                               0x4000

//PCS_STATUS register
#define DP83TD510_PCS_STATUS_TX_LPI_RECEIVED                             0x0800
#define DP83TD510_PCS_STATUS_RX_LPI_RECEIVED                             0x0400
#define DP83TD510_PCS_STATUS_TX_LPI_INDICATION                           0x0200
#define DP83TD510_PCS_STATUS_RX_LPI_INDICATION                           0x0100
#define DP83TD510_PCS_STATUS_FAULT                                       0x0080
#define DP83TD510_PCS_STATUS_RECEIVE_LINK_STATUS                         0x0004

//AN_CONTROL register
#define DP83TD510_AN_CONTROL_MR_MAIN_RESET                               0x8000
#define DP83TD510_AN_CONTROL_MR_AN_ENABLE                                0x1000
#define DP83TD510_AN_CONTROL_MR_RESTART_AN                               0x0200

//AN_STATUS register
#define DP83TD510_AN_STATUS_MR_PAGE_RECEIVED                             0x0040
#define DP83TD510_AN_STATUS_MR_AN_COMPLETE                               0x0020
#define DP83TD510_AN_STATUS_REMOTE_FAULT                                 0x0010
#define DP83TD510_AN_STATUS_MR_AN_ABILITY                                0x0008
#define DP83TD510_AN_STATUS_LINK_STATUS                                  0x0004

//AN_ADV_1 register
#define DP83TD510_AN_ADV_1_MR_BP_NP_ABILITY                              0x8000
#define DP83TD510_AN_ADV_1_MR_BP_ACK                                     0x4000
#define DP83TD510_AN_ADV_1_MR_BP_REMOTE_FAULT                            0x2000
#define DP83TD510_AN_ADV_1_MR_BP_12_5                                    0x1FE0
#define DP83TD510_AN_ADV_1_SELECTOR_FIELD                                0x001F

//AN_ADV_2 register
#define DP83TD510_AN_ADV_2_MR_BP_31_16                                   0xFFFF

//AN_ADV_3 register
#define DP83TD510_AN_ADV_3_MR_BP_47_32                                   0xFFFF

//AN_LP_ADV_1 register
#define DP83TD510_AN_LP_ADV_1_MR_LP_BP_15_0                              0xFFFF

//AN_LP_ADV_2 register
#define DP83TD510_AN_LP_ADV_2_MR_LP_BP_31_16                             0xFFFF

//AN_LP_ADV_3 register
#define DP83TD510_AN_LP_ADV_3_MR_LP_BP_47_32                             0xFFFF

//AN_NP_ADV_1 register
#define DP83TD510_AN_NP_ADV_1_MR_NP_NP_ABILITY                           0x8000
#define DP83TD510_AN_NP_ADV_1_MR_NP_MESSAGE_PAGE                         0x2000
#define DP83TD510_AN_NP_ADV_1_MR_NP_ACK2                                 0x1000
#define DP83TD510_AN_NP_ADV_1_MR_NP_TOGGLE                               0x0800
#define DP83TD510_AN_NP_ADV_1_MR_NP_MSG_UNFORM_CODE_FIELD                0x07FF

//AN_NP_ADV_2 register
#define DP83TD510_AN_NP_ADV_2_MR_NP_UNFORM_CODE_FIELD_1                  0xFFFF

//AN_NP_ADV_3 register
#define DP83TD510_AN_NP_ADV_3_MR_NP_UNFORM_CODE_FIELD_2                  0xFFFF

//AN_LP_NP_ADV_1 register
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_NP_ABILITY                     0x8000
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_ACK                            0x4000
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_MESSAGE_PAGE                   0x2000
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_ACK2                           0x1000
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_TOGGLE                         0x0800
#define DP83TD510_AN_LP_NP_ADV_1_MR_LP_NP_MSG_UNFORM_CODE_FIELD          0x07FF

//AN_LP_NP_ADV_2 register
#define DP83TD510_AN_LP_NP_ADV_2_MR_LP_NP_UNFORM_CODE_FIELD_1            0xFFFF

//AN_LP_NP_ADV_3 register
#define DP83TD510_AN_LP_NP_ADV_3_MR_LP_NP_UNFORM_CODE_FIELD_2            0xFFFF

//AN_CTRL_10BT1 register
#define DP83TD510_AN_CTRL_10BT1_MR_10BT1_L_CAPABILITY                    0x8000
#define DP83TD510_AN_CTRL_10BT1_MR_ABILITY_10BT1_L_EEE                   0x4000
#define DP83TD510_AN_CTRL_10BT1_MR_ABILITY_10BT1_L_INCR_TX_RX_LVL        0x2000
#define DP83TD510_AN_CTRL_10BT1_MR_10BT1_L_INCR_TX_RX_LVL_RQST           0x1000

//AN_STATUS_10BT1 register
#define DP83TD510_AN_STATUS_10BT1_MR_LP_10BT1_L_CAPABILITY               0x8000
#define DP83TD510_AN_STATUS_10BT1_MR_LP_ABILITY_10BT1_L_EEE              0x4000
#define DP83TD510_AN_STATUS_10BT1_MR_LP_ABILITY_10BT1_L_INCR_TX_RX_LVL   0x2000
#define DP83TD510_AN_STATUS_10BT1_MR_LP_10BT1_L_INCR_TX_RX_LVL_RQST      0x1000

//PRBS_CFG_1 register
#define DP83TD510_PRBS_CFG_1_SEND_PKT                                    0x1000
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_SEL                            0x0700
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_SEL_RGMII_TX                   0x0000
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_SEL_RMII_TX                    0x0200
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_SEL_MII_TX                     0x0300
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_SEL_CU_RX                      0x0500
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_GEN_SEL                            0x0070
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_GEN_SEL_RGMII_RX                   0x0000
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_GEN_SEL_RMII_RX                    0x0020
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_GEN_SEL_MII_RX                     0x0030
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_GEN_SEL_CU_TX                      0x0040
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CNT_MODE                           0x0008
#define DP83TD510_PRBS_CFG_1_CFG_PRBS_CHK_ENABLE                         0x0004
#define DP83TD510_PRBS_CFG_1_CFG_PKT_GEN_PRBS                            0x0002
#define DP83TD510_PRBS_CFG_1_PKT_GEN_EN                                  0x0001

//PRBS_CFG_2 register
#define DP83TD510_PRBS_CFG_2_CFG_PKT_LEN_PRBS                            0xFFFF

//PRBS_CFG_3 register
#define DP83TD510_PRBS_CFG_3_CFG_PRBS_FIX_PATT_EN                        0x1000
#define DP83TD510_PRBS_CFG_3_CFG_PRBS_FIX_PATT                           0x0F00
#define DP83TD510_PRBS_CFG_3_CFG_IPG_LEN                                 0x00FF

//PRBS_STATUS_1 register
#define DP83TD510_PRBS_STATUS_1_PRBS_BYTE_CNT                            0xFFFF

//PRBS_STATUS_2 register
#define DP83TD510_PRBS_STATUS_2_PRBS_PKT_CNT_15_0                        0xFFFF

//PRBS_STATUS_3 register
#define DP83TD510_PRBS_STATUS_3_PRBS_PKT_CNT_31_16                       0xFFFF

//PRBS_STATUS_4 register
#define DP83TD510_PRBS_STATUS_4_PRBS_SYNC_LOSS                           0x2000
#define DP83TD510_PRBS_STATUS_4_PKT_DONE                                 0x1000
#define DP83TD510_PRBS_STATUS_4_PKT_GEN_BUSY                             0x0800
#define DP83TD510_PRBS_STATUS_4_PRBS_PKT_OV                              0x0400
#define DP83TD510_PRBS_STATUS_4_PRBS_BYTE_OV                             0x0200
#define DP83TD510_PRBS_STATUS_4_PRBS_LOCK                                0x0100
#define DP83TD510_PRBS_STATUS_4_PRBS_ERR_CNT                             0x00FF

//PRBS_STATUS_5 register
#define DP83TD510_PRBS_STATUS_5_PRBS_ERR_OV_CNT                          0x00FF

//PRBS_STATUS_6 register
#define DP83TD510_PRBS_STATUS_6_PKT_ERR_CNT_15_0                         0xFFFF

//PRBS_STATUS_7 register
#define DP83TD510_PRBS_STATUS_7_PKT_ERR_CNT_31_16                        0xFFFF

//PRBS_CFG_4 register
#define DP83TD510_PRBS_CFG_4_PKT_ERR_CNT_31_16                           0xFF00
#define DP83TD510_PRBS_CFG_4_CFG_PKT_MODE                                0x00C0
#define DP83TD510_PRBS_CFG_4_CFG_PATTERN_VLD_BYTES                       0x0038
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT                                 0x0007
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_1_PKT                           0x0000
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_10_PKTS                         0x0001
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_100_PKTS                        0x0002
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_1000_PKTS                       0x0003
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_10000_PKTS                      0x0004
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_100000_PKTS                     0x0005
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_1000000_PKTS                    0x0006
#define DP83TD510_PRBS_CFG_4_CFG_PKT_CNT_CONTINUOUS_PKTS                 0x0007

//PRBS_CFG_5 register
#define DP83TD510_PRBS_CFG_5_PATTERN_15_0                                0xFFFF

//PRBS_CFG_6 register
#define DP83TD510_PRBS_CFG_6_PATTERN_31_16                               0xFFFF

//PRBS_CFG_7 register
#define DP83TD510_PRBS_CFG_7_PATTERN_47_32                               0xFFFF

//PRBS_CFG_8 register
#define DP83TD510_PRBS_CFG_8_PMATCH_DATA_15_0                            0xFFFF

//PRBS_CFG_9 register
#define DP83TD510_PRBS_CFG_9_PMATCH_DATA_31_16                           0xFFFF

//PRBS_CFG_10 register
#define DP83TD510_PRBS_CFG_10_PMATCH_DATA_47_32                          0xFFFF

//CRC_STATUS register
#define DP83TD510_CRC_STATUS_RX_BAD_CRC                                  0x0002
#define DP83TD510_CRC_STATUS_TX_BAD_CRC                                  0x0001

//PKT_STAT_1 register
#define DP83TD510_PKT_STAT_1_TX_PKT_CNT_15_0                             0xFFFF

//PKT_STAT_2 register
#define DP83TD510_PKT_STAT_2_TX_PKT_CNT_31_16                            0xFFFF

//PKT_STAT_3 register
#define DP83TD510_PKT_STAT_3_TX_ERR_PKT_CNT                              0xFFFF

//PKT_STAT_4 register
#define DP83TD510_PKT_STAT_4_RX_PKT_CNT_15_0                             0xFFFF

//PKT_STAT_5 register
#define DP83TD510_PKT_STAT_5_RX_PKT_CNT_31_16                            0xFFFF

//PKT_STAT_6 register
#define DP83TD510_PKT_STAT_6_RX_ERR_PKT_CNT                              0xFFFF

//TDR_CFG1 register
#define DP83TD510_TDR_CFG1_CFG_TDR_TX_TYPE                               0x1000
#define DP83TD510_TDR_CFG1_CFG_TDR_TX_TYPE_1V0                           0x0000
#define DP83TD510_TDR_CFG1_CFG_TDR_TX_TYPE_2V4                           0x1000
#define DP83TD510_TDR_CFG1_CFG_FORWARD_SHADOW_2                          0x0F00
#define DP83TD510_TDR_CFG1_CFG_FORWARD_SHADOW_1                          0x00F0
#define DP83TD510_TDR_CFG1_CFG_POST_SILENCE_TIME                         0x000C
#define DP83TD510_TDR_CFG1_CFG_PRE_SILENCE_TIME                          0x0003

//TDR_CFG2 register
#define DP83TD510_TDR_CFG2_CFG_END_TAP_INDEX_1                           0x7F00
#define DP83TD510_TDR_CFG2_CFG_START_TAP_INDEX_1                         0x007F

//TDR_CFG3 register
#define DP83TD510_TDR_CFG3_CFG_TDR_TX_DURATION                           0xFFFF

//FAULT_CFG1 register
#define DP83TD510_FAULT_CFG1_CFG_TDR_FLT_LOC_OFFSET_1                    0x7F00
#define DP83TD510_FAULT_CFG1_CFG_TDR_FLT_INIT_1                          0x00FF

//FAULT_CFG2 register
#define DP83TD510_FAULT_CFG2_CFG_TDR_FLT_SLOPE_1                         0x00FF

//FAULT_STAT1 register
#define DP83TD510_FAULT_STAT1_PEAKS_LOC_1                                0x7F00
#define DP83TD510_FAULT_STAT1_PEAKS_LOC_0                                0x007F

//FAULT_STAT2 register
#define DP83TD510_FAULT_STAT2_PEAKS_LOC_3                                0x7F00
#define DP83TD510_FAULT_STAT2_PEAKS_LOC_2                                0x007F

//FAULT_STAT3 register
#define DP83TD510_FAULT_STAT3_PEAKS_AMP_0                                0xFF00
#define DP83TD510_FAULT_STAT3_PEAKS_LOC_4                                0x007F

//FAULT_STAT4 register
#define DP83TD510_FAULT_STAT4_PEAKS_AMP_2                                0xFF00
#define DP83TD510_FAULT_STAT4_PEAKS_AMP_1                                0x00FF

//FAULT_STAT5 register
#define DP83TD510_FAULT_STAT5_PEAKS_AMP_1                                0xFF00
#define DP83TD510_FAULT_STAT5_PEAKS_AMP_3                                0x00FF

//FAULT_STAT6 register
#define DP83TD510_FAULT_STAT6_PEAKS_SIGN_4                               0x0010
#define DP83TD510_FAULT_STAT6_PEAKS_SIGN_3                               0x0008
#define DP83TD510_FAULT_STAT6_PEAKS_SIGN_2                               0x0004
#define DP83TD510_FAULT_STAT6_PEAKS_SIGN_1                               0x0002
#define DP83TD510_FAULT_STAT6_PEAKS_SIGN_0                               0x0001

//CHIP_SOR_0 register
#define DP83TD510_CHIP_SOR_0_READ_STRAP_TERM_SL                          0x0040

//LEDS_CFG_1 register
#define DP83TD510_LEDS_CFG_1_LEDS_BYPASS_STRETCHING                      0x4000
#define DP83TD510_LEDS_CFG_1_LEDS_BLINK_RATE                             0x3000
#define DP83TD510_LEDS_CFG_1_LEDS_BLINK_RATE_20HZ                        0x0000
#define DP83TD510_LEDS_CFG_1_LEDS_BLINK_RATE_10HZ                        0x1000
#define DP83TD510_LEDS_CFG_1_LEDS_BLINK_RATE_5HZ                         0x2000
#define DP83TD510_LEDS_CFG_1_LEDS_BLINK_RATE_2HZ                         0x3000
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION                                0x0F00
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_LINK_OK                        0x0000
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_TX_RX_ACT                      0x0100
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_TX_ACT                         0x0200
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_RX_ACT                         0x0300
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_LR                             0x0400
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_SR                             0x0500
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_SPEED                          0x0600
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_DUPLEX                         0x0700
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_LINK_ACT_BLINK                 0x0800
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_TX_RX_ACT_BLINK                0x0900
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_TX_BLINK                       0x0A00
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_RX_BLINK                       0x0B00
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_LINK_LOST                      0x0C00
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_PRBS_ERROR                     0x0D00
#define DP83TD510_LEDS_CFG_1_LED_2_OPTION_XMII_TX_RX_ERROR               0x0E00
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION                                0x00F0
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_LINK_OK                        0x0000
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_TX_RX_ACT                      0x0010
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_TX_ACT                         0x0020
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_RX_ACT                         0x0030
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_LR                             0x0040
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_SR                             0x0050
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_SPEED                          0x0060
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_DUPLEX                         0x0070
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_LINK_ACT_BLINK                 0x0080
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_TX_RX_ACT_BLINK                0x0090
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_TX_BLINK                       0x00A0
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_RX_BLINK                       0x00B0
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_LINK_LOST                      0x00C0
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_PRBS_ERROR                     0x00D0
#define DP83TD510_LEDS_CFG_1_LED_1_OPTION_XMII_TX_RX_ERROR               0x00E0
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION                                0x000F
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_LINK_OK                        0x0000
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_TX_RX_ACT                      0x0001
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_TX_ACT                         0x0002
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_RX_ACT                         0x0003
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_LR                             0x0004
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_SR                             0x0005
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_SPEED                          0x0006
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_DUPLEX                         0x0007
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_LINK_ACT_BLINK                 0x0008
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_TX_RX_ACT_BLINK                0x0009
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_TX_BLINK                       0x000A
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_RX_BLINK                       0x000B
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_LINK_LOST                      0x000C
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_PRBS_ERROR                     0x000D
#define DP83TD510_LEDS_CFG_1_LED_0_OPTION_XMII_TX_RX_ERROR               0x000E

//IO_MUX_CFG register
#define DP83TD510_IO_MUX_CFG_IO_OE_N_VALUE                               0x8000
#define DP83TD510_IO_MUX_CFG_IO_OE_N_VALUE_OUTPUT                        0x0000
#define DP83TD510_IO_MUX_CFG_IO_OE_N_VALUE_INPUT                         0x8000
#define DP83TD510_IO_MUX_CFG_IO_OE_N_FORCE_CTRL                          0x4000
#define DP83TD510_IO_MUX_CFG_PUPD_VALUE                                  0x3000
#define DP83TD510_IO_MUX_CFG_PUPD_FORCE_CNTL                             0x0800
#define DP83TD510_IO_MUX_CFG_IMPEDANCE_CTRL                              0x0030
#define DP83TD510_IO_MUX_CFG_MAC_RX_IMPEDANCE_CTRL                       0x000C
#define DP83TD510_IO_MUX_CFG_MAC_TX_IMPEDANCE_CTRL                       0x0003

//IO_MUX_GPIO_CTRL_1 register
#define DP83TD510_IO_MUX_GPIO_CTRL_1_MAC_TX_IMPEDANCE_CTRL               0x8000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE                    0x7000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_XI_CLK             0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_LD_30MHZ_CLK       0x1000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_30MHZ_ADC_CLK      0x2000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_FREE_60MHZ_CLK     0x3000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_7_5MHZ_CLK         0x4000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_25MHZ_CLK          0x5000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_SOURCE_2_5MHZ_CLK         0x6000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_CLK_INV_EN                    0x0800
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL                     0x0700
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL_LED_2               0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL_CLK_OUT             0x0100
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL_INTERRUPT           0x0200
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL_LOW                 0x0600
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_2_GPIO_CTRL_HIGH                0x0700
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_DIV_2_EN                  0x0080
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE                    0x0070
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_XI_CLK             0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_LD_30MHZ_CLK       0x0010
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_30MHZ_ADC_CLK      0x0020
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_FREE_60MHZ_CLK     0x0030
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_7_5MHZ_CLK         0x0040
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_25MHZ_CLK          0x0050
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_SOURCE_2_5MHZ_CLK         0x0060
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_CLK_INV_EN                    0x0008
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL                     0x0007
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL_LED_0               0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL_CLK_OUT             0x0001
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL_INTERRUPT           0x0002
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL_LOW                 0x0006
#define DP83TD510_IO_MUX_GPIO_CTRL_1_LED_0_GPIO_CTRL_HIGH                0x0007

//IO_MUX_GPIO_CTRL_2 register
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE                     0xE000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_XI_CLK              0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_LD_30MHZ_CLK        0x2000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_30MHZ_ADC_CLK       0x4000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_FREE_60MHZ_CLK      0x6000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_7_5MHZ_CLK          0x8000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_25MHZ_CLK           0xA000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CLK_SOURCE_2_5MHZ_CLK          0xC000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL                           0x1C00
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL_LED_1                     0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL_CLK_OUT                   0x0400
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL_INTERRUPT                 0x0800
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL_LOW                       0x1800
#define DP83TD510_IO_MUX_GPIO_CTRL_2_GPIO_CTRL_HIGH                      0x1C00
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CFG_TX_ER_ON_LED2                   0x0200
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_DIV_2_EN                  0x0100
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE                    0x00F0
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_XI_CLK             0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_LD_30MHZ_CLK       0x0010
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_30MHZ_ADC_CLK      0x0020
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_FREE_60MHZ_CLK     0x0030
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_7_5MHZ_CLK         0x0040
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_25MHZ_CLK          0x0050
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_2_5MHZ_CLK         0x0060
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_25_50MHZ_CLK       0x0080
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_RMII_RX_50MHz_CLK  0x0090
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_RMII_TX_50MHZ_CLK  0x00A0
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_MII_RX_CLK         0x00B0
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_RGMII_RX_ALIGN_CLK 0x00C0
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_SOURCE_RGMII_RX_SHIFT_CLK 0x00D0
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_CLK_INV_EN                    0x0008
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL                     0x0007
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL_LED_1               0x0000
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL_CLK_OUT             0x0001
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL_INTERRUPT           0x0002
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL_LOW                 0x0006
#define DP83TD510_IO_MUX_GPIO_CTRL_2_CLK_O_GPIO_CTRL_HIGH                0x0007

//CHIP_SOR_1 register
#define DP83TD510_CHIP_SOR_1_SOR_15_0                                    0xFFFF
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_D3                              0x0001
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_D2                              0x0002
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_D1                              0x0004
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_D0                              0x0008
#define DP83TD510_CHIP_SOR_1_SOR_15_0_CLK_OUT_LED_1                      0x0010
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_CTRL                            0x0020
#define DP83TD510_CHIP_SOR_1_SOR_15_0_RX_ER                              0x0040
#define DP83TD510_CHIP_SOR_1_SOR_15_0_LED_2                              0x0080
#define DP83TD510_CHIP_SOR_1_SOR_15_0_LED_0                              0x0100
#define DP83TD510_CHIP_SOR_1_SOR_15_0_GPIO                               0x0200

//CHIP_SOR_2 register
#define DP83TD510_CHIP_SOR_2_SOR_19_16                                   0x000F

//LEDS_CFG_2 register
#define DP83TD510_LEDS_CFG_2_LED_2_POLARITY                              0x0400
#define DP83TD510_LEDS_CFG_2_LED_2_POLARITY_LOW                          0x0000
#define DP83TD510_LEDS_CFG_2_LED_2_POLARITY_HIGH                         0x0400
#define DP83TD510_LEDS_CFG_2_LED_2_DRV_VAL                               0x0200
#define DP83TD510_LEDS_CFG_2_LED_2_DRV_EN                                0x0100
#define DP83TD510_LEDS_CFG_2_LED_1_POLARITY                              0x0040
#define DP83TD510_LEDS_CFG_2_LED_1_POLARITY_LOW                          0x0000
#define DP83TD510_LEDS_CFG_2_LED_1_POLARITY_HIGH                         0x0040
#define DP83TD510_LEDS_CFG_2_LED_1_DRV_VAL                               0x0020
#define DP83TD510_LEDS_CFG_2_LED_1_DRV_EN                                0x0010
#define DP83TD510_LEDS_CFG_2_LED_0_POLARITY                              0x0004
#define DP83TD510_LEDS_CFG_2_LED_0_POLARITY_LOW                          0x0000
#define DP83TD510_LEDS_CFG_2_LED_0_POLARITY_HIGH                         0x0004
#define DP83TD510_LEDS_CFG_2_LED_0_DRV_VAL                               0x0002
#define DP83TD510_LEDS_CFG_2_LED_0_DRV_EN                                0x0001

//AN_STAT_1 register
#define DP83TD510_AN_STAT_1_MASTER_SLAVE_RESOL_FAIL                      0x8000
#define DP83TD510_AN_STAT_1_AN_STATE                                     0x7000
#define DP83TD510_AN_STAT_1_HD_STATE                                     0x0700
#define DP83TD510_AN_STAT_1_RX_STATE                                     0x0070
#define DP83TD510_AN_STAT_1_AN_TX_STATE                                  0x000F

//DSP_REG_72 register
#define DP83TD510_DSP_REG_72_MSE_SQI                                     0x03FF

//DSP_REG_8D register
#define DP83TD510_DSP_REG_8D_CFG_ALCD_2P4_METRIC_STEP_1                  0x0FFF

//DSP_REG_8E register
#define DP83TD510_DSP_REG_8E_CFG_ALCD_2P4_METRIC_STEP_2                  0x0FFF

//DSP_REG_8F register
#define DP83TD510_DSP_REG_8F_CFG_ALCD_2P4_METRIC_STEP_3                  0x0FFF

//DSP_REG_90 register
#define DP83TD510_DSP_REG_90_CFG_ALCD_2P4_METRIC_STEP_4                  0x0FFF

//DSP_REG_91 register
#define DP83TD510_DSP_REG_91_CFG_ALCD_2P4_METRIC_STEP_5                  0x0FFF

//DSP_REG_92 register
#define DP83TD510_DSP_REG_92_CFG_ALCD_2P4_METRIC_STEP_6                  0x0FFF

//DSP_REG_98 register
#define DP83TD510_DSP_REG_98_CFG_ALCD_1P0_METRIC_STEP_1                  0x0FFF

//DSP_REG_99 register
#define DP83TD510_DSP_REG_99_CFG_ALCD_1P0_METRIC_STEP_2                  0x0FFF

//DSP_REG_9A register
#define DP83TD510_DSP_REG_9A_CFG_ALCD_1P0_METRIC_STEP_3                  0x0FFF

//DSP_REG_9B register
#define DP83TD510_DSP_REG_9B_CFG_ALCD_1P0_METRIC_STEP_4                  0x0FFF

//DSP_REG_9C register
#define DP83TD510_DSP_REG_9C_CFG_ALCD_1P0_METRIC_STEP_5                  0x0FFF

//DSP_REG_9D register
#define DP83TD510_DSP_REG_9D_CFG_ALCD_1P0_METRIC_STEP_6                  0x0FFF

//DSP_REG_E9 register
#define DP83TD510_DSP_REG_E9_CFG_ALCD_CABLE_0                            0x00FF

//DSP_REG_EA register
#define DP83TD510_DSP_REG_EA_CFG_ALCD_CABLE_1                            0x00FF

//DSP_REG_EB register
#define DP83TD510_DSP_REG_EB_CFG_ALCD_CABLE_2                            0x00FF

//DSP_REG_EC register
#define DP83TD510_DSP_REG_EC_CFG_ALCD_CABLE_3                            0x00FF

//DSP_REG_ED register
#define DP83TD510_DSP_REG_ED_CFG_ALCD_CABLE_4                            0x00FF

//DSP_REG_EE register
#define DP83TD510_DSP_REG_EE_CFG_ALCD_CABLE_5                            0x00FF

//MSE_DETECT register
#define DP83TD510_MSE_DETECT_SQI                                         0xFFFF
#define DP83TD510_MSE_DETECT_SQI_GOOD                                    0x0320
#define DP83TD510_MSE_DETECT_SQI_POOR                                    0x0660

//ALCD_METRIC register
#define DP83TD510_ALCD_METRIC_ALCD_METRIC_VALUE                          0xFFF0

//ALCD_STATUS register
#define DP83TD510_ALCD_STATUS_ALCD_COMPLETE                              0x8000
#define DP83TD510_ALCD_STATUS_ALCD_CABLE_LENGTH                          0x07FF

//SCAN_2 register
#define DP83TD510_SCAN_2_SCAN_STATE_SAF                                  0x01F0
#define DP83TD510_SCAN_2_CFG_EN_EFUSE_BURN                               0x0008

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DP83TD510 Ethernet PHY driver
extern const PhyDriver dp83td510PhyDriver;

//DP83TD510 related functions
error_t dp83td510Init(NetInterface *interface);
void dp83td510InitHook(NetInterface *interface);

void dp83td510Tick(NetInterface *interface);

void dp83td510EnableIrq(NetInterface *interface);
void dp83td510DisableIrq(NetInterface *interface);

void dp83td510EventHandler(NetInterface *interface);

void dp83td510WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t dp83td510ReadPhyReg(NetInterface *interface, uint8_t address);

void dp83td510DumpPhyReg(NetInterface *interface);

void dp83td510WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t dp83td510ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
