/**
 * @file dp83869_driver.h
 * @brief DP83869 Gigabit Ethernet PHY driver
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

#ifndef _DP83869_DRIVER_H
#define _DP83869_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef DP83869_PHY_ADDR
   #define DP83869_PHY_ADDR 0
#elif (DP83869_PHY_ADDR < 0 || DP83869_PHY_ADDR > 31)
   #error DP83869_PHY_ADDR parameter is not valid
#endif

//DP83869 PHY registers
#define DP83869_BMCR                                           0x00
#define DP83869_BMSR                                           0x01
#define DP83869_PHYIDR1                                        0x02
#define DP83869_PHYIDR2                                        0x03
#define DP83869_ANAR                                           0x04
#define DP83869_ANLPAR                                         0x05
#define DP83869_ANER                                           0x06
#define DP83869_ANNPTR                                         0x07
#define DP83869_ANLNPTR                                        0x08
#define DP83869_GEN_CFG1                                       0x09
#define DP83869_GEN_STATUS1                                    0x0A
#define DP83869_REGCR                                          0x0D
#define DP83869_ADDAR                                          0x0E
#define DP83869_1KSCR                                          0x0F
#define DP83869_PHY_CONTROL                                    0x10
#define DP83869_PHY_STATUS                                     0x11
#define DP83869_INTERRUPT_MASK                                 0x12
#define DP83869_INTERRUPT_STATUS                               0x13
#define DP83869_GEN_CFG                                        0x14
#define DP83869_RX_ERR_CNT                                     0x15
#define DP83869_BIST_CONTROL                                   0x16
#define DP83869_GEN_STATUS2                                    0x17
#define DP83869_LEDS_CFG1                                      0x18
#define DP83869_LEDS_CFG2                                      0x19
#define DP83869_LEDS_CFG3                                      0x1A
#define DP83869_GEN_CFG4                                       0x1E
#define DP83869_GEN_CTRL                                       0x1F

//DP83869 MMD registers
#define DP83869_ANALOG_TEST_CTR                                0x1F, 0x0025
#define DP83869_GEN_CFG_ENH_AMIX                               0x1F, 0x002C
#define DP83869_GEN_CFG_FLD                                    0x1F, 0x002D
#define DP83869_GEN_CFG_FLD_THR                                0x1F, 0x002E
#define DP83869_GEN_CFG3                                       0x1F, 0x0031
#define DP83869_RGMII_CTRL                                     0x1F, 0x0032
#define DP83869_RGMII_CTRL2                                    0x1F, 0x0033
#define DP83869_SGMII_AUTO_NEG_STATUS                          0x1F, 0x0037
#define DP83869_PRBS_TX_CHK_CTRL                               0x1F, 0x0039
#define DP83869_PRBS_TX_CHK_BYTE_CNT                           0x1F, 0x003A
#define DP83869_G_100BT_REG0                                   0x1F, 0x0043
#define DP83869_SERDES_SYNC_STS                                0x1F, 0x004F
#define DP83869_STRAP_STS                                      0x1F, 0x006E
#define DP83869_ANA_RGMII_DLL_CTRL                             0x1F, 0x0086
#define DP83869_RXF_CFG                                        0x1F, 0x0134
#define DP83869_RXF_STATUS                                     0x1F, 0x0135
#define DP83869_IO_MUX_CFG                                     0x1F, 0x0170
#define DP83869_TDR_GEN_CFG1                                   0x1F, 0x0180
#define DP83869_TDR_GEN_CFG2                                   0x1F, 0x0181
#define DP83869_TDR_SEG_DURATION                               0x1F, 0x0182
#define DP83869_TDR_SEG_DURATION2                              0x1F, 0x0183
#define DP83869_TDR_GEN_CFG3                                   0x1F, 0x0184
#define DP83869_TDR_GEN_CFG4                                   0x1F, 0x0185
#define DP83869_TDR_PEAKS_LOC_A_0_1                            0x1F, 0x0190
#define DP83869_TDR_PEAKS_LOC_A_2_3                            0x1F, 0x0191
#define DP83869_TDR_PEAKS_LOC_A_4_B_0                          0x1F, 0x0192
#define DP83869_TDR_PEAKS_LOC_B_1_2                            0x1F, 0x0193
#define DP83869_TDR_PEAKS_LOC_B_3_4                            0x1F, 0x0194
#define DP83869_TDR_PEAKS_LOC_C_0_1                            0x1F, 0x0195
#define DP83869_TDR_PEAKS_LOC_C_2_3                            0x1F, 0x0196
#define DP83869_TDR_PEAKS_LOC_C_4_D_0                          0x1F, 0x0197
#define DP83869_TDR_PEAKS_LOC_D_1_2                            0x1F, 0x0198
#define DP83869_TDR_PEAKS_LOC_D_3_4                            0x1F, 0x0199
#define DP83869_TDR_GEN_STATUS                                 0x1F, 0x01A4
#define DP83869_TDR_PEAKS_SIGN_A_B                             0x1F, 0x01A5
#define DP83869_TDR_PEAKS_SIGN_C_D                             0x1F, 0x01A6
#define DP83869_OP_MODE_DECODE                                 0x1F, 0x01DF
#define DP83869_GPIO_MUX_CTRL                                  0x1F, 0x01E0
#define DP83869_FX_CTRL                                        0x1F, 0x0C00
#define DP83869_FX_STS                                         0x1F, 0x0C01
#define DP83869_FX_PHYID1                                      0x1F, 0x0C02
#define DP83869_FX_PHYID2                                      0x1F, 0x0C03
#define DP83869_FX_ANADV                                       0x1F, 0x0C04
#define DP83869_FX_LPABL                                       0x1F, 0x0C05
#define DP83869_FX_ANEXP                                       0x1F, 0x0C06
#define DP83869_FX_LOCNP                                       0x1F, 0x0C07
#define DP83869_FX_LPNP                                        0x1F, 0x0C08
#define DP83869_FX_INT_EN                                      0x1F, 0x0C18
#define DP83869_FX_INT_STS                                     0x1F, 0x0C19

//BMCR register
#define DP83869_BMCR_RESET                                     0x8000
#define DP83869_BMCR_MII_LOOPBACK                              0x4000
#define DP83869_BMCR_SPEED_SEL_LSB                             0x2000
#define DP83869_BMCR_AUTONEG_EN                                0x1000
#define DP83869_BMCR_PWD_DWN                                   0x0800
#define DP83869_BMCR_ISOLATE                                   0x0400
#define DP83869_BMCR_RSTRT_AUTONEG                             0x0200
#define DP83869_BMCR_DUPLEX_EN                                 0x0100
#define DP83869_BMCR_COL_TST                                   0x0080
#define DP83869_BMCR_SPEED_SEL_MSB                             0x0040

//BMSR register
#define DP83869_BMSR_100M_FDUP                                 0x4000
#define DP83869_BMSR_100M_HDUP                                 0x2000
#define DP83869_BMSR_10M_FDUP                                  0x1000
#define DP83869_BMSR_10M_HDUP                                  0x0800
#define DP83869_BMSR_EXT_STS                                   0x0100
#define DP83869_BMSR_MF_PREAMBLE_SUP                           0x0040
#define DP83869_BMSR_AUTONEG_COMP                              0x0020
#define DP83869_BMSR_REMOTE_FAULT                              0x0010
#define DP83869_BMSR_AUTONEG_ABL                               0x0008
#define DP83869_BMSR_LINK_STS1                                 0x0004
#define DP83869_BMSR_JABBER_DTCT                               0x0002
#define DP83869_BMSR_EXT_CAPBLTY                               0x0001

//PHYIDR1 register
#define DP83869_PHYIDR1_OUI_MSB                                0xFFFF
#define DP83869_PHYIDR1_OUI_MSB_DEFAULT                        0x2000

//PHYIDR2 register
#define DP83869_PHYIDR2_OUI_LSB                                0xFC00
#define DP83869_PHYIDR2_OUI_LSB_DEFAULT                        0xA000
#define DP83869_PHYIDR2_VNDR_MDL                               0x03F0
#define DP83869_PHYIDR2_VNDR_MDL_DEFAULT                       0x00F0
#define DP83869_PHYIDR2_MDL_REV                                0x000F
#define DP83869_PHYIDR2_MDL_REV_DEFAULT                        0x0001

//ANAR register
#define DP83869_ANAR_NEXT_PAGE_1_ADV                           0x8000
#define DP83869_ANAR_REMOTE_FAULT_ADV                          0x2000
#define DP83869_ANAR_ASYMMETRIC_PAUSE_ADV                      0x0800
#define DP83869_ANAR_PAUSE_ADV                                 0x0400
#define DP83869_ANAR_G_100BT_4_ADV                             0x0200
#define DP83869_ANAR_G_100BTX_FD_ADV                           0x0100
#define DP83869_ANAR_G_100BTX_HD_ADV                           0x0080
#define DP83869_ANAR_G_10BT_FD_ADV                             0x0040
#define DP83869_ANAR_G_10BT_HD_ADV                             0x0020
#define DP83869_ANAR_SELECTOR_FIELD_ADV                        0x001F
#define DP83869_ANAR_SELECTOR_FIELD_ADV_DEFAULT                0x0001

//ANLPAR register
#define DP83869_ANLPAR_NEXT_PAGE_1_LP                          0x8000
#define DP83869_ANLPAR_ACKNOWLEDGE_1_LP                        0x4000
#define DP83869_ANLPAR_REMOTE_FAULT_LP                         0x2000
#define DP83869_ANLPAR_ASYMMETRIC_PAUSE_LP                     0x0800
#define DP83869_ANLPAR_PAUSE_LP                                0x0400
#define DP83869_ANLPAR_G_100BT4_LP                             0x0200
#define DP83869_ANLPAR_G_100BTX_FD_LP                          0x0100
#define DP83869_ANLPAR_G_100BTX_HD_LP                          0x0080
#define DP83869_ANLPAR_G_10BT_FD_LP                            0x0040
#define DP83869_ANLPAR_G_10BT_HD_LP                            0x0020
#define DP83869_ANLPAR_SELECTOR_FIELD_LP                       0x001F

//ANER register
#define DP83869_ANER_RX_NEXT_PAGE_LOC_ABLE                     0x0040
#define DP83869_ANER_RX_NEXT_PAGE_STOR_LOC                     0x0020
#define DP83869_ANER_PRLL_TDCT_FAULE                           0x0010
#define DP83869_ANER_LP_NP_ABLE                                0x0008
#define DP83869_ANER_LOCAL_NP_ABLE                             0x0004
#define DP83869_ANER_PAGE_RECEIVED_1                           0x0002
#define DP83869_ANER_LP_AUTONEG_ABLE                           0x0001

//ANNPTR register
#define DP83869_ANNPTR_NEXT_PAGE_2_ADV                         0x8000
#define DP83869_ANNPTR_MESSAGE_PAGE                            0x2000
#define DP83869_ANNPTR_ACKNOWLEDGE2                            0x1000
#define DP83869_ANNPTR_TOGGLE                                  0x0800
#define DP83869_ANNPTR_MESSAGE_UNFORMATTED                     0x07FF

//ANLNPTR register
#define DP83869_ANLNPTR_NEXT_PAGE_2_LP                         0x8000
#define DP83869_ANLNPTR_ACKNOWLEDGE_2_LP                       0x4000
#define DP83869_ANLNPTR_MESSAGE_PAGE_LP                        0x2000
#define DP83869_ANLNPTR_ACKNOWLEDGE2_LP                        0x1000
#define DP83869_ANLNPTR_TOGGLE_LP                              0x0800
#define DP83869_ANLNPTR_MESSAGE_UNFORMATTED_LP                 0x07FF

//GEN_CFG1 register
#define DP83869_GEN_CFG1_TEST_MODE                             0xE000
#define DP83869_GEN_CFG1_MASTER_SLAVE_MAN_CFG_EN               0x1000
#define DP83869_GEN_CFG1_MASTER_SLAVE_MAN_CFG_VAL              0x0800
#define DP83869_GEN_CFG1_PORT_TYPE                             0x0400
#define DP83869_GEN_CFG1_G_1000BT_FD_ADV                       0x0200
#define DP83869_GEN_CFG1_G_1000BT_HD_ADV                       0x0100
#define DP83869_GEN_CFG1_TDR_AUTO_RUN                          0x0080

//GEN_STATUS1 register
#define DP83869_GEN_STATUS1_MS_CONFIG_FAULT                    0x8000
#define DP83869_GEN_STATUS1_MS_CONFIG_RES                      0x4000
#define DP83869_GEN_STATUS1_LOC_RCVR_STATUS_1                  0x2000
#define DP83869_GEN_STATUS1_REM_RCVR_STATUS                    0x1000
#define DP83869_GEN_STATUS1_LP_1000BT_FD_ABILITY               0x0800
#define DP83869_GEN_STATUS1_LP_1000BT_HD_ABILITY               0x0400
#define DP83869_GEN_STATUS1_IDLE_ERR_COUNT                     0x00FF

//REGCR register
#define DP83869_REGCR_FUNC                                     0xC000
#define DP83869_REGCR_FUNC_ADDR                                0x0000
#define DP83869_REGCR_FUNC_DATA_NO_POST_INC                    0x4000
#define DP83869_REGCR_FUNC_DATA_POST_INC_RW                    0x8000
#define DP83869_REGCR_FUNC_DATA_POST_INC_W                     0xC000
#define DP83869_REGCR_DEVAD                                    0x001F

//1KSCR register
#define DP83869_1KSCR_G_1000BX_FD                              0x8000
#define DP83869_1KSCR_G_1000BX_HD                              0x4000
#define DP83869_1KSCR_G_1000BT_FD                              0x2000
#define DP83869_1KSCR_G_1000BT_HD                              0x1000

//PHY_CONTROL register
#define DP83869_PHY_CONTROL_TX_FIFO_DEPTH                      0xC000
#define DP83869_PHY_CONTROL_RX_FIFO_DEPTH                      0x3000
#define DP83869_PHY_CONTROL_FORCE_LINK_GOOD                    0x0400
#define DP83869_PHY_CONTROL_POWER_SAVE_MODE                    0x0300
#define DP83869_PHY_CONTROL_MDI_CROSSOVER_MODE                 0x0060
#define DP83869_PHY_CONTROL_DISABLE_CLK_125                    0x0010
#define DP83869_PHY_CONTROL_LINE_DRIVER_INV_EN                 0x0002
#define DP83869_PHY_CONTROL_DISABLE_JABBER                     0x0001

//PHY_STATUS register
#define DP83869_PHY_STATUS_SPEED_SEL                           0xC000
#define DP83869_PHY_STATUS_SPEED_SEL_10MBPS                    0x0000
#define DP83869_PHY_STATUS_SPEED_SEL_100MBPS                   0x4000
#define DP83869_PHY_STATUS_SPEED_SEL_1000MBPS                  0x8000
#define DP83869_PHY_STATUS_DUPLEX_MODE_ENV                     0x2000
#define DP83869_PHY_STATUS_PAGE_RECEIVED_2                     0x1000
#define DP83869_PHY_STATUS_SPEED_DUPLEX_RESOLVED               0x0800
#define DP83869_PHY_STATUS_LINK_STATUS_2                       0x0400
#define DP83869_PHY_STATUS_MDI_X_MODE_CD_1                     0x0200
#define DP83869_PHY_STATUS_MDI_X_MODE_AB_1                     0x0100
#define DP83869_PHY_STATUS_SPEED_OPT_STATUS                    0x0080
#define DP83869_PHY_STATUS_SLEEP_MODE                          0x0040
#define DP83869_PHY_STATUS_WIRE_CROSS                          0x003C
#define DP83869_PHY_STATUS_DATA_POLARITY                       0x0002
#define DP83869_PHY_STATUS_JABBER_DTCT_2                       0x0001

//INTERRUPT_MASK register
#define DP83869_INTERRUPT_MASK_AUTONEG_ERR_INT_EN              0x8000
#define DP83869_INTERRUPT_MASK_SPEED_CHNG_INT_EN               0x4000
#define DP83869_INTERRUPT_MASK_DUPLEX_MODE_CHNG_INT_EN         0x2000
#define DP83869_INTERRUPT_MASK_PAGE_RECEIVED_INT_EN            0x1000
#define DP83869_INTERRUPT_MASK_AUTONEG_COMP_INT_EN             0x0800
#define DP83869_INTERRUPT_MASK_LINK_STATUS_CHNG_INT_EN         0x0400
#define DP83869_INTERRUPT_MASK_EEE_ERR_INT_EN                  0x0200
#define DP83869_INTERRUPT_MASK_FALSE_CARRIER_INT_EN            0x0100
#define DP83869_INTERRUPT_MASK_ADC_FIFO_OVF_UNF_INT_EN         0x0080
#define DP83869_INTERRUPT_MASK_MDI_CROSSOVER_CHNG_INT_EN       0x0040
#define DP83869_INTERRUPT_MASK_SPEED_OPT_EVENT_INT_EN          0x0020
#define DP83869_INTERRUPT_MASK_SLEEP_MODE_CHNG_INT_EN          0x0010
#define DP83869_INTERRUPT_MASK_WOL_INT_EN                      0x0008
#define DP83869_INTERRUPT_MASK_XGMII_ERR_INT_EN                0x0004
#define DP83869_INTERRUPT_MASK_POLARITY_CHNG_INT_EN            0x0002
#define DP83869_INTERRUPT_MASK_JABBER_INT_EN                   0x0001

//INTERRUPT_STATUS register
#define DP83869_INTERRUPT_STATUS_AUTONEG_ERR                   0x8000
#define DP83869_INTERRUPT_STATUS_SPEED_CHNG                    0x4000
#define DP83869_INTERRUPT_STATUS_DUPLEX_MODE_CHNG              0x2000
#define DP83869_INTERRUPT_STATUS_PAGE_RECEIVED                 0x1000
#define DP83869_INTERRUPT_STATUS_AUTONEG_COMP                  0x0800
#define DP83869_INTERRUPT_STATUS_LINK_STATUS_CHNG              0x0400
#define DP83869_INTERRUPT_STATUS_EEE_ERR_STATUS                0x0200
#define DP83869_INTERRUPT_STATUS_FALSE_CARRIER                 0x0100
#define DP83869_INTERRUPT_STATUS_ADC_FIFO_OVF_UNF              0x0080
#define DP83869_INTERRUPT_STATUS_MDI_CROSSOVER_CHNG            0x0040
#define DP83869_INTERRUPT_STATUS_SPEED_OPT_EVENT               0x0020
#define DP83869_INTERRUPT_STATUS_SLEEP_MODE_CHNG               0x0010
#define DP83869_INTERRUPT_STATUS_WOL                           0x0008
#define DP83869_INTERRUPT_STATUS_XGMII_ERR                     0x0004
#define DP83869_INTERRUPT_STATUS_POLARITY_CHNG                 0x0002
#define DP83869_INTERRUPT_STATUS_JABBER                        0x0001

//GEN_CFG register
#define DP83869_GEN_CFG_PD_DETECT_EN                           0x8000
#define DP83869_GEN_CFG_SGMII_TX_ERR_DIS                       0x4000
#define DP83869_GEN_CFG_INTERRUPT_POLARITY                     0x2000
#define DP83869_GEN_CFG_SGMII_SOFT_RESET                       0x1000
#define DP83869_GEN_CFG_SPEED_OPT_ATTEMPT_CNT                  0x0C00
#define DP83869_GEN_CFG_SPEED_OPT_EN                           0x0200
#define DP83869_GEN_CFG_SPEED_OPT_ENHANCED_EN                  0x0100
#define DP83869_GEN_CFG_SGMII_AUTONEG_EN                       0x0080
#define DP83869_GEN_CFG_SPEED_OPT_10M_EN                       0x0040
#define DP83869_GEN_CFG_MII_CLK_CFG                            0x0030
#define DP83869_GEN_CFG_COL_FD_EN                              0x0008
#define DP83869_GEN_CFG_LEGACY_CODING_TXMODE_EN                0x0004
#define DP83869_GEN_CFG_MASTER_SEMI_CROSS_EN                   0x0002
#define DP83869_GEN_CFG_SLAVE_SEMI_CROSS_EN                    0x0001

//RX_ERR_CNT register
#define DP83869_RX_ERR_CNT_RX_ERROR_COUNT                      0xFFFF

//BIST_CONTROL register
#define DP83869_BIST_CONTROL_PACKET_GEN_EN_3_0                 0xF000
#define DP83869_BIST_CONTROL_REV_LOOP_RX_DATA_CTRL             0x0080
#define DP83869_BIST_CONTROL_MII_LOOP_TX_DATA_CTRL             0x0040
#define DP83869_BIST_CONTROL_LOOP_TX_DATA_MIX                  0x003C
#define DP83869_BIST_CONTROL_LOOPBACK_MODE                     0x0003
#define DP83869_BIST_CONTROL_LOOPBACK_MODE_BEFORE_SCRAMBLER    0x0001
#define DP83869_BIST_CONTROL_LOOPBACK_MODE_AFTER_SCRAMBLER     0x0002
#define DP83869_BIST_CONTROL_LOOPBACK_MODE_AFTER_MLT3_ENCODER  0x0003

//GEN_STATUS2 register
#define DP83869_GEN_STATUS2_PD_PASS                            0x8000
#define DP83869_GEN_STATUS2_PD_PULSE_DET_ZERO                  0x4000
#define DP83869_GEN_STATUS2_PD_FAIL_WD                         0x2000
#define DP83869_GEN_STATUS2_PD_FAIL_NON_PD                     0x1000
#define DP83869_GEN_STATUS2_PRBS_LOCK                          0x0800
#define DP83869_GEN_STATUS2_PRBS_SYNC_LOSS                     0x0400
#define DP83869_GEN_STATUS2_PKT_GEN_BUSY                       0x0200
#define DP83869_GEN_STATUS2_SCR_MODE_MASTER_1G                 0x0100
#define DP83869_GEN_STATUS2_SCR_MODE_SLAVE_1G                  0x0080
#define DP83869_GEN_STATUS2_CORE_PWR_MODE                      0x0040

//LEDS_CFG1 register
#define DP83869_LEDS_CFG1_LED_GPIO_SEL                         0xF000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_LINK                    0x0000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_ACT                     0x1000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_TX_ACT                  0x2000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_RX_ACT                  0x3000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_COL                     0x4000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_1000                    0x5000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_100                     0x6000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_10                      0x7000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_10_100                  0x8000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_100_1000                0x9000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_FD                      0xA000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_LINK_ACT                0xB000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_ERR                     0xD000
#define DP83869_LEDS_CFG1_LED_GPIO_SEL_RX_ERR                  0xE000
#define DP83869_LEDS_CFG1_LED_2_SEL                            0x1F00
#define DP83869_LEDS_CFG1_LED_2_SEL_LINK                       0x0000
#define DP83869_LEDS_CFG1_LED_2_SEL_ACT                        0x0100
#define DP83869_LEDS_CFG1_LED_2_SEL_TX_ACT                     0x0200
#define DP83869_LEDS_CFG1_LED_2_SEL_RX_ACT                     0x0300
#define DP83869_LEDS_CFG1_LED_2_SEL_COL                        0x0400
#define DP83869_LEDS_CFG1_LED_2_SEL_1000                       0x0500
#define DP83869_LEDS_CFG1_LED_2_SEL_100                        0x0600
#define DP83869_LEDS_CFG1_LED_2_SEL_10                         0x0700
#define DP83869_LEDS_CFG1_LED_2_SEL_10_100                     0x0800
#define DP83869_LEDS_CFG1_LED_2_SEL_100_1000                   0x0900
#define DP83869_LEDS_CFG1_LED_2_SEL_FD                         0x0A00
#define DP83869_LEDS_CFG1_LED_2_SEL_LINK_ACT                   0x0B00
#define DP83869_LEDS_CFG1_LED_2_SEL_ERR                        0x0D00
#define DP83869_LEDS_CFG1_LED_2_SEL_RX_ERR                     0x0E00
#define DP83869_LEDS_CFG1_LED_1_SEL                            0x00F0
#define DP83869_LEDS_CFG1_LED_1_SEL_LINK                       0x0000
#define DP83869_LEDS_CFG1_LED_1_SEL_ACT                        0x0010
#define DP83869_LEDS_CFG1_LED_1_SEL_TX_ACT                     0x0020
#define DP83869_LEDS_CFG1_LED_1_SEL_RX_ACT                     0x0030
#define DP83869_LEDS_CFG1_LED_1_SEL_COL                        0x0040
#define DP83869_LEDS_CFG1_LED_1_SEL_1000                       0x0050
#define DP83869_LEDS_CFG1_LED_1_SEL_100                        0x0060
#define DP83869_LEDS_CFG1_LED_1_SEL_10                         0x0070
#define DP83869_LEDS_CFG1_LED_1_SEL_10_100                     0x0080
#define DP83869_LEDS_CFG1_LED_1_SEL_100_1000                   0x0090
#define DP83869_LEDS_CFG1_LED_1_SEL_FD                         0x00A0
#define DP83869_LEDS_CFG1_LED_1_SEL_LINK_ACT                   0x00B0
#define DP83869_LEDS_CFG1_LED_1_SEL_ERR                        0x00D0
#define DP83869_LEDS_CFG1_LED_1_SEL_RX_ERR                     0x00E0
#define DP83869_LEDS_CFG1_LED_0_SEL                            0x000F
#define DP83869_LEDS_CFG1_LED_0_SEL_LINK                       0x0000
#define DP83869_LEDS_CFG1_LED_0_SEL_ACT                        0x0001
#define DP83869_LEDS_CFG1_LED_0_SEL_TX_ACT                     0x0002
#define DP83869_LEDS_CFG1_LED_0_SEL_RX_ACT                     0x0003
#define DP83869_LEDS_CFG1_LED_0_SEL_COL                        0x0004
#define DP83869_LEDS_CFG1_LED_0_SEL_1000                       0x0005
#define DP83869_LEDS_CFG1_LED_0_SEL_100                        0x0006
#define DP83869_LEDS_CFG1_LED_0_SEL_10                         0x0007
#define DP83869_LEDS_CFG1_LED_0_SEL_10_100                     0x0008
#define DP83869_LEDS_CFG1_LED_0_SEL_100_1000                   0x0009
#define DP83869_LEDS_CFG1_LED_0_SEL_FD                         0x000A
#define DP83869_LEDS_CFG1_LED_0_SEL_LINK_ACT                   0x000B
#define DP83869_LEDS_CFG1_LED_0_SEL_ERR                        0x000D
#define DP83869_LEDS_CFG1_LED_0_SEL_RX_ERR                     0x000E

//LEDS_CFG2 register
#define DP83869_LEDS_CFG2_LED_GPIO_POLARITY                    0x4000
#define DP83869_LEDS_CFG2_LED_GPIO_DRV_VAL                     0x2000
#define DP83869_LEDS_CFG2_LED_GPIO_DRV_EN                      0x1000
#define DP83869_LEDS_CFG2_LED_2_POLARITY                       0x0400
#define DP83869_LEDS_CFG2_LED_2_DRV_VAL                        0x0200
#define DP83869_LEDS_CFG2_LED_2_DRV_EN                         0x0100
#define DP83869_LEDS_CFG2_LED_1_POLARITY                       0x0040
#define DP83869_LEDS_CFG2_LED_1_DRV_VAL                        0x0020
#define DP83869_LEDS_CFG2_LED_1_DRV_EN                         0x0010
#define DP83869_LEDS_CFG2_LED_0_POLARITY                       0x0004
#define DP83869_LEDS_CFG2_LED_0_DRV_VAL                        0x0002
#define DP83869_LEDS_CFG2_LED_0_DRV_EN                         0x0001

//LEDS_CFG3 register
#define DP83869_LEDS_CFG3_LEDS_BYPASS_STRETCHING               0x0004
#define DP83869_LEDS_CFG3_LEDS_BLINK_RATE                      0x0003
#define DP83869_LEDS_CFG3_LEDS_BLINK_RATE_20HZ                 0x0000
#define DP83869_LEDS_CFG3_LEDS_BLINK_RATE_10HZ                 0x0001
#define DP83869_LEDS_CFG3_LEDS_BLINK_RATE_5HZ                  0x0002
#define DP83869_LEDS_CFG3_LEDS_BLINK_RATE_2HZ                  0x0003

//GEN_CFG4 register
#define DP83869_GEN_CFG4_CFG_FAST_ANEG_EN                      0x4000
#define DP83869_GEN_CFG4_CFG_FAST_ANEG_SEL_VAL                 0x3000
#define DP83869_GEN_CFG4_CFG_ANEG_ADV_FD_EN                    0x0800
#define DP83869_GEN_CFG4_RESTART_STATUS_BITS_EN                0x0400
#define DP83869_GEN_CFG4_CFG_ROBUST_AMDIX_EN                   0x0200
#define DP83869_GEN_CFG4_CFG_FAST_AMDIX_EN                     0x0100
#define DP83869_GEN_CFG4_INT_OE                                0x0080
#define DP83869_GEN_CFG4_FORCE_INTERRUPT                       0x0040
#define DP83869_GEN_CFG4_FORCE_1G_AUTONEG_EN                   0x0008
#define DP83869_GEN_CFG4_TDR_FAIL                              0x0004
#define DP83869_GEN_CFG4_TDR_DONE                              0x0002
#define DP83869_GEN_CFG4_TDR_START                             0x0001

//GEN_CTRL register
#define DP83869_GEN_CTRL_SW_RESET                              0x8000
#define DP83869_GEN_CTRL_SW_RESTART                            0x4000

//ANALOG_TEST_CTR register
#define DP83869_ANALOG_TEST_CTR_TM7_PULSE_SEL                  0x0C00
#define DP83869_ANALOG_TEST_CTR_EXTND_TM7_100BT_MSB            0x0200
#define DP83869_ANALOG_TEST_CTR_EXTND_TM7_100BT_EN             0x0100
#define DP83869_ANALOG_TEST_CTR_TM_CH_SEL                      0x00E0
#define DP83869_ANALOG_TEST_CTR_ANALOG_TEST                    0x001F

//GEN_CFG_ENH_AMIX register
#define DP83869_GEN_CFG_ENH_AMIX_CFG_FLD_WINDW_CNT             0x3E00
#define DP83869_GEN_CFG_ENH_AMIX_CFG_FAST_AMDIX_VAL            0x01F0
#define DP83869_GEN_CFG_ENH_AMIX_CFG_ROBUST_AMDIX_VAL          0x000F

//GEN_CFG_FLD register
#define DP83869_GEN_CFG_FLD_CFG_FORCE_DROP_LINK_EN             0x8000
#define DP83869_GEN_CFG_FLD_FLD_BYPASS_MAX_WAIT_TIMER          0x4000
#define DP83869_GEN_CFG_FLD_SLICER_OUT_STUCK                   0x2000
#define DP83869_GEN_CFG_FLD_FLD_STATUS                         0x1F00
#define DP83869_GEN_CFG_FLD_CFG_FAST_LINK_DOWN_MODES           0x001F

//GEN_CFG_FLD_THR register
#define DP83869_GEN_CFG_FLD_THR_ENERGY_WINDOW_LEN_FLD          0x0700
#define DP83869_GEN_CFG_FLD_THR_ENERGY_ON_FLD_THR              0x0070
#define DP83869_GEN_CFG_FLD_THR_ENERGY_LOST_FLD_THR            0x0007

//GEN_CFG3 register
#define DP83869_GEN_CFG3_SGMII_AUTONEG_TIMER                   0x0060
#define DP83869_GEN_CFG3_PORT_MIRRORING_MODE                   0x0001

//RGMII_CTRL register
#define DP83869_RGMII_CTRL_RGMII_RX_HALF_FULL_THR              0x0060
#define DP83869_RGMII_CTRL_RGMII_TX_HALF_FULL_THR              0x0018
#define DP83869_RGMII_CTRL_SUPPRESS_TX_ERR_EN                  0x0004
#define DP83869_RGMII_CTRL_RGMII_TX_CLK_DELAY                  0x0002
#define DP83869_RGMII_CTRL_RGMII_RX_CLK_DELAY                  0x0001

//RGMII_CTRL2 register
#define DP83869_RGMII_CTRL2_RGMII_AF_BYPASS_EN                 0x0010
#define DP83869_RGMII_CTRL2_RGMII_AF_BYPASS_DLY_EN             0x0008
#define DP83869_RGMII_CTRL2_LOW_LATENCY_10_100_EN              0x0004

//SGMII_AUTO_NEG_STATUS register
#define DP83869_SGMII_AUTO_NEG_STATUS_SGMII_PAGE_RX            0x0002
#define DP83869_SGMII_AUTO_NEG_STATUS_SGMII_AUTONEG_COMPLETE   0x0001

//PRBS_TX_CHK_CTRL register
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_ERR_CNT           0x7F80
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_SYNC_LOSS         0x0020
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_LOCK_STS          0x0010
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_BYTE_CNT_OVF      0x0004
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_CNT_MODE          0x0002
#define DP83869_PRBS_TX_CHK_CTRL_PRBS_TX_CHK_EN                0x0001

//PRBS_TX_CHK_BYTE_CNT register
#define DP83869_PRBS_TX_CHK_BYTE_CNT_PRBS_TX_CHK_BYTE_CNT      0xFFFF

//G_100BT_REG0 register
#define DP83869_G_100BT_REG0_FAST_RX_DV                        0x0001

//SERDES_SYNC_STS register
#define DP83869_SERDES_SYNC_STS_SYNC_STATUS                    0x0100

//STRAP_STS register
#define DP83869_STRAP_STS_STRAP_LINK_LOSS_PASS_THRU            0x2000
#define DP83869_STRAP_STS_STRAP_MIRROR_EN                      0x1000
#define DP83869_STRAP_STS_STRAP_OPMODE                         0x0E00
#define DP83869_STRAP_STS_STRAP_PHY_ADD                        0x01F0
#define DP83869_STRAP_STS_STRAP_ANEGSEL                        0x000C
#define DP83869_STRAP_STS_STRAP_ANEG_EN                        0x0002
#define DP83869_STRAP_STS_STRAP_RGMII_MII_SEL                  0x0001

//ANA_RGMII_DLL_CTRL register
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_EN_FORCE_VAL            0x0200
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_EN_FORCE_CTRL           0x0100
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL        0x00F0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_0_25NS 0x0000
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_0_50NS 0x0010
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_0_75NS 0x0020
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_1_00NS 0x0030
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_1_25NS 0x0040
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_1_50NS 0x0050
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_1_75NS 0x0060
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_2_00NS 0x0070
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_2_25NS 0x0080
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_2_50NS 0x0090
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_2_75NS 0x00A0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_3_00NS 0x00B0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_3_25NS 0x00C0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_3_50NS 0x00D0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_3_75NS 0x00E0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_4_00NS 0x00F0
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL        0x000F
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_0_25NS 0x0000
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_0_50NS 0x0001
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_0_75NS 0x0002
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_1_00NS 0x0003
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_1_25NS 0x0004
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_1_50NS 0x0005
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_1_75NS 0x0006
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_2_00NS 0x0007
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_2_25NS 0x0008
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_2_50NS 0x0009
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_2_75NS 0x000A
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_3_00NS 0x000B
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_3_25NS 0x000C
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_3_50NS 0x000D
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_3_75NS 0x000E
#define DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_4_00NS 0x000F

//RXF_CFG register
#define DP83869_RXF_CFG_WOL_OUT_CLEAN                          0x0800
#define DP83869_RXF_CFG_WOL_OUT_STRETCH                        0x0600
#define DP83869_RXF_CFG_WOL_OUT_MODE                           0x0100
#define DP83869_RXF_CFG_ENHANCED_MAC_SUPPORT                   0x0080
#define DP83869_RXF_CFG_WAKE_ON_UCAST                          0x0010
#define DP83869_RXF_CFG_WAKE_ON_BCAST                          0x0004
#define DP83869_RXF_CFG_WAKE_ON_PATTERN                        0x0002
#define DP83869_RXF_CFG_WAKE_ON_MAGIC                          0x0001

//RXF_STATUS register
#define DP83869_RXF_STATUS_SFD_ERR                             0x0080
#define DP83869_RXF_STATUS_BAD_CRC                             0x0040
#define DP83869_RXF_STATUS_UCAST_RCVD                          0x0010
#define DP83869_RXF_STATUS_BCAST_RCVD                          0x0004
#define DP83869_RXF_STATUS_PATTERN_RCVD                        0x0002
#define DP83869_RXF_STATUS_MAGIC_RCVD                          0x0001

//IO_MUX_CFG register
#define DP83869_IO_MUX_CFG_CLK_O_SEL                           0x1F00
#define DP83869_IO_MUX_CFG_CLK_O_DISABLE                       0x0040
#define DP83869_IO_MUX_CFG_IO_IMPEDANCE_CTRL                   0x001F

//TDR_GEN_CFG1 register
#define DP83869_TDR_GEN_CFG1_TDR_CH_CD_BYPASS                  0x1000
#define DP83869_TDR_GEN_CFG1_TDR_CROSS_MODE_DIS                0x0800
#define DP83869_TDR_GEN_CFG1_TDR_NLP_CHECK                     0x0400
#define DP83869_TDR_GEN_CFG1_TDR_AVG_NUM                       0x0380
#define DP83869_TDR_GEN_CFG1_TDR_SEG_NUM                       0x0070
#define DP83869_TDR_GEN_CFG1_TDR_CYCLE_TIME                    0x000F

//TDR_GEN_CFG2 register
#define DP83869_TDR_GEN_CFG2_TDR_SILENCE_TH                    0xFF00
#define DP83869_TDR_GEN_CFG2_TDR_POST_SILENCE_TIME             0x00C0
#define DP83869_TDR_GEN_CFG2_TDR_PRE_SILENCE_TIME              0x0030

//TDR_SEG_DURATION register
#define DP83869_TDR_SEG_DURATION_TDR_SEG_DURATION_SEG3         0x7C00
#define DP83869_TDR_SEG_DURATION_TDR_SEG_DURATION_SEG2         0x03E0
#define DP83869_TDR_SEG_DURATION_TDR_SEG_DURATION_SEG1         0x001F

//TDR_SEG_DURATION2 register
#define DP83869_TDR_SEG_DURATION2_TDR_SEG_DURATION_SEG5        0xFF00
#define DP83869_TDR_SEG_DURATION2_TDR_SEG_DURATION_SEG4        0x003F

//TDR_GEN_CFG3 register
#define DP83869_TDR_GEN_CFG3_TDR_FWD_SHADOW_SEG4               0xF000
#define DP83869_TDR_GEN_CFG3_TDR_FWD_SHADOW_SEG3               0x0F00
#define DP83869_TDR_GEN_CFG3_TDR_FWD_SHADOW_SEG2               0x0070
#define DP83869_TDR_GEN_CFG3_TDR_FWD_SHADOW_SEG1               0x0007

//TDR_GEN_CFG4 register
#define DP83869_TDR_GEN_CFG4_TDR_SDW_AVG_LOC                   0x3800
#define DP83869_TDR_GEN_CFG4_TDR_TX_TYPE_SEG5                  0x0100
#define DP83869_TDR_GEN_CFG4_TDR_TX_TYPE_SEG4                  0x0080
#define DP83869_TDR_GEN_CFG4_TDR_TX_TYPE_SEG3                  0x0040
#define DP83869_TDR_GEN_CFG4_TDR_TX_TYPE_SEG2                  0x0020
#define DP83869_TDR_GEN_CFG4_TDR_TX_TYPE_SEG1                  0x0010
#define DP83869_TDR_GEN_CFG4_TDR_FWD_SHADOW_SEG5               0x000F

//TDR_PEAKS_LOC_A_0_1 register
#define DP83869_TDR_PEAKS_LOC_A_0_1_TDR_PEAKS_LOC_A_1          0xFF00
#define DP83869_TDR_PEAKS_LOC_A_0_1_TDR_PEAKS_LOC_A_0          0x00FF

//TDR_PEAKS_LOC_A_2_3 register
#define DP83869_TDR_PEAKS_LOC_A_2_3_TDR_PEAKS_LOC_A_3          0xFF00
#define DP83869_TDR_PEAKS_LOC_A_2_3_TDR_PEAKS_LOC_A_2          0x00FF

//TDR_PEAKS_LOC_A_4_B_0 register
#define DP83869_TDR_PEAKS_LOC_A_4_B_0_TDR_PEAKS_LOC_B_0        0xFF00
#define DP83869_TDR_PEAKS_LOC_A_4_B_0_TDR_PEAKS_LOC_A_4        0x00FF

//TDR_PEAKS_LOC_B_1_2 register
#define DP83869_TDR_PEAKS_LOC_B_1_2_TDR_PEAKS_LOC_B_2          0xFF00
#define DP83869_TDR_PEAKS_LOC_B_1_2_TDR_PEAKS_LOC_B_1          0x00FF

//TDR_PEAKS_LOC_B_3_4 register
#define DP83869_TDR_PEAKS_LOC_B_3_4_TDR_PEAKS_LOC_B_4          0xFF00
#define DP83869_TDR_PEAKS_LOC_B_3_4_TDR_PEAKS_LOC_B_3          0x00FF

//TDR_PEAKS_LOC_C_0_1 register
#define DP83869_TDR_PEAKS_LOC_C_0_1_TDR_PEAKS_LOC_C_1          0xFF00
#define DP83869_TDR_PEAKS_LOC_C_0_1_TDR_PEAKS_LOC_C_0          0x00FF

//TDR_PEAKS_LOC_C_2_3 register
#define DP83869_TDR_PEAKS_LOC_C_2_3_TDR_PEAKS_LOC_C_3          0xFF00
#define DP83869_TDR_PEAKS_LOC_C_2_3_TDR_PEAKS_LOC_C_2          0x00FF

//TDR_PEAKS_LOC_C_4_D_0 register
#define DP83869_TDR_PEAKS_LOC_C_4_D_0_TDR_PEAKS_LOC_D_0        0xFF00
#define DP83869_TDR_PEAKS_LOC_C_4_D_0_TDR_PEAKS_LOC_C_4        0x00FF

//TDR_PEAKS_LOC_D_1_2 register
#define DP83869_TDR_PEAKS_LOC_D_1_2_TDR_PEAKS_LOC_D_2          0xFF00
#define DP83869_TDR_PEAKS_LOC_D_1_2_TDR_PEAKS_LOC_D_1          0x00FF

//TDR_PEAKS_LOC_D_3_4 register
#define DP83869_TDR_PEAKS_LOC_D_3_4_TDR_PEAKS_LOC_D_4          0xFF00
#define DP83869_TDR_PEAKS_LOC_D_3_4_TDR_PEAKS_LOC_D_3          0x00FF

//TDR_GEN_STATUS register
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_CROSS_MODE_D          0x0800
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_CROSS_MODE_C          0x0400
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_CROSS_MODE_B          0x0200
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_CROSS_MODE_A          0x0100
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_OVERFLOW_D            0x0080
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_OVERFLOW_C            0x0040
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_OVERFLOW_B            0x0020
#define DP83869_TDR_GEN_STATUS_TDR_P_LOC_OVERFLOW_A            0x0010
#define DP83869_TDR_GEN_STATUS_TDR_SEG1_HIGH_CROSS_D           0x0008
#define DP83869_TDR_GEN_STATUS_TDR_SEG1_HIGH_CROSS_C           0x0004
#define DP83869_TDR_GEN_STATUS_TDR_SEG1_HIGH_CROSS_B           0x0002
#define DP83869_TDR_GEN_STATUS_TDR_SEG1_HIGH_CROSS_A           0x0001

//TDR_PEAKS_SIGN_A_B register
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_B_4          0x0200
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_B_3          0x0100
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_B_2          0x0080
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_B_1          0x0040
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_B_0          0x0020
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_A_4          0x0010
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_A_3          0x0008
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_A_2          0x0004
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_A_1          0x0002
#define DP83869_TDR_PEAKS_SIGN_A_B_TDR_PEAKS_SIGN_A_0          0x0001

//TDR_PEAKS_SIGN_C_D register
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_D_4          0x0200
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_D_3          0x0100
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_D_2          0x0080
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_D_1          0x0040
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_D_0          0x0020
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_C_4          0x0010
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_C_3          0x0008
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_C_2          0x0004
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_C_1          0x0002
#define DP83869_TDR_PEAKS_SIGN_C_D_TDR_PEAKS_SIGN_C_0          0x0001

//OP_MODE_DECODE register
#define DP83869_OP_MODE_DECODE_BRIDGE_MODE_RGMII_MAC           0x0040
#define DP83869_OP_MODE_DECODE_RGMII_MII_SEL                   0x0020
#define DP83869_OP_MODE_DECODE_CFG_OPMODE                      0x0007

//GPIO_MUX_CTRL register
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL             0x00F0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_CLK_OUT     0x0000
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_INT         0x0020
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_LINK        0x0030
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_TX_SFD      0x0050
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_RX_SFD      0x0060
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_WOL         0x0070
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_ED          0x0080
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_PRBS_ERR    0x0090
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_LED_2       0x00A0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_LED_3       0x00B0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_CRS         0x00C0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_COL         0x00D0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_CONST_0     0x00E0
#define DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_CONST_1     0x00F0
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL                0x000F
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_CLK_OUT        0x0000
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_INT            0x0002
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_LINK           0x0003
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_TX_SFD         0x0005
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_RX_SFD         0x0006
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_WOL            0x0007
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_ED             0x0008
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_PRBS_ERR       0x0009
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_LED_2          0x000A
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_LED_3          0x000B
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_CRS            0x000C
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_COL            0x000D
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_CONST_0        0x000E
#define DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_CONST_1        0x000F

//FX_CTRL register
#define DP83869_FX_CTRL_CTRL0_RESET                            0x8000
#define DP83869_FX_CTRL_CTRL0_LOOPBACK                         0x4000
#define DP83869_FX_CTRL_CTRL0_SPEED_SEL_LSB                    0x2000
#define DP83869_FX_CTRL_CTRL0_ANEG_EN                          0x1000
#define DP83869_FX_CTRL_CTRL0_PWRDN                            0x0800
#define DP83869_FX_CTRL_CTRL0_ISOLATE                          0x0400
#define DP83869_FX_CTRL_CTRL0_RESTART_AN                       0x0200
#define DP83869_FX_CTRL_CTRL0_DUPLEX_MODE                      0x0100
#define DP83869_FX_CTRL_CTRL0_COL_TEST                         0x0080
#define DP83869_FX_CTRL_CTRL0_SPEED_SEL_MSB                    0x0040

//FX_STS register
#define DP83869_FX_STS_STTS_100B_T4                            0x8000
#define DP83869_FX_STS_STTS_100B_X_FD                          0x4000
#define DP83869_FX_STS_STTS_100B_X_HD                          0x2000
#define DP83869_FX_STS_STTS_10B_FD                             0x1000
#define DP83869_FX_STS_STTS_10B_HD                             0x0800
#define DP83869_FX_STS_STTS_100B_T2_FD                         0x0400
#define DP83869_FX_STS_STTS_100B_T2_HD                         0x0200
#define DP83869_FX_STS_STTS_EXTENDED_STATUS                    0x0100
#define DP83869_FX_STS_STTS_MF_PREAMBLE_SUPRSN                 0x0040
#define DP83869_FX_STS_STTS_ANEG_COMPLETE                      0x0020
#define DP83869_FX_STS_STTS_REMOTE_FAULT                       0x0010
#define DP83869_FX_STS_STTS_ANEG_ABILITY                       0x0008
#define DP83869_FX_STS_STTS_LINK_STATUS                        0x0004
#define DP83869_FX_STS_STTS_JABBER_DET                         0x0002
#define DP83869_FX_STS_STTS_EXTENDED_CAPABILITY                0x0001

//FX_PHYID1 register
#define DP83869_FX_PHYID1_OUI_6_19_FIBER                       0x3FFF
#define DP83869_FX_PHYID1_OUI_6_19_FIBER_DEFAULT               0x2000

//FX_PHYID2 register
#define DP83869_FX_PHYID2_OUI_0_5_FIBER                        0xFC00
#define DP83869_FX_PHYID2_OUI_0_5_FIBER_DEFAULT                0xA000
#define DP83869_FX_PHYID2_MODEL_NUM_FIBER                      0x03F0
#define DP83869_FX_PHYID2_MODEL_NUM_FIBER_DEFAULT              0x00F0
#define DP83869_FX_PHYID2_REVISION_NUM_FIBER                   0x000F
#define DP83869_FX_PHYID2_REVISION_NUM_FIBER_DEFAULT           0x0001

//FX_ANADV register
#define DP83869_FX_ANADV_BP_NEXT_PAGE                          0x8000
#define DP83869_FX_ANADV_BP_ACK                                0x4000
#define DP83869_FX_ANADV_BP_REMOTE_FAULT                       0x3000
#define DP83869_FX_ANADV_BP_ASYMMETRIC_PAUSE                   0x0100
#define DP83869_FX_ANADV_BP_PAUSE                              0x0080
#define DP83869_FX_ANADV_BP_HALF_DUPLEX                        0x0040
#define DP83869_FX_ANADV_BP_FULL_DUPLEX                        0x0020
#define DP83869_FX_ANADV_BP_RSVD1                              0x001F

//FX_LPABL register
#define DP83869_FX_LPABL_LP_ABILITY_NEXT_PAGE                  0x8000
#define DP83869_FX_LPABL_LP_ABILITY_ACK                        0x4000
#define DP83869_FX_LPABL_LP_ABILITY_REMOTE_FAULT               0x3000
#define DP83869_FX_LPABL_LP_ABILITY_ASYMMETRIC_PAUSE           0x0100
#define DP83869_FX_LPABL_LP_ABILITY_PAUSE                      0x0080
#define DP83869_FX_LPABL_LP_ABILITY_HALF_DUPLEX                0x0040
#define DP83869_FX_LPABL_LP_ABILITY_FULL_DUPLEX                0x0020

//FX_ANEXP register
#define DP83869_FX_ANEXP_AN_EXP_LP_NEXT_PAGE_ABLE              0x0008
#define DP83869_FX_ANEXP_AN_EXP_LOCAL_NEXT_PAGE_ABLE           0x0004
#define DP83869_FX_ANEXP_AN_EXP_PAGE_RECEIVED                  0x0002
#define DP83869_FX_ANEXP_AN_EXP_LP_AUTO_NEG_ABLE               0x0001

//FX_LOCNP register
#define DP83869_FX_LOCNP_NP_TX_NEXT_PAGE                       0x8000
#define DP83869_FX_LOCNP_NP_TX_MESSAGE_PAGE_MODE               0x2000
#define DP83869_FX_LOCNP_NP_TX_ACK_2                           0x1000
#define DP83869_FX_LOCNP_NP_TX_TOGGLE                          0x0800
#define DP83869_FX_LOCNP_NP_TX_MESSAGE_FIELD                   0x07FF

//FX_LPNP register
#define DP83869_FX_LPNP_LP_NP_NEXT_PAGE                        0x8000
#define DP83869_FX_LPNP_LP_NP_ACK                              0x4000
#define DP83869_FX_LPNP_LP_NP_MESSAGE_PAGE_MODE                0x2000
#define DP83869_FX_LPNP_LP_NP_ACK_2                            0x1000
#define DP83869_FX_LPNP_LP_NP_TOGGLE                           0x0800
#define DP83869_FX_LPNP_LP_NP_MESSAGE_FIELD                    0x07FF

//FX_INT_EN register
#define DP83869_FX_INT_EN_FEF_FAULT_EN                         0x0200
#define DP83869_FX_INT_EN_TX_FIFO_FULL_EN                      0x0100
#define DP83869_FX_INT_EN_TX_FIFO_EMPTY_EN                     0x0080
#define DP83869_FX_INT_EN_RX_FIFO_FULL_EN                      0x0040
#define DP83869_FX_INT_EN_RX_FIFO_EMPTY_EN                     0x0020
#define DP83869_FX_INT_EN_LINK_STS_CHANGE_EN                   0x0010
#define DP83869_FX_INT_EN_LP_FAULT_RX_EN                       0x0008
#define DP83869_FX_INT_EN_PRI_RES_FAIL_EN                      0x0004
#define DP83869_FX_INT_EN_LP_NP_RX_EN                          0x0002
#define DP83869_FX_INT_EN_LP_BP_RX_EN                          0x0001

//FX_INT_STS register
#define DP83869_FX_INT_STS_FEF_FAULT                           0x0200
#define DP83869_FX_INT_STS_TX_FIFO_FULL                        0x0100
#define DP83869_FX_INT_STS_TX_FIFO_EMPTY                       0x0080
#define DP83869_FX_INT_STS_RX_FIFO_FULL                        0x0040
#define DP83869_FX_INT_STS_RX_FIFO_EMPTY                       0x0020
#define DP83869_FX_INT_STS_LINK_STS_CHANGE                     0x0010
#define DP83869_FX_INT_STS_LP_FAULT_RX                         0x0008
#define DP83869_FX_INT_STS_PRI_RES_FAIL                        0x0004
#define DP83869_FX_INT_STS_LP_NP_RX                            0x0002
#define DP83869_FX_INT_STS_LP_BP_RX                            0x0001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DP83869 Ethernet PHY driver
extern const PhyDriver dp83869PhyDriver;

//DP83869 related functions
error_t dp83869Init(NetInterface *interface);
void dp83869InitHook(NetInterface *interface);

void dp83869Tick(NetInterface *interface);

void dp83869EnableIrq(NetInterface *interface);
void dp83869DisableIrq(NetInterface *interface);

void dp83869EventHandler(NetInterface *interface);

void dp83869WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t dp83869ReadPhyReg(NetInterface *interface, uint8_t address);

void dp83869DumpPhyReg(NetInterface *interface);

void dp83869WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t dp83869ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
