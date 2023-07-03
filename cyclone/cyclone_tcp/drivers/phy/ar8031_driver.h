/**
 * @file ar8031_driver.h
 * @brief AR8031 Gigabit Ethernet PHY driver
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

#ifndef _AR8031_DRIVER_H
#define _AR8031_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef AR8031_PHY_ADDR
   #define AR8031_PHY_ADDR 0
#elif (AR8031_PHY_ADDR < 0 || AR8031_PHY_ADDR > 31)
   #error AR8031_PHY_ADDR parameter is not valid
#endif

//AR8031 PHY registers
#define AR8031_BMCR                                    0x00
#define AR8031_BMSR                                    0x01
#define AR8031_PHYID1                                  0x02
#define AR8031_PHYID2                                  0x03
#define AR8031_ANAR                                    0x04
#define AR8031_ANLPAR                                  0x05
#define AR8031_ANER                                    0x06
#define AR8031_ANNPR                                   0x07
#define AR8031_ANLPNPR                                 0x08
#define AR8031_GBCR                                    0x09
#define AR8031_GBSR                                    0x0A
#define AR8031_MMDACR                                  0x0D
#define AR8031_MMDAADR                                 0x0E
#define AR8031_GBESR                                   0x0F
#define AR8031_FUNC_CTRL                               0x10
#define AR8031_PHY_STATUS                              0x11
#define AR8031_INT_EN                                  0x12
#define AR8031_INT_STATUS                              0x13
#define AR8031_SMART_SPEED                             0x14
#define AR8031_CDT_CTRL                                0x16
#define AR8031_LED_CTRL                                0x18
#define AR8031_MAN_LED_OVERRIDE                        0x19
#define AR8031_COPPER_FIBER_STATUS                     0x1B
#define AR8031_CDT_STATUS                              0x1C
#define AR8031_DBG_PORT_ADDR_OFFSET                    0x1D
#define AR8031_DBG_PORT_DATA                           0x1E
#define AR8031_CHIP_CONF                               0x1F

//AR8031 MMD registers
#define AR8031_PCS_CTRL                                0x03, 0x0000
#define AR8031_PCS_STAT                                0x03, 0x0001
#define AR8031_EEE_CAPABILITY                          0x03, 0x0014
#define AR8031_EEE_WAKE_ERROR_COUNTER                  0x03, 0x0016
#define AR8031_P1588_CTRL                              0x03, 0x8012
#define AR8031_P1588_RX_SEQ_ID                         0x03, 0x8013
#define AR8031_P1588_RX_SRC_PORT_ID1                   0x03, 0x8014
#define AR8031_P1588_RX_SRC_PORT_ID2                   0x03, 0x8015
#define AR8031_P1588_RX_SRC_PORT_ID3                   0x03, 0x8016
#define AR8031_P1588_RX_SRC_PORT_ID4                   0x03, 0x8017
#define AR8031_P1588_RX_SRC_PORT_ID5                   0x03, 0x8018
#define AR8031_P1588_RX_TIMESTAMP1                     0x03, 0x8019
#define AR8031_P1588_RX_TIMESTAMP2                     0x03, 0x801A
#define AR8031_P1588_RX_TIMESTAMP3                     0x03, 0x801B
#define AR8031_P1588_RX_TIMESTAMP4                     0x03, 0x801C
#define AR8031_P1588_RX_TIMESTAMP5                     0x03, 0x801D
#define AR8031_P1588_RX_FRAC_NANO1                     0x03, 0x801E
#define AR8031_P1588_RX_FRAC_NANO0                     0x03, 0x801F
#define AR8031_P1588_TX_SEQ_ID                         0x03, 0x8020
#define AR8031_P1588_TX_SRC_PORT_ID1                   0x03, 0x8021
#define AR8031_P1588_TX_SRC_PORT_ID2                   0x03, 0x8022
#define AR8031_P1588_TX_SRC_PORT_ID3                   0x03, 0x8023
#define AR8031_P1588_TX_SRC_PORT_ID4                   0x03, 0x8024
#define AR8031_P1588_TX_SRC_PORT_ID5                   0x03, 0x8025
#define AR8031_P1588_TX_TIMESTAMP1                     0x03, 0x8026
#define AR8031_P1588_TX_TIMESTAMP2                     0x03, 0x8027
#define AR8031_P1588_TX_TIMESTAMP3                     0x03, 0x8028
#define AR8031_P1588_TX_TIMESTAMP4                     0x03, 0x8029
#define AR8031_P1588_TX_TIMESTAMP5                     0x03, 0x802A
#define AR8031_P1588_TX_FRAC_NANO1                     0x03, 0x802B
#define AR8031_P1588_TX_FRAC_NANO2                     0x03, 0x802C
#define AR8031_P1588_ORIGIN_CORRECTION1                0x03, 0x802D
#define AR8031_P1588_ORIGIN_CORRECTION2                0x03, 0x802E
#define AR8031_P1588_ORIGIN_CORRECTION3                0x03, 0x802F
#define AR8031_P1588_ORIGIN_CORRECTION4                0x03, 0x8030
#define AR8031_P1588_INGRESS_TRIG_TIME1                0x03, 0x8031
#define AR8031_P1588_INGRESS_TRIG_TIME2                0x03, 0x8032
#define AR8031_P1588_INGRESS_TRIG_TIME3                0x03, 0x8033
#define AR8031_P1588_INGRESS_TRIG_TIME4                0x03, 0x8034
#define AR8031_P1588_TX_LATENCY                        0x03, 0x8035
#define AR8031_P1588_INC_VALUE1                        0x03, 0x8036
#define AR8031_P1588_INC_VALUE2                        0x03, 0x8037
#define AR8031_P1588_NANO_OFFSET1                      0x03, 0x8038
#define AR8031_P1588_NANO_OFFSET2                      0x03, 0x8039
#define AR8031_P1588_SEC_OFFSET1                       0x03, 0x803A
#define AR8031_P1588_SEC_OFFSET2                       0x03, 0x803B
#define AR8031_P1588_SEC_OFFSET3                       0x03, 0x803C
#define AR8031_P1588_REAL_TIME1                        0x03, 0x803D
#define AR8031_P1588_REAL_TIME2                        0x03, 0x803E
#define AR8031_P1588_REAL_TIME3                        0x03, 0x803F
#define AR8031_P1588_REAL_TIME4                        0x03, 0x8040
#define AR8031_P1588_REAL_TIME5                        0x03, 0x8041
#define AR8031_P1588_REAL_TIME6                        0x03, 0x8042
#define AR8031_P1588_RTC_FRAC_NANO1                    0x03, 0x8042
#define AR8031_P1588_RTC_FRAC_NANO2                    0x03, 0x8043
#define AR8031_WOL_INTERNAL_ADDR1                      0x03, 0x804A
#define AR8031_WOL_INTERNAL_ADDR2                      0x03, 0x804B
#define AR8031_WOL_INTERNAL_ADDR3                      0x03, 0x804C
#define AR8031_REM_PHY_LPBK                            0x03, 0x805A
#define AR8031_SMART_EEE_CTRL1                         0x03, 0x805B
#define AR8031_SMART_EEE_CTRL2                         0x03, 0x805C
#define AR8031_SMART_EEE_CTRL3                         0x03, 0x805D
#define AR8031_AN_CTRL1                                0x07, 0x0000
#define AR8031_AN_STAT                                 0x07, 0x0001
#define AR8031_AN_XNP_TRANSMIT                         0x07, 0x0016
#define AR8031_AN_XNP_TRANSMIT1                        0x07, 0x0017
#define AR8031_AN_XNP_TRANSMIT2                        0x07, 0x0018
#define AR8031_AN_LP_XNP_ABILITY                       0x07, 0x0019
#define AR8031_AN_LP_XNP_ABILITY1                      0x07, 0x001A
#define AR8031_AN_LP_XNP_ABILITY2                      0x07, 0x001B
#define AR8031_EEE_ADV                                 0x07, 0x003C
#define AR8031_EEE_LP_ADV                              0x07, 0x003D
#define AR8031_EEE_ABILITY_AN_RES                      0x07, 0x8000
#define AR8031_SGMII_CTRL1                             0x07, 0x8005
#define AR8031_SGMII_CTRL2                             0x07, 0x8011
#define AR8031_SGMII_CTRL3                             0x07, 0x8012
#define AR8031_CLK_25M_CLK_SEL                         0x07, 0x8016
#define AR8031_1588_CLK_SEL                            0x07, 0x8017

//Control register
#define AR8031_BMCR_RESET                              0x8000
#define AR8031_BMCR_LOOPBACK                           0x4000
#define AR8031_BMCR_SPEED_SEL_LSB                      0x2000
#define AR8031_BMCR_AN_EN                              0x1000
#define AR8031_BMCR_POWER_DOWN                         0x0800
#define AR8031_BMCR_ISOLATE                            0x0400
#define AR8031_BMCR_RESTART_AN                         0x0200
#define AR8031_BMCR_DUPLEX_MODE                        0x0100
#define AR8031_BMCR_COL_TEST                           0x0080
#define AR8031_BMCR_SPEED_SEL_MSB                      0x0040

//Status register
#define AR8031_BMSR_100BT4                             0x8000
#define AR8031_BMSR_100BTX_FD                          0x4000
#define AR8031_BMSR_100BTX_HD                          0x2000
#define AR8031_BMSR_10BT_FD                            0x1000
#define AR8031_BMSR_10BT_HD                            0x0800
#define AR8031_BMSR_100BT2_FD                          0x0400
#define AR8031_BMSR_100BT2_HD                          0x0200
#define AR8031_BMSR_EXTENDED_STATUS                    0x0100
#define AR8031_BMSR_MF_PREAMBLE_SUPPR                  0x0040
#define AR8031_BMSR_AN_COMPLETE                        0x0020
#define AR8031_BMSR_REMOTE_FAULT                       0x0010
#define AR8031_BMSR_AN_CAPABLE                         0x0008
#define AR8031_BMSR_LINK_STATUS                        0x0004
#define AR8031_BMSR_JABBER_DETECT                      0x0002
#define AR8031_BMSR_EXTENDED_CAPABLE                   0x0001

//PHY Identifier 1 register
#define AR8031_PHYID1_OUI_MSB                          0xFFFF
#define AR8031_PHYID1_OUI_MSB_DEFAULT                  0x004D

//PHY Identifier 2 register
#define AR8031_PHYID2_OUI_LSB                          0xFC00
#define AR8031_PHYID2_OUI_LSB_DEFAULT                  0xD000
#define AR8031_PHYID2_MODEL_NUM                        0x03F0
#define AR8031_PHYID2_MODEL_NUM_DEFAULT                0x0070
#define AR8031_PHYID2_REVISION_NUM                     0x000F

//Auto-Negotiation Advertisement register
#define AR8031_ANAR_NEXT_PAGE                          0x8000
#define AR8031_ANAR_ACK                                0x4000
#define AR8031_ANAR_REMOTE_FAULT                       0x2000
#define AR8031_ANAR_XNP_ABLE                           0x1000
#define AR8031_ANAR_ASYM_PAUSE                         0x0800
#define AR8031_ANAR_PAUSE                              0x0400
#define AR8031_ANAR_100BT4                             0x0200
#define AR8031_ANAR_100BTX_FD                          0x0100
#define AR8031_ANAR_100BTX_HD                          0x0080
#define AR8031_ANAR_10BT_FD                            0x0040
#define AR8031_ANAR_10BT_HD                            0x0020
#define AR8031_ANAR_SELECTOR                           0x001F
#define AR8031_ANAR_SELECTOR_DEFAULT                   0x0001

//Link Partner Ability register
#define AR8031_ANLPAR_NEXT_PAGE                        0x8000
#define AR8031_ANLPAR_ACK                              0x4000
#define AR8031_ANLPAR_REMOTE_FAULT                     0x2000
#define AR8031_ANLPAR_ASYM_PAUSE                       0x0800
#define AR8031_ANLPAR_PAUSE                            0x0400
#define AR8031_ANLPAR_100BT4                           0x0200
#define AR8031_ANLPAR_100BTX_FD                        0x0100
#define AR8031_ANLPAR_100BTX_HD                        0x0080
#define AR8031_ANLPAR_10BT_FD                          0x0040
#define AR8031_ANLPAR_10BT_HD                          0x0020
#define AR8031_ANLPAR_SELECTOR                         0x001F
#define AR8031_ANLPAR_SELECTOR_DEFAULT                 0x0001

//Auto-Negotiation Expansion register
#define AR8031_ANER_PAR_DETECT_FAULT                   0x0010
#define AR8031_ANER_LP_NEXT_PAGE_ABLE                  0x0008
#define AR8031_ANER_NEXT_PAGE_ABLE                     0x0004
#define AR8031_ANER_PAGE_RECEIVED                      0x0002
#define AR8031_ANER_LP_AN_ABLE                         0x0001

//Auto-Negotiation Next Page Transmit register
#define AR8031_ANNPR_NEXT_PAGE                         0x8000
#define AR8031_ANNPR_MSG_PAGE                          0x2000
#define AR8031_ANNPR_ACK2                              0x1000
#define AR8031_ANNPR_TOGGLE                            0x0800
#define AR8031_ANNPR_MESSAGE                           0x07FF

//Link Partner Next Page register
#define AR8031_ANLPNPR_NEXT_PAGE                       0x8000
#define AR8031_ANLPNPR_MSG_PAGE                        0x2000
#define AR8031_ANLPNPR_ACK2                            0x1000
#define AR8031_ANLPNPR_TOGGLE                          0x0800
#define AR8031_ANLPNPR_MESSAGE                         0x07FF

//1000BASE-T Control register
#define AR8031_GBCR_TEST_MODE                          0xE000
#define AR8031_GBCR_MS_MAN_CONF_EN                     0x1000
#define AR8031_GBCR_MS_MAN_CONF_VAL                    0x0800
#define AR8031_GBCR_PORT_TYPE                          0x0400
#define AR8031_GBCR_1000BT_FD                          0x0200
#define AR8031_GBCR_1000BT_HD                          0x0100

//1000BASE-T Status register
#define AR8031_GBSR_MS_CONF_FAULT                      0x8000
#define AR8031_GBSR_MS_CONF_RES                        0x4000
#define AR8031_GBSR_LOCAL_RECEIVER_STATUS              0x2000
#define AR8031_GBSR_REMOTE_RECEIVER_STATUS             0x1000
#define AR8031_GBSR_LP_1000BT_FD                       0x0800
#define AR8031_GBSR_LP_1000BT_HD                       0x0400
#define AR8031_GBSR_IDLE_ERR_COUNT                     0x00FF

//MMD Access Control register
#define AR8031_MMDACR_FUNC                             0xC000
#define AR8031_MMDACR_FUNC_ADDR                        0x0000
#define AR8031_MMDACR_FUNC_DATA_NO_POST_INC            0x4000
#define AR8031_MMDACR_FUNC_DATA_POST_INC_RW            0x8000
#define AR8031_MMDACR_FUNC_DATA_POST_INC_W             0xC000
#define AR8031_MMDACR_DEVAD                            0x001F

//Extended Status register
#define AR8031_GBESR_1000BX_FD                         0x8000
#define AR8031_GBESR_1000BX_HD                         0x4000
#define AR8031_GBESR_1000BT_FD                         0x2000
#define AR8031_GBESR_1000BT_HD                         0x1000

//Function Control register
#define AR8031_FUNC_CTRL_ASSERT_CRS_ON_TX              0x0800
#define AR8031_FUNC_CTRL_FORCE_LINK                    0x0400
#define AR8031_FUNC_CTRL_MDIX_MODE                     0x0060
#define AR8031_FUNC_CTRL_MDIX_MODE_MANUAL_MDI          0x0000
#define AR8031_FUNC_CTRL_MDIX_MODE_MANUAL_MDIX         0x0020
#define AR8031_FUNC_CTRL_MDIX_MODE_AUTO                0x0060
#define AR8031_FUNC_CTRL_SQE_TEST                      0x0004
#define AR8031_FUNC_CTRL_POLARITY_REVERSAL             0x0002
#define AR8031_FUNC_CTRL_JABBER_DIS                    0x0001

//PHY-Specific Status register
#define AR8031_PHY_STATUS_SPEED                        0xC000
#define AR8031_PHY_STATUS_SPEED_10MBPS                 0x0000
#define AR8031_PHY_STATUS_SPEED_100MBPS                0x4000
#define AR8031_PHY_STATUS_SPEED_1000MBPS               0x8000
#define AR8031_PHY_STATUS_DUPLEX                       0x2000
#define AR8031_PHY_STATUS_PAGE_RECEIVED                0x1000
#define AR8031_PHY_STATUS_SPEED_DUPLEX_RESOLVED        0x0800
#define AR8031_PHY_STATUS_LINK                         0x0400
#define AR8031_PHY_STATUS_MDI_CROSSOVER_STATUS         0x0040
#define AR8031_PHY_STATUS_WIRESPEED_DOWNGRADE          0x0020
#define AR8031_PHY_STATUS_TX_PAUSE_EN                  0x0008
#define AR8031_PHY_STATUS_RX_PAUSE_EN                  0x0004
#define AR8031_PHY_STATUS_POLARITY                     0x0002
#define AR8031_PHY_STATUS_JABBER                       0x0001

//Interrupt Enable Register register
#define AR8031_INT_EN_AN_ERROR                         0x8000
#define AR8031_INT_EN_SPEED_CHANGED                    0x4000
#define AR8031_INT_EN_PAGE_RECEIVED                    0x1000
#define AR8031_INT_EN_LINK_FAIL                        0x0800
#define AR8031_INT_EN_LINK_SUCCESS                     0x0400
#define AR8031_INT_EN_FAST_LINK_DOWN1                  0x0200
#define AR8031_INT_EN_LINK_FAIL_BX                     0x0100
#define AR8031_INT_EN_LINK_SUCCESS_BX                  0x0080
#define AR8031_INT_EN_FAST_LINK_DOWN0                  0x0040
#define AR8031_INT_EN_WIRESPEED_DOWNGRADE              0x0020
#define AR8031_INT_EN_10MS_PTP                         0x0010
#define AR8031_INT_EN_RX_PTP                           0x0008
#define AR8031_INT_EN_TX_PTP                           0x0004
#define AR8031_INT_EN_POLARITY_CHANGED                 0x0002
#define AR8031_INT_EN_WOL_PTP                          0x0001

//Interrupt Status register
#define AR8031_INT_STATUS_AN_ERROR                     0x8000
#define AR8031_INT_STATUS_SPEED_CHANGED                0x4000
#define AR8031_INT_STATUS_PAGE_RECEIVED                0x1000
#define AR8031_INT_STATUS_LINK_FAIL                    0x0800
#define AR8031_INT_STATUS_LINK_SUCCESS                 0x0400
#define AR8031_INT_STATUS_FAST_LINK_DOWN1              0x0200
#define AR8031_INT_STATUS_LINK_FAIL_BX                 0x0100
#define AR8031_INT_STATUS_LINK_SUCCESS_BX              0x0080
#define AR8031_INT_STATUS_FAST_LINK_DOWN0              0x0040
#define AR8031_INT_STATUS_WIRESPEED_DOWNGRADE          0x0020
#define AR8031_INT_STATUS_10MS_PTP                     0x0010
#define AR8031_INT_STATUS_RX_PTP                       0x0008
#define AR8031_INT_STATUS_TX_PTP                       0x0004
#define AR8031_INT_STATUS_POLARITY_CHANGED             0x0002
#define AR8031_INT_STATUS_WOL_PTP                      0x0001

//Smart Speed register
#define AR8031_SMART_SPEED_EN                          0x0020
#define AR8031_SMART_SPEED_RETRY_LIMIT                 0x001C
#define AR8031_SMART_SPEED_BYPASS_TIMER                0x0002

//Cable Diagnostic Tester (CDT) Control register
#define AR8031_CDT_CTRL_MDI_PAIR_SELECT                0x0300
#define AR8031_CDT_CTRL_TEST_EN                        0x0001

//LED Control register
#define AR8031_LED_CTRL_LED_DIS                        0x8000
#define AR8031_LED_CTRL_LED_ON_TIME                    0x7000
#define AR8031_LED_CTRL_LED_OFF_TIME                   0x0700
#define AR8031_LED_CTRL_LED_LINK_CTRL                  0x0018
#define AR8031_LED_CTRL_LED_ACT_CTRL                   0x0004

//Manual LED Override register
#define AR8031_MAN_LED_OVERRIDE_LED_ACT                0x1000
#define AR8031_MAN_LED_OVERRIDE_LED_LINK10_100_CTRL    0x00C0
#define AR8031_MAN_LED_OVERRIDE_LED_RX_CTRL            0x000C
#define AR8031_MAN_LED_OVERRIDE_LED_TX_CTRL            0x0003

//Copper/Fiber Status register
#define AR8031_COPPER_FIBER_STATUS_TX_PAUSE_EN_BX      0x2000
#define AR8031_COPPER_FIBER_STATUS_RX_PAUSE_EN_BX      0x1000
#define AR8031_COPPER_FIBER_STATUS_LINK_ESTABLISHED_BX 0x0800
#define AR8031_COPPER_FIBER_STATUS_FD_MODE_BX          0x0400
#define AR8031_COPPER_FIBER_STATUS_SPEED_MODE_BX       0x0300
#define AR8031_COPPER_FIBER_STATUS_TX_PAUSE_EN_BT      0x0020
#define AR8031_COPPER_FIBER_STATUS_RX_PAUSE_EN_BT      0x0010
#define AR8031_COPPER_FIBER_STATUS_LINK_ESTABLISHED_BT 0x0008
#define AR8031_COPPER_FIBER_STATUS_FD_MODE_BT          0x0004
#define AR8031_COPPER_FIBER_STATUS_SPEED_MODE_BT       0x0003

//Cable Diagnostic Tester Status register
#define AR8031_CDT_STATUS_STATUS                       0x0300
#define AR8031_CDT_STATUS_DELTA_TIME                   0x00FF

//Chip Configure register
#define AR8031_CHIP_CONF_BT_BX_REG_SEL                 0x8000
#define AR8031_CHIP_CONF_SMII_IMP_50_75_AUTO           0x4000
#define AR8031_CHIP_CONF_SGMII_RXIMP_50_75             0x2000
#define AR8031_CHIP_CONF_SGMII_TXIMP_50_75             0x1000
#define AR8031_CHIP_CONF_PRIORITY_SEL                  0x0400
#define AR8031_CHIP_CONF_FIBER_MODE_AUTO               0x0100
#define AR8031_CHIP_CONF_MODE_CFG_QUAL                 0x00F0
#define AR8031_CHIP_CONF_MODE_CFG                      0x000F

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//AR8031 Ethernet PHY driver
extern const PhyDriver ar8031PhyDriver;

//AR8031 related functions
error_t ar8031Init(NetInterface *interface);
void ar8031InitHook(NetInterface *interface);

void ar8031Tick(NetInterface *interface);

void ar8031EnableIrq(NetInterface *interface);
void ar8031DisableIrq(NetInterface *interface);

void ar8031EventHandler(NetInterface *interface);

void ar8031WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t ar8031ReadPhyReg(NetInterface *interface, uint8_t address);

void ar8031DumpPhyReg(NetInterface *interface);

void ar8031WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t ar8031ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
