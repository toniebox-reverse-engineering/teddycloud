/**
 * @file adin1100_driver.h
 * @brief ADIN1100 10Base-T1L Ethernet PHY driver
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

#ifndef _ADIN1100_DRIVER_H
#define _ADIN1100_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef ADIN1100_PHY_ADDR
   #define ADIN1100_PHY_ADDR 0
#elif (ADIN1100_PHY_ADDR < 0 || ADIN1100_PHY_ADDR > 31)
   #error ADIN1100_PHY_ADDR parameter is not valid
#endif

//ADIN1100 PHY registers
#define ADIN1100_MI_CONTROL                                             0x00
#define ADIN1100_MI_STATUS                                              0x01
#define ADIN1100_MI_PHY_ID1                                             0x02
#define ADIN1100_MI_PHY_ID2                                             0x03
#define ADIN1100_MMD_ACCESS_CNTRL                                       0x0D
#define ADIN1100_MMD_ACCESS                                             0x0E

//ADIN1100 MMD registers
#define ADIN1100_PMA_PMD_CNTRL1                                         0x01, 0x0000
#define ADIN1100_PMA_PMD_STAT1                                          0x01, 0x0001
#define ADIN1100_PMA_PMD_DEVS_IN_PKG1                                   0x01, 0x0005
#define ADIN1100_PMA_PMD_DEVS_IN_PKG2                                   0x01, 0x0006
#define ADIN1100_PMA_PMD_CNTRL2                                         0x01, 0x0007
#define ADIN1100_PMA_PMD_STAT2                                          0x01, 0x0008
#define ADIN1100_PMA_PMD_TX_DIS                                         0x01, 0x0009
#define ADIN1100_PMA_PMD_EXT_ABILITY                                    0x01, 0x000B
#define ADIN1100_PMA_PMD_BT1_ABILITY                                    0x01, 0x0012
#define ADIN1100_PMA_PMD_BT1_CONTROL                                    0x01, 0x0834
#define ADIN1100_B10L_PMA_CNTRL                                         0x01, 0x08F6
#define ADIN1100_B10L_PMA_STAT                                          0x01, 0x08F7
#define ADIN1100_B10L_TEST_MODE_CNTRL                                   0x01, 0x08F8
#define ADIN1100_B10L_PMA_LINK_STAT                                     0x01, 0x8302
#define ADIN1100_MSE_VAL                                                0x01, 0x830B
#define ADIN1100_PCS_CNTRL1                                             0x03, 0x0000
#define ADIN1100_PCS_STAT1                                              0x03, 0x0001
#define ADIN1100_PCS_DEVS_IN_PKG1                                       0x03, 0x0005
#define ADIN1100_PCS_DEVS_IN_PKG2                                       0x03, 0x0006
#define ADIN1100_PCS_STAT2                                              0x03, 0x0008
#define ADIN1100_B10L_PCS_CNTRL                                         0x03, 0x08E6
#define ADIN1100_B10L_PCS_STAT                                          0x03, 0x08E7
#define ADIN1100_AN_DEVS_IN_PKG1                                        0x07, 0x0005
#define ADIN1100_AN_DEVS_IN_PKG2                                        0x07, 0x0006
#define ADIN1100_AN_CONTROL                                             0x07, 0x0200
#define ADIN1100_AN_STATUS                                              0x07, 0x0201
#define ADIN1100_AN_ADV_ABILITY_L                                       0x07, 0x0202
#define ADIN1100_AN_ADV_ABILITY_M                                       0x07, 0x0203
#define ADIN1100_AN_ADV_ABILITY_H                                       0x07, 0x0204
#define ADIN1100_AN_LP_ADV_ABILITY_L                                    0x07, 0x0205
#define ADIN1100_AN_LP_ADV_ABILITY_M                                    0x07, 0x0206
#define ADIN1100_AN_LP_ADV_ABILITY_H                                    0x07, 0x0207
#define ADIN1100_AN_NEXT_PAGE_L                                         0x07, 0x0208
#define ADIN1100_AN_NEXT_PAGE_M                                         0x07, 0x0209
#define ADIN1100_AN_NEXT_PAGE_H                                         0x07, 0x020A
#define ADIN1100_AN_LP_NEXT_PAGE_L                                      0x07, 0x020B
#define ADIN1100_AN_LP_NEXT_PAGE_M                                      0x07, 0x020C
#define ADIN1100_AN_LP_NEXT_PAGE_H                                      0x07, 0x020D
#define ADIN1100_AN_B10_ADV_ABILITY                                     0x07, 0x020E
#define ADIN1100_AN_B10_LP_ADV_ABILITY                                  0x07, 0x020F
#define ADIN1100_AN_FRC_MODE_EN                                         0x07, 0x8000
#define ADIN1100_AN_STATUS_EXTRA                                        0x07, 0x8001
#define ADIN1100_AN_PHY_INST_STATUS                                     0x07, 0x8030
#define ADIN1100_MMD1_DEV_ID1                                           0x1E, 0x0002
#define ADIN1100_MMD1_DEV_ID2                                           0x1E, 0x0003
#define ADIN1100_MMD1_DEVS_IN_PKG1                                      0x1E, 0x0005
#define ADIN1100_MMD1_DEVS_IN_PKG2                                      0x1E, 0x0006
#define ADIN1100_MMD1_STATUS                                            0x1E, 0x0008
#define ADIN1100_CRSM_IRQ_STATUS                                        0x1E, 0x0010
#define ADIN1100_CRSM_IRQ_MASK                                          0x1E, 0x0020
#define ADIN1100_CRSM_SFT_RST                                           0x1E, 0x8810
#define ADIN1100_CRSM_SFT_PD_CNTRL                                      0x1E, 0x8812
#define ADIN1100_CRSM_PHY_SUBSYS_RST                                    0x1E, 0x8814
#define ADIN1100_CRSM_MAC_IF_RST                                        0x1E, 0x8815
#define ADIN1100_CRSM_STAT                                              0x1E, 0x8818
#define ADIN1100_CRSM_PMG_CNTRL                                         0x1E, 0x8819
#define ADIN1100_CRSM_MAC_IF_CFG                                        0x1E, 0x882B
#define ADIN1100_CRSM_DIAG_CLK_CTRL                                     0x1E, 0x882C
#define ADIN1100_MGMT_PRT_PKG                                           0x1E, 0x8C22
#define ADIN1100_MGMT_MDIO_CNTRL                                        0x1E, 0x8C30
#define ADIN1100_DIGIO_PINMUX                                           0x1E, 0x8C56
#define ADIN1100_DIGIO_PINMUX2                                          0x1E, 0x8C57
#define ADIN1100_LED0_BLINK_TIME_CNTRL                                  0x1E, 0x8C80
#define ADIN1100_LED1_BLINK_TIME_CNTRL                                  0x1E, 0x8C81
#define ADIN1100_LED_CNTRL                                              0x1E, 0x8C82
#define ADIN1100_LED_POLARITY                                           0x1E, 0x8C83
#define ADIN1100_MMD2_DEV_ID1                                           0x1F, 0x0002
#define ADIN1100_MMD2_DEV_ID2                                           0x1F, 0x0003
#define ADIN1100_MMD2_DEVS_IN_PKG1                                      0x1F, 0x0005
#define ADIN1100_MMD2_DEVS_IN_PKG2                                      0x1F, 0x0006
#define ADIN1100_MMD2_STATUS                                            0x1F, 0x0008
#define ADIN1100_PHY_SUBSYS_IRQ_STATUS                                  0x1F, 0x0011
#define ADIN1100_PHY_SUBSYS_IRQ_MASK                                    0x1F, 0x0021
#define ADIN1100_FC_EN                                                  0x1F, 0x8001
#define ADIN1100_FC_IRQ_EN                                              0x1F, 0x8004
#define ADIN1100_FC_TX_SEL                                              0x1F, 0x8005
#define ADIN1100_RX_ERR_CNT                                             0x1F, 0x8008
#define ADIN1100_FC_FRM_CNT_H                                           0x1F, 0x8009
#define ADIN1100_FC_FRM_CNT_L                                           0x1F, 0x800A
#define ADIN1100_FC_LEN_ERR_CNT                                         0x1F, 0x800B
#define ADIN1100_FC_ALGN_ERR_CNT                                        0x1F, 0x800C
#define ADIN1100_FC_SYMB_ERR_CNT                                        0x1F, 0x800D
#define ADIN1100_FC_OSZ_CNT                                             0x1F, 0x800E
#define ADIN1100_FC_USZ_CNT                                             0x1F, 0x800F
#define ADIN1100_FC_ODD_CNT                                             0x1F, 0x8010
#define ADIN1100_FC_ODD_PRE_CNT                                         0x1F, 0x8011
#define ADIN1100_FC_FALSE_CARRIER_CNT                                   0x1F, 0x8013
#define ADIN1100_FG_EN                                                  0x1F, 0x8020
#define ADIN1100_FG_CNTRL_RSTRT                                         0x1F, 0x8021
#define ADIN1100_FG_CONT_MODE_EN                                        0x1F, 0x8022
#define ADIN1100_FG_IRQ_EN                                              0x1F, 0x8023
#define ADIN1100_FG_FRM_LEN                                             0x1F, 0x8025
#define ADIN1100_FG_IFG_LEN                                             0x1F, 0x8026
#define ADIN1100_FG_NFRM_H                                              0x1F, 0x8027
#define ADIN1100_FG_NFRM_L                                              0x1F, 0x8028
#define ADIN1100_FG_DONE                                                0x1F, 0x8029
#define ADIN1100_RMII_CFG                                               0x1F, 0x8050
#define ADIN1100_MAC_IF_LOOPBACK                                        0x1F, 0x8055
#define ADIN1100_MAC_IF_SOP_CNTRL                                       0x1F, 0x805A

//MII Control register
#define ADIN1100_MI_CONTROL_MI_SFT_RST                                  0x8000
#define ADIN1100_MI_CONTROL_MI_LOOPBACK                                 0x4000
#define ADIN1100_MI_CONTROL_MI_SPEED_SEL_LSB                            0x2000
#define ADIN1100_MI_CONTROL_MI_AN_EN                                    0x1000
#define ADIN1100_MI_CONTROL_MI_SFT_PD                                   0x0800
#define ADIN1100_MI_CONTROL_MI_ISOLATE                                  0x0400
#define ADIN1100_MI_CONTROL_MI_FULL_DUPLEX                              0x0100
#define ADIN1100_MI_CONTROL_MI_COLTEST                                  0x0080
#define ADIN1100_MI_CONTROL_MI_SPEED_SEL_MSB                            0x0040
#define ADIN1100_MI_CONTROL_MI_UNIDIR_EN                                0x0020

//MII Status register
#define ADIN1100_MI_STATUS_MI_T4_SPRT                                   0x8000
#define ADIN1100_MI_STATUS_MI_FD100_SPRT                                0x4000
#define ADIN1100_MI_STATUS_MI_HD100_SPRT                                0x2000
#define ADIN1100_MI_STATUS_MI_FD10_SPRT                                 0x1000
#define ADIN1100_MI_STATUS_MI_HD10_SPRT                                 0x0800
#define ADIN1100_MI_STATUS_MI_FD_T2_SPRT                                0x0400
#define ADIN1100_MI_STATUS_MI_HD_T2_SPRT                                0x0200
#define ADIN1100_MI_STATUS_MI_EXT_STAT_SPRT                             0x0100
#define ADIN1100_MI_STATUS_MI_UNIDIR_ABLE                               0x0080
#define ADIN1100_MI_STATUS_MI_MF_PREAM_SUP_ABLE                         0x0040
#define ADIN1100_MI_STATUS_MI_AN_COMPLETE                               0x0020
#define ADIN1100_MI_STATUS_MI_REM_FLT                                   0x0010
#define ADIN1100_MI_STATUS_MI_AN_ABLE                                   0x0008
#define ADIN1100_MI_STATUS_MI_LINK_STAT_LAT                             0x0004
#define ADIN1100_MI_STATUS_MI_JABBER_DET                                0x0002
#define ADIN1100_MI_STATUS_MI_EXT_CAPABLE                               0x0001

//PHY Identifier 1 register
#define ADIN1100_MI_PHY_ID1_MI_PHY_ID1                                  0xFFFF
#define ADIN1100_MI_PHY_ID1_MI_PHY_ID1_DEFAULT                          0x0283

//PHY Identifier 2 register
#define ADIN1100_MI_PHY_ID2_MI_PHY_ID2_OUI                              0xFC00
#define ADIN1100_MI_PHY_ID2_MI_PHY_ID2_OUI_DEFAULT                      0xBC00
#define ADIN1100_MI_PHY_ID2_MI_MODEL_NUM                                0x03F0
#define ADIN1100_MI_PHY_ID2_MI_MODEL_NUM_DEFAULT                        0x0080
#define ADIN1100_MI_PHY_ID2_MI_REV_NUM                                  0x000F
#define ADIN1100_MI_PHY_ID2_MI_REV_NUM_DEFAULT                          0x0001

//MMD Access Control register
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION                      0xC000
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_ADDR                 0x0000
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_DATA_NO_POST_INC     0x4000
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_DATA_POST_INC_RW     0x8000
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_DATA_POST_INC_W      0xC000
#define ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_DEVAD                         0x001F

//PMA/PMD Control 1 register
#define ADIN1100_PMA_PMD_CNTRL1_PMA_SFT_RST                             0x8000
#define ADIN1100_PMA_PMD_CNTRL1_PMA_SFT_PD                              0x0800
#define ADIN1100_PMA_PMD_CNTRL1_LB_PMA_LOC_EN                           0x0001

//PMA/PMD Status 1 register
#define ADIN1100_PMA_PMD_STAT1_PMA_LINK_STAT_OK_LL                      0x0004
#define ADIN1100_PMA_PMD_STAT1_PMA_SFT_PD_ABLE                          0x0002

//PMA/PMD Control 2 register
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL                        0x007F
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_CX4            0x0000
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_EW             0x0001
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_LW             0x0002
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_SW             0x0003
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_LX4            0x0004
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_ER             0x0005
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_LR             0x0006
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_SR             0x0007
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_LRM            0x0008
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_T              0x0009
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_KX4            0x000A
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_KR             0x000B
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_1000BASE_T             0x000C
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_1000BASE_KX            0x000D
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100BASE_TX             0x000E
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10BASE_T               0x000F
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_D1       0x0010
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_D2       0x0011
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_D3       0x0012
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_D1          0x0013
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_D2          0x0014
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_D3          0x0015
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_U1       0x0016
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_U2       0x0017
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_U3       0x0018
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_U1          0x0019
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_U3          0x001A
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_RESERVED               0x001B
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_D4          0x001C
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_D4       0x001D
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GBASE_PR_U4          0x001E
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10_1GBASE_PRX_U4       0x001F
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_KR4            0x0020
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_CR4            0x0021
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_SR4            0x0022
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_LR4            0x0023
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_FR             0x0024
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_ER4            0x0025
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_40GBASE_T              0x0026
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_CR10          0x0028
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_SR10          0x0029
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_LR4           0x002A
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_ER4           0x002B
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_KP4           0x002C
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_KR4           0x002D
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_CR4           0x002E
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_100GBASE_SR4           0x002F
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_2_5GBASE_T             0x0030
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_5GBASE_T               0x0031
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GPASS_XR_D           0x0032
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_10GPASS_XR_U           0x0033
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_BASE_H                 0x0034
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_LR             0x0035
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_ER             0x0036
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_T              0x0037
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_CR             0x0038
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_KR             0x0039
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_25GBASE_SR             0x003A
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_BASE_T1                0x003D
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_200GBASE_DR4           0x0053
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_200GBASE_FR4           0x0054
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_200GBASE_LR4           0x0055
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_400GBASE_SR16          0x0059
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_400GBASE_DR4           0x005A
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_400GBASE_FR8           0x005B
#define ADIN1100_PMA_PMD_CNTRL2_PMA_PMD_TYPE_SEL_400GBASE_LR8           0x005C

//PMA/PMD Status 2 register
#define ADIN1100_PMA_PMD_STAT2_PMA_PMD_PRESENT                          0xC000
#define ADIN1100_PMA_PMD_STAT2_PMA_PMD_EXT_ABLE                         0x0200
#define ADIN1100_PMA_PMD_STAT2_PMA_PMD_TX_DIS_ABLE                      0x0100
#define ADIN1100_PMA_PMD_STAT2_LB_PMA_LOC_ABLE                          0x0001

//PMA/PMD Transmit Disable register
#define ADIN1100_PMA_PMD_TX_DIS_PMA_TX_DIS                              0x0001

//PMA/PMD Extended Abilities register
#define ADIN1100_PMA_PMD_EXT_ABILITY_PMA_PMD_BT1_ABLE                   0x0800

//BASE-T1 PMA/PMD Extended Ability register
#define ADIN1100_PMA_PMD_BT1_ABILITY_B10S_ABILITY                       0x0008
#define ADIN1100_PMA_PMD_BT1_ABILITY_B10L_ABILITY                       0x0004
#define ADIN1100_PMA_PMD_BT1_ABILITY_B1000_ABILITY                      0x0002
#define ADIN1100_PMA_PMD_BT1_ABILITY_B100_ABILITY                       0x0001

//BASE-T1 PMA/PMD Control register
#define ADIN1100_PMA_PMD_BT1_CONTROL_CFG_MST                            0x4000
#define ADIN1100_PMA_PMD_BT1_CONTROL_BT1_TYPE_SEL                       0x000F
#define ADIN1100_PMA_PMD_BT1_CONTROL_BT1_TYPE_SEL_100BASE_T             0x0000
#define ADIN1100_PMA_PMD_BT1_CONTROL_BT1_TYPE_SEL_1000BASE_T            0x0001
#define ADIN1100_PMA_PMD_BT1_CONTROL_BT1_TYPE_SEL_10BASE_T1L            0x0002
#define ADIN1100_PMA_PMD_BT1_CONTROL_BT1_TYPE_SEL_10BASE_T1S            0x0003

//10BASE-T1L PMA Control register
#define ADIN1100_B10L_PMA_CNTRL_B10L_TX_DIS_MODE_EN                     0x4000
#define ADIN1100_B10L_PMA_CNTRL_B10L_TX_LVL_HI                          0x1000
#define ADIN1100_B10L_PMA_CNTRL_B10L_EEE                                0x0400
#define ADIN1100_B10L_PMA_CNTRL_B10L_LB_PMA_LOC_EN                      0x0001

//10BASE-T1L PMA Status register
#define ADIN1100_B10L_PMA_STAT_B10L_LB_PMA_LOC_ABLE                     0x2000
#define ADIN1100_B10L_PMA_STAT_B10L_TX_LVL_HI_ABLE                      0x1000
#define ADIN1100_B10L_PMA_STAT_B10L_PMA_SFT_PD_ABLE                     0x0800
#define ADIN1100_B10L_PMA_STAT_B10L_EEE_ABLE                            0x0400

//10BASE-T1L Test Mode Control register
#define ADIN1100_B10L_TEST_MODE_CNTRL_B10L_TX_TEST_MODE                 0xE000

//10BASE-T1L PMA Link Status register
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_REM_RCVR_STAT_OK_LL            0x0200
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_REM_RCVR_STAT_OK               0x0100
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_LOC_RCVR_STAT_OK_LL            0x0080
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_LOC_RCVR_STAT_OK               0x0040
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_DSCR_STAT_OK_LL                0x0020
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_DSCR_STAT_OK                   0x0010
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_LINK_STAT_OK_LL                0x0002
#define ADIN1100_B10L_PMA_LINK_STAT_B10L_LINK_STAT_OK                   0x0001

//PCS Control 1 register
#define ADIN1100_PCS_CNTRL1_PCS_SFT_RST                                 0x8000
#define ADIN1100_PCS_CNTRL1_LB_PCS_EN                                   0x4000
#define ADIN1100_PCS_CNTRL1_PCS_SFT_PD                                  0x0800

//PCS Status 1 register
#define ADIN1100_PCS_STAT1_PCS_SFT_PD_ABLE                              0x0002

//PCS Status 2 register
#define ADIN1100_PCS_STAT2_PCS_PRESENT                                  0xC000

//10BASE-T1L PCS Control register
#define ADIN1100_B10L_PCS_CNTRL_B10L_LB_PCS_EN                          0x4000

//10BASE-T1L PCS Status register
#define ADIN1100_B10L_PCS_STAT_B10L_PCS_DSCR_STAT_OK_LL                 0x0004

//BASE-T1 Autonegotiation Control register
#define ADIN1100_AN_CONTROL_AN_EN                                       0x1000
#define ADIN1100_AN_CONTROL_AN_RESTART                                  0x0200

//BASE-T1 Autonegotiation Status register
#define ADIN1100_AN_STATUS_AN_PAGE_RX                                   0x0040
#define ADIN1100_AN_STATUS_AN_COMPLETE                                  0x0020
#define ADIN1100_AN_STATUS_AN_REMOTE_FAULT                              0x0010
#define ADIN1100_AN_STATUS_AN_ABLE                                      0x0008
#define ADIN1100_AN_STATUS_AN_LINK_STATUS                               0x0004

//BASE-T1 Autonegotiation Advertisement L register
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_NEXT_PAGE_REQ                  0x8000
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_ACK                            0x4000
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_REMOTE_FAULT                   0x2000
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_FORCE_MS                       0x1000
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_PAUSE                          0x0C00
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_SELECTOR                       0x001F
#define ADIN1100_AN_ADV_ABILITY_L_AN_ADV_SELECTOR_DEFAULT               0x0001

//BASE-T1 Autonegotiation Advertisement M register
#define ADIN1100_AN_ADV_ABILITY_M_AN_ADV_B10L                           0x4000
#define ADIN1100_AN_ADV_ABILITY_M_AN_ADV_MST                            0x0010

//BASE-T1 Autonegotiation Advertisement H register
#define ADIN1100_AN_ADV_ABILITY_H_AN_ADV_B10L_TX_LVL_HI_ABL             0x2000
#define ADIN1100_AN_ADV_ABILITY_H_AN_ADV_B10L_TX_LVL_HI_REQ             0x1000

//BASE-T1 Autonegotiation Link Partner Base Page Ability L register
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_NEXT_PAGE_REQ            0x8000
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_ACK                      0x4000
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_REMOTE_FAULT             0x2000
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_FORCE_MS                 0x1000
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_PAUSE                    0x0C00
#define ADIN1100_AN_LP_ADV_ABILITY_L_AN_LP_ADV_SELECTOR                 0x001F

//BASE-T1 Autonegotiation Link Partner Base Page Ability M register
#define ADIN1100_AN_LP_ADV_ABILITY_M_AN_LP_ADV_B10L                     0x4000
#define ADIN1100_AN_LP_ADV_ABILITY_M_AN_LP_ADV_B1000                    0x0080
#define ADIN1100_AN_LP_ADV_ABILITY_M_AN_LP_ADV_B10S_FD                  0x0040
#define ADIN1100_AN_LP_ADV_ABILITY_M_AN_LP_ADV_B100                     0x0020
#define ADIN1100_AN_LP_ADV_ABILITY_M_AN_LP_ADV_MST                      0x0010

//BASE-T1 Autonegotiation Link Partner Base Page Ability H register
#define ADIN1100_AN_LP_ADV_ABILITY_H_AN_LP_ADV_B10L_EEE                 0x4000
#define ADIN1100_AN_LP_ADV_ABILITY_H_AN_LP_ADV_B10L_TX_LVL_HI_ABL       0x2000
#define ADIN1100_AN_LP_ADV_ABILITY_H_AN_LP_ADV_B10L_TX_LVL_HI_REQ       0x1000
#define ADIN1100_AN_LP_ADV_ABILITY_H_AN_LP_ADV_B10S_HD                  0x0800

//BASE-T1 Autonegotiation Next Page Transmit L register
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_NEXT_PAGE_REQ                     0x8000
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_ACK                               0x4000
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_MESSAGE_PAGE                      0x2000
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_ACK2                              0x1000
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_TOGGLE                            0x0800
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_MESSAGE_CODE                      0x07FF
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_MESSAGE_CODE_NULL                 0x0001
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_MESSAGE_CODE_OUI_TAGGED           0x0005
#define ADIN1100_AN_NEXT_PAGE_L_AN_NP_MESSAGE_CODE_AN_DEV_ID_TAG        0x0006

//BASE-T1 Autonegotiation Next Page Transmit M register
#define ADIN1100_AN_NEXT_PAGE_M_AN_NP_UNFORMATTED1                      0xFFFF

//BASE-T1 Autonegotiation Next Page Transmit H register
#define ADIN1100_AN_NEXT_PAGE_H_AN_NP_UNFORMATTED2                      0xFFFF

//BASE-T1 Autonegotiation Link Partner Next Page Ability L register
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_NEXT_PAGE_REQ               0x8000
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_ACK                         0x4000
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_MESSAGE_PAGE                0x2000
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_ACK2                        0x1000
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_TOGGLE                      0x0800
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_MESSAGE_CODE                0x07FF
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_MESSAGE_CODE_NULL           0x0001
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_MESSAGE_CODE_OUI_TAGGED     0x0005
#define ADIN1100_AN_LP_NEXT_PAGE_L_AN_LP_NP_MESSAGE_CODE_AN_DEV_ID_TAG  0x0006

//BASE-T1 Autonegotiation Link Partner Next Page Ability M register
#define ADIN1100_AN_LP_NEXT_PAGE_M_AN_LP_NP_UNFORMATTED1                0xFFFF

//BASE-T1 Autonegotiation Link Partner Next Page Ability H register
#define ADIN1100_AN_LP_NEXT_PAGE_H_AN_LP_NP_UNFORMATTED2                0xFFFF

//10BASE-T1 Autonegotiation Control register
#define ADIN1100_AN_B10_ADV_ABILITY_AN_B10_ADV_B10L                     0x8000
#define ADIN1100_AN_B10_ADV_ABILITY_AN_B10_ADV_B10L_EEE                 0x4000
#define ADIN1100_AN_B10_ADV_ABILITY_AN_B10_ADV_B10L_TX_LVL_HI_ABL       0x2000
#define ADIN1100_AN_B10_ADV_ABILITY_AN_B10_ADV_B10L_TX_LVL_HI_REQ       0x1000

//10BASE-T1 Autonegotiation Status register
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10L               0x8000
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10L_EEE           0x4000
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10L_TX_LVL_HI_ABL 0x2000
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10L_TX_LVL_HI_REQ 0x1000
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10S_FD            0x0080
#define ADIN1100_AN_B10_LP_ADV_ABILITY_AN_B10_LP_ADV_B10S_HD            0x0040

//Autonegotiation Forced Mode Enable register
#define ADIN1100_AN_FRC_MODE_EN_AN_FRC_MODE_EN                          0x0001

//Extra Autonegotiation Status register
#define ADIN1100_AN_STATUS_EXTRA_AN_LP_NP_RX                            0x0400
#define ADIN1100_AN_STATUS_EXTRA_AN_INC_LINK                            0x0200
#define ADIN1100_AN_STATUS_EXTRA_AN_TX_LVL_RSLTN                        0x0180
#define ADIN1100_AN_STATUS_EXTRA_AN_TX_LVL_RSLTN_NOT_RUN                0x0000
#define ADIN1100_AN_STATUS_EXTRA_AN_TX_LVL_RSLTN_SUCCESS_1_0V           0x0100
#define ADIN1100_AN_STATUS_EXTRA_AN_TX_LVL_RSLTN_SUCCESS_2_4V           0x0180
#define ADIN1100_AN_STATUS_EXTRA_AN_MS_CONFIG_RSLTN                     0x0060
#define ADIN1100_AN_STATUS_EXTRA_AN_MS_CONFIG_RSLTN_NOT_RUN             0x0000
#define ADIN1100_AN_STATUS_EXTRA_AN_MS_CONFIG_RSLTN_CONFIG_FAULT        0x0020
#define ADIN1100_AN_STATUS_EXTRA_AN_MS_CONFIG_RSLTN_SUCCESS_SLAVE       0x0040
#define ADIN1100_AN_STATUS_EXTRA_AN_MS_CONFIG_RSLTN_SUCCESS_MASTER      0x0060
#define ADIN1100_AN_STATUS_EXTRA_AN_HCD_TECH                            0x001E
#define ADIN1100_AN_STATUS_EXTRA_AN_HCD_TECH_NULL                       0x0000
#define ADIN1100_AN_STATUS_EXTRA_AN_HCD_TECH_10BASE_T1L                 0x0002
#define ADIN1100_AN_STATUS_EXTRA_AN_LINK_GOOD                           0x0001

//PHY Instantaneous Status register
#define ADIN1100_AN_PHY_INST_STATUS_IS_AN_TX_EN                         0x0010
#define ADIN1100_AN_PHY_INST_STATUS_IS_CFG_MST                          0x0008
#define ADIN1100_AN_PHY_INST_STATUS_IS_CFG_SLV                          0x0004
#define ADIN1100_AN_PHY_INST_STATUS_IS_TX_LVL_HI                        0x0002
#define ADIN1100_AN_PHY_INST_STATUS_IS_TX_LVL_LO                        0x0001

//Vendor Specific 1 MMD Identifier High register
#define ADIN1100_MMD1_DEV_ID1_MMD1_DEV_ID1                              0xFFFF
#define ADIN1100_MMD1_DEV_ID1_MMD1_DEV_ID1_DEFAULT                      0x0283

//Vendor Specific 1 MMD Identifier Low register
#define ADIN1100_MMD1_DEV_ID2_MMD1_DEV_ID2_OUI                          0xFC00
#define ADIN1100_MMD1_DEV_ID2_MMD1_DEV_ID2_OUI_DEFAULT                  0xBC00
#define ADIN1100_MMD1_DEV_ID2_MMD1_MODEL_NUM                            0x03F0
#define ADIN1100_MMD1_DEV_ID2_MMD1_MODEL_NUM_DEFAULT                    0x0080
#define ADIN1100_MMD1_DEV_ID2_MMD1_REV_NUM                              0x000F
#define ADIN1100_MMD1_DEV_ID2_MMD1_REV_NUM_DEFAULT                      0x0001

//Vendor Specific 1 MMD Status register
#define ADIN1100_MMD1_STATUS_MMD1_STATUS                                0xC000
#define ADIN1100_MMD1_STATUS_MMD1_STATUS_DEV_RESP                       0x8000

//System Interrupt Status register
#define ADIN1100_CRSM_IRQ_STATUS_CRSM_SW_IRQ_LH                         0x8000
#define ADIN1100_CRSM_IRQ_STATUS_CRSM_HRD_RST_IRQ_LH                    0x1000

//System Interrupt Mask register
#define ADIN1100_CRSM_IRQ_MASK_CRSM_SW_IRQ_REQ                          0x8000
#define ADIN1100_CRSM_IRQ_MASK_CRSM_HRD_RST_IRQ_EN                      0x1000

//Software Reset register
#define ADIN1100_CRSM_SFT_RST_CRSM_SFT_RST                              0x0001

//Software Power-Down Control register
#define ADIN1100_CRSM_SFT_PD_CNTRL_CRSM_SFT_PD                          0x0001

//PHY Subsystem Reset register
#define ADIN1100_CRSM_PHY_SUBSYS_RST_CRSM_PHY_SUBSYS_RST                0x0001

//PHY MAC Interface Reset register
#define ADIN1100_CRSM_MAC_IF_RST_CRSM_MAC_IF_RST                        0x0001

//System Status register
#define ADIN1100_CRSM_STAT_CRSM_SFT_PD_RDY                              0x0002
#define ADIN1100_CRSM_STAT_CRSM_SYS_RDY                                 0x0001

//CRSM Power Management Control register
#define ADIN1100_CRSM_PMG_CNTRL_CRSM_FRC_OSC_EN                         0x0001

//MAC Interface Configuration register
#define ADIN1100_CRSM_MAC_IF_CFG_CRSM_RMII_CLK50                        0x8000
#define ADIN1100_CRSM_MAC_IF_CFG_CRSM_RMII_CLK_EN                       0x4000
#define ADIN1100_CRSM_MAC_IF_CFG_CRSM_RMII_MEDIA_CNV_EN                 0x0100
#define ADIN1100_CRSM_MAC_IF_CFG_CRSM_RMII_EN                           0x0010
#define ADIN1100_CRSM_MAC_IF_CFG_CRSM_RGMII_EN                          0x0001

//CRSM Diagnostics Clock Control register
#define ADIN1100_CRSM_DIAG_CLK_CTRL_CRSM_DIAG_CLK_EN                    0x0001

//Package Configuration Values register
#define ADIN1100_MGMT_PRT_PKG_MGMT_PRT_PKG_VAL                          0x003F

//MDIO Control register
#define ADIN1100_MGMT_MDIO_CNTRL_MGMT_GRP_MDIO_EN                       0x0001

//Pin Mux Configuration 1 register
#define ADIN1100_DIGIO_PINMUX_DIGIO_LED1_PINMUX                         0x000E
#define ADIN1100_DIGIO_PINMUX_DIGIO_LED1_PINMUX_LED_1                   0x0000
#define ADIN1100_DIGIO_PINMUX_DIGIO_LED1_PINMUX_NONE                    0x000E
#define ADIN1100_DIGIO_PINMUX_DIGIO_LINK_ST_POLARITY                    0x0001
#define ADIN1100_DIGIO_PINMUX_DIGIO_LINK_ST_POLARITY_ASSERT_HIGH        0x0000
#define ADIN1100_DIGIO_PINMUX_DIGIO_LINK_ST_POLARITY_ASSERT_LOW         0x0001

//Pin Mux Configuration 2 register
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX                       0x00F0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RXD_3                 0x0000
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RXD_2                 0x0010
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RXD_1                 0x0020
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RX_CLK                0x0030
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RX_DV                 0x0040
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_RX_ER                 0x0050
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TX_ER                 0x0060
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TX_EN                 0x0070
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TX_CLK                0x0080
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TXD_1                 0x0090
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TXD_2                 0x00A0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_TXD_3                 0x00B0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_LINK_ST               0x00C0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_LED_0                 0x00D0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_LED_1                 0x00E0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_RXSOP_PINMUX_OFF                   0x00F0
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX                       0x000F
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RXD_3                 0x0000
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RXD_2                 0x0001
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RXD_1                 0x0002
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RX_CLK                0x0003
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RX_DV                 0x0004
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_RX_ER                 0x0005
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TX_ER                 0x0006
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TX_EN                 0x0007
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TX_CLK                0x0008
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TXD_1                 0x0009
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TXD_2                 0x000A
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_TXD_3                 0x000B
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_LINK_ST               0x000C
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_LED_0                 0x000D
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_LED_1                 0x000E
#define ADIN1100_DIGIO_PINMUX2_DIGIO_TXSOP_PINMUX_OFF                   0x000F

//LED 0 On/Off Blink Time register
#define ADIN1100_LED0_BLINK_TIME_CNTRL_LED0_ON_N4MS                     0xFF00
#define ADIN1100_LED0_BLINK_TIME_CNTRL_LED0_OFF_N4MS                    0x00FF

//LED 1 On/Off Blink Time register
#define ADIN1100_LED1_BLINK_TIME_CNTRL_LED1_ON_N4MS                     0xFF00
#define ADIN1100_LED1_BLINK_TIME_CNTRL_LED1_OFF_N4MS                    0x00FF

//LED Control register
#define ADIN1100_LED_CNTRL_LED1_EN                                      0x8000
#define ADIN1100_LED_CNTRL_LED1_LINK_ST_QUALIFY                         0x4000
#define ADIN1100_LED_CNTRL_LED1_MODE                                    0x2000
#define ADIN1100_LED_CNTRL_LED1_FUNCTION                                0x1F00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_TXRX_ACTIVITY           0x0000
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_TX_ACTIVITY             0x0100
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_RX_ACTIVITY             0x0200
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_ONLY                    0x0300
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TXRX_ACTIVITY                  0x0400
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TX_ACTIVITY                    0x0500
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_RX_ACTIVITY                    0x0600
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_RX_ER                   0x0700
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LINKUP_RX_TX_ER                0x0800
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_RX_ER                          0x0900
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_RX_TX_ER                       0x0A00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TX_SOP                         0x0B00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_RX_SOP                         0x0C00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_ON                             0x0D00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_OFF                            0x0E00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_BLINK                          0x0F00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TX_LEVEL_2P4                   0x1000
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TX_LEVEL_1P0                   0x1100
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_MASTER                         0x1200
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_SLAVE                          0x1300
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_INCOMPATIBLE_LINK_CFG          0x1400
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_AN_LINK_GOOD                   0x1500
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_AN_COMPLETE                    0x1600
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TS_TIMER                       0x1700
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_LOC_RCVR_STATUS                0x1800
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_REM_RCVR_STATUS                0x1900
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_CLK25_REF                      0x1A00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_TX_TCLK                        0x1B00
#define ADIN1100_LED_CNTRL_LED1_FUNCTION_CLK_120MHZ                     0x1C00
#define ADIN1100_LED_CNTRL_LED0_EN                                      0x0080
#define ADIN1100_LED_CNTRL_LED0_LINK_ST_QUALIFY                         0x0040
#define ADIN1100_LED_CNTRL_LED0_MODE                                    0x0020
#define ADIN1100_LED_CNTRL_LED0_FUNCTION                                0x001F
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_TXRX_ACTIVITY           0x0000
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_TX_ACTIVITY             0x0001
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_RX_ACTIVITY             0x0002
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_ONLY                    0x0003
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TXRX_ACTIVITY                  0x0004
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TX_ACTIVITY                    0x0005
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_RX_ACTIVITY                    0x0006
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_RX_ER                   0x0007
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_RX_TX_ER                0x0008
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_RX_ER                          0x0009
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_RX_TX_ER                       0x000A
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TX_SOP                         0x000B
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_RX_SOP                         0x000C
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_ON                             0x000D
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_OFF                            0x000E
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_BLINK                          0x000F
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TX_LEVEL_2P4                   0x0010
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TX_LEVEL_1P0                   0x0011
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_MASTER                         0x0012
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_SLAVE                          0x0013
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_INCOMPATIBLE_LINK_CFG          0x0014
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_AN_LINK_GOOD                   0x0015
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_AN_COMPLETE                    0x0016
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TS_TIMER                       0x0017
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_LOC_RCVR_STATUS                0x0018
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_REM_RCVR_STATUS                0x0019
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_CLK25_REF                      0x001A
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_TX_TCLK                        0x001B
#define ADIN1100_LED_CNTRL_LED0_FUNCTION_CLK_120MHZ                     0x001C

//LED Polarity register
#define ADIN1100_LED_POLARITY_LED1_POLARITY                             0x000C
#define ADIN1100_LED_POLARITY_LED1_POLARITY_AUTOSENSE                   0x0000
#define ADIN1100_LED_POLARITY_LED1_POLARITY_ACTIVE_HIGH                 0x0004
#define ADIN1100_LED_POLARITY_LED1_POLARITY_ACTIVE_LOW                  0x0008
#define ADIN1100_LED_POLARITY_LED0_POLARITY                             0x0003
#define ADIN1100_LED_POLARITY_LED0_POLARITY_AUTOSENSE                   0x0000
#define ADIN1100_LED_POLARITY_LED0_POLARITY_ACTIVE_HIGH                 0x0001
#define ADIN1100_LED_POLARITY_LED0_POLARITY_ACTIVE_LOW                  0x0002

//Vendor Specific 2 MMD Identifier High register
#define ADIN1100_MMD2_DEV_ID1_MMD2_DEV_ID1                              0xFFFF
#define ADIN1100_MMD2_DEV_ID1_MMD2_DEV_ID1_DEFAULT                      0x0283

//Vendor Specific 2 MMD Identifier Low register
#define ADIN1100_MMD2_DEV_ID2_MMD2_DEV_ID2_OUI                          0xFC00
#define ADIN1100_MMD2_DEV_ID2_MMD2_DEV_ID2_OUI_DEFAULT                  0xBC00
#define ADIN1100_MMD2_DEV_ID2_MMD2_MODEL_NUM                            0x03F0
#define ADIN1100_MMD2_DEV_ID2_MMD2_MODEL_NUM_DEFAULT                    0x0080
#define ADIN1100_MMD2_DEV_ID2_MMD2_REV_NUM                              0x000F
#define ADIN1100_MMD2_DEV_ID2_MMD2_REV_NUM_DEFAULT                      0x0001

//Vendor Specific 2 MMD Status register
#define ADIN1100_MMD2_STATUS_MMD2_STATUS                                0xC000
#define ADIN1100_MMD2_STATUS_MMD2_STATUS_DEV_RESP                       0x8000

//PHY Subsystem Interrupt Status register
#define ADIN1100_PHY_SUBSYS_IRQ_STATUS_MAC_IF_FC_FG_IRQ_LH              0x4000
#define ADIN1100_PHY_SUBSYS_IRQ_STATUS_MAC_IF_EBUF_ERR_IRQ_LH           0x2000
#define ADIN1100_PHY_SUBSYS_IRQ_STATUS_AN_STAT_CHNG_IRQ_LH              0x0800
#define ADIN1100_PHY_SUBSYS_IRQ_STATUS_LINK_STAT_CHNG_LH                0x0002

//PHY Subsystem Interrupt Mask register
#define ADIN1100_PHY_SUBSYS_IRQ_MASK_MAC_IF_FC_FG_IRQ_EN                0x4000
#define ADIN1100_PHY_SUBSYS_IRQ_MASK_MAC_IF_EBUF_ERR_IRQ_EN             0x2000
#define ADIN1100_PHY_SUBSYS_IRQ_MASK_AN_STAT_CHNG_IRQ_EN                0x0800
#define ADIN1100_PHY_SUBSYS_IRQ_MASK_LINK_STAT_CHNG_IRQ_EN              0x0002

//Frame Checker Enable register
#define ADIN1100_FC_EN_FC_EN                                            0x0001

//Frame Checker Interrupt Enable register
#define ADIN1100_FC_IRQ_EN_FC_IRQ_EN                                    0x0001

//Frame Checker Transmit Select register
#define ADIN1100_FC_TX_SEL_FC_TX_SEL                                    0x0001

//Frame Generator Enable register
#define ADIN1100_FG_EN_FG_EN                                            0x0001

//Frame Generator Control/Restart register
#define ADIN1100_FG_CNTRL_RSTRT_FG_RSTRT                                0x0008
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL                                0x0007
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_NO_FRAMES                      0x0000
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_RANDOM                         0x0001
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_ALL_ZEROS                      0x0002
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_ALL_ONES                       0x0003
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_ALT                            0x0004
#define ADIN1100_FG_CNTRL_RSTRT_FG_CNTRL_DEC                            0x0005

//Frame Generator Continuous Mode Enable register
#define ADIN1100_FG_CONT_MODE_EN_FG_CONT_MODE_EN                        0x0001

//Frame Generator Interrupt Enable register
#define ADIN1100_FG_IRQ_EN_FG_IRQ_EN                                    0x0001

//Frame Generator Done register
#define ADIN1100_FG_DONE_FG_DONE                                        0x0001

//RMII Configuration register
#define ADIN1100_RMII_CFG_RMII_TXD_CHK_EN                               0x0001

//MAC Interface Loopbacks Configuration register
#define ADIN1100_MAC_IF_LOOPBACK_MAC_IF_REM_LB_RX_SUP_EN                0x0008
#define ADIN1100_MAC_IF_LOOPBACK_MAC_IF_REM_LB_EN                       0x0004
#define ADIN1100_MAC_IF_LOOPBACK_MAC_IF_LB_TX_SUP_EN                    0x0002
#define ADIN1100_MAC_IF_LOOPBACK_MAC_IF_LB_EN                           0x0001

//MAC Start Of Packet (SOP) Generation Control register
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_TX_SOP_LEN_CHK_EN              0x0020
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_TX_SOP_SFD_EN                  0x0010
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_TX_SOP_DET_EN                  0x0008
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_RX_SOP_LEN_CHK_EN              0x0004
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_RX_SOP_SFD_EN                  0x0002
#define ADIN1100_MAC_IF_SOP_CNTRL_MAC_IF_RX_SOP_DET_EN                  0x0001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ADIN1100 Ethernet PHY driver
extern const PhyDriver adin1100PhyDriver;

//ADIN1100 related functions
error_t adin1100Init(NetInterface *interface);
void adin1100InitHook(NetInterface *interface);

void adin1100Tick(NetInterface *interface);

void adin1100EnableIrq(NetInterface *interface);
void adin1100DisableIrq(NetInterface *interface);

void adin1100EventHandler(NetInterface *interface);

void adin1100WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t adin1100ReadPhyReg(NetInterface *interface, uint8_t address);

void adin1100DumpPhyReg(NetInterface *interface);

void adin1100WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t adin1100ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
