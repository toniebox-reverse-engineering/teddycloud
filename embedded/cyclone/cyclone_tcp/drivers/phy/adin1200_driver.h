/**
 * @file adin1200_driver.h
 * @brief ADIN1200 Ethernet PHY driver
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

#ifndef _ADIN1200_DRIVER_H
#define _ADIN1200_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef ADIN1200_PHY_ADDR
   #define ADIN1200_PHY_ADDR 0
#elif (ADIN1200_PHY_ADDR < 0 || ADIN1200_PHY_ADDR > 31)
   #error ADIN1200_PHY_ADDR parameter is not valid
#endif

//ADIN1200 PHY registers
#define ADIN1200_MII_CONTROL                                             0x00
#define ADIN1200_MII_STATUS                                              0x01
#define ADIN1200_PHY_ID_1                                                0x02
#define ADIN1200_PHY_ID_2                                                0x03
#define ADIN1200_AUTONEG_ADV                                             0x04
#define ADIN1200_LP_ABILITY                                              0x05
#define ADIN1200_AUTONEG_EXP                                             0x06
#define ADIN1200_TX_NEXT_PAGE                                            0x07
#define ADIN1200_LP_RX_NEXT_PAGE                                         0x08
#define ADIN1200_MSTR_SLV_STATUS                                         0x0A
#define ADIN1200_EXT_STATUS                                              0x0F
#define ADIN1200_EXT_REG_PTR                                             0x10
#define ADIN1200_EXT_REG_DATA                                            0x11
#define ADIN1200_PHY_CTRL_1                                              0x12
#define ADIN1200_PHY_CTRL_STATUS_1                                       0x13
#define ADIN1200_RX_ERR_CNT                                              0x14
#define ADIN1200_PHY_CTRL_STATUS_2                                       0x15
#define ADIN1200_PHY_CTRL_2                                              0x16
#define ADIN1200_PHY_CTRL_3                                              0x17
#define ADIN1200_IRQ_MASK                                                0x18
#define ADIN1200_IRQ_STATUS                                              0x19
#define ADIN1200_PHY_STATUS_1                                            0x1A
#define ADIN1200_LED_CTRL_1                                              0x1B
#define ADIN1200_LED_CTRL_2                                              0x1C
#define ADIN1200_LED_CTRL_3                                              0x1D
#define ADIN1200_PHY_STATUS_2                                            0x1F

//ADIN1200 Extended registers
#define ADIN1200_EEE_CAPABILITY                                          0x8000
#define ADIN1200_EEE_ADV                                                 0x8001
#define ADIN1200_EEE_LP_ABILITY                                          0x8002
#define ADIN1200_EEE_RSLVD                                               0x8008
#define ADIN1200_MSE_A                                                   0x8402
#define ADIN1200_FLD_EN                                                  0x8E27
#define ADIN1200_FLD_STAT_LAT                                            0x8E38
#define ADIN1200_RX_MII_CLK_STOP_EN                                      0x9400
#define ADIN1200_PCS_STATUS_1                                            0x9401
#define ADIN1200_FC_EN                                                   0x9403
#define ADIN1200_FC_IRQ_EN                                               0x9406
#define ADIN1200_FC_TX_SEL                                               0x9407
#define ADIN1200_FC_MAX_FRM_SIZE                                         0x9408
#define ADIN1200_FC_FRM_CNT_H                                            0x940A
#define ADIN1200_FC_FRM_CNT_L                                            0x940B
#define ADIN1200_FC_LEN_ERR_CNT                                          0x940C
#define ADIN1200_FC_ALGN_ERR_CNT                                         0x940D
#define ADIN1200_FC_SYMB_ERR_CNT                                         0x940E
#define ADIN1200_FC_OSZ_CNT                                              0x940F
#define ADIN1200_FC_USZ_CNT                                              0x9410
#define ADIN1200_FC_ODD_CNT                                              0x9411
#define ADIN1200_FC_ODD_PRE_CNT                                          0x9412
#define ADIN1200_FC_DRIBBLE_BITS_CNT                                     0x9413
#define ADIN1200_FC_FALSE_CARRIER_CNT                                    0x9414
#define ADIN1200_FG_EN                                                   0x9415
#define ADIN1200_FG_CNTRL_RSTRT                                          0x9416
#define ADIN1200_FG_CONT_MODE_EN                                         0x9417
#define ADIN1200_FG_IRQ_EN                                               0x9418
#define ADIN1200_FG_FRM_LEN                                              0x941A
#define ADIN1200_FG_IFG_LEN                                              0x941B
#define ADIN1200_FG_NFRM_H                                               0x941C
#define ADIN1200_FG_NFRM_L                                               0x941D
#define ADIN1200_FG_DONE                                                 0x941E
#define ADIN1200_FIFO_SYNC                                               0x9427
#define ADIN1200_SOP_CTRL                                                0x9428
#define ADIN1200_SOP_RX_DEL                                              0x9429
#define ADIN1200_SOP_TX_DEL                                              0x942A
#define ADIN1200_DPTH_MII_BYTE                                           0x9602
#define ADIN1200_LPI_WAKE_ERR_CNT                                        0xA000
#define ADIN1200_B_10_E_EN                                               0xB403
#define ADIN1200_B_10_TX_TST_MODE                                        0xB412
#define ADIN1200_B_100_TX_TST_MODE                                       0xB413
#define ADIN1200_CDIAG_RUN                                               0xBA1B
#define ADIN1200_CDIAG_XPAIR_DIS                                         0xBA1C
#define ADIN1200_CDIAG_DTLD_RSLTS_0                                      0xBA1D
#define ADIN1200_CDIAG_DTLD_RSLTS_1                                      0xBA1E
#define ADIN1200_CDIAG_FLT_DIST_0                                        0xBA21
#define ADIN1200_CDIAG_FLT_DIST_1                                        0xBA22
#define ADIN1200_CDIAG_CBL_LEN_EST                                       0xBA25
#define ADIN1200_LED_PUL_STR_DUR                                         0xBC00

//ADIN1200 Subsystem registers
#define ADIN1200_GE_SFT_RST                                              0xFF0C
#define ADIN1200_GE_SFT_RST_CFG_EN                                       0xFF0D
#define ADIN1200_GE_CLK_CFG                                              0xFF1F
#define ADIN1200_GE_RGMII_CFG                                            0xFF23
#define ADIN1200_GE_RMII_CFG                                             0xFF24
#define ADIN1200_GE_PHY_BASE_CFG                                         0xFF26
#define ADIN1200_GE_LNK_STAT_INV_EN                                      0xFF3C
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL                                   0xFF3D
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL                                   0xFF3E
#define ADIN1200_GE_IO_INT_N_OR_CNTRL                                    0xFF3F
#define ADIN1200_GE_IO_LED_A_OR_CNTRL                                    0xFF41

//MII Control register
#define ADIN1200_MII_CONTROL_SFT_RST                                     0x8000
#define ADIN1200_MII_CONTROL_LOOPBACK                                    0x4000
#define ADIN1200_MII_CONTROL_SPEED_SEL_LSB                               0x2000
#define ADIN1200_MII_CONTROL_AUTONEG_EN                                  0x1000
#define ADIN1200_MII_CONTROL_SFT_PD                                      0x0800
#define ADIN1200_MII_CONTROL_ISOLATE                                     0x0400
#define ADIN1200_MII_CONTROL_RESTART_ANEG                                0x0200
#define ADIN1200_MII_CONTROL_DPLX_MODE                                   0x0100
#define ADIN1200_MII_CONTROL_COLTEST                                     0x0080
#define ADIN1200_MII_CONTROL_SPEED_SEL_MSB                               0x0040
#define ADIN1200_MII_CONTROL_UNIDIR_EN                                   0x0020

//MII Status register
#define ADIN1200_MII_STATUS_T_4_SPRT                                     0x8000
#define ADIN1200_MII_STATUS_FD_100_SPRT                                  0x4000
#define ADIN1200_MII_STATUS_HD_100_SPRT                                  0x2000
#define ADIN1200_MII_STATUS_FD_10_SPRT                                   0x1000
#define ADIN1200_MII_STATUS_HD_10_SPRT                                   0x0800
#define ADIN1200_MII_STATUS_FD_T_2_SPRT                                  0x0400
#define ADIN1200_MII_STATUS_HD_T_2_SPRT                                  0x0200
#define ADIN1200_MII_STATUS_EXT_STAT_SPRT                                0x0100
#define ADIN1200_MII_STATUS_UNIDIR_ABLE                                  0x0080
#define ADIN1200_MII_STATUS_MF_PREAM_SUP_ABLE                            0x0040
#define ADIN1200_MII_STATUS_AUTONEG_DONE                                 0x0020
#define ADIN1200_MII_STATUS_REM_FLT_LAT                                  0x0010
#define ADIN1200_MII_STATUS_AUTONEG_ABLE                                 0x0008
#define ADIN1200_MII_STATUS_LINK_STAT_LAT                                0x0004
#define ADIN1200_MII_STATUS_JABBER_DET_LAT                               0x0002
#define ADIN1200_MII_STATUS_EXT_CAPABLE                                  0x0001

//PHY Identifier 1 register
#define ADIN1200_PHY_ID_1_PHY_ID_1                                       0xFFFF
#define ADIN1200_PHY_ID_1_PHY_ID_1_DEFAULT                               0x0283

//PHY Identifier 2 register
#define ADIN1200_PHY_ID_2_PHY_ID_2_OUI                                   0xFC00
#define ADIN1200_PHY_ID_2_PHY_ID_2_OUI_DEFAULT                           0xBC00
#define ADIN1200_PHY_ID_2_MODEL_NUM                                      0x03F0
#define ADIN1200_PHY_ID_2_MODEL_NUM_DEFAULT                              0x0020
#define ADIN1200_PHY_ID_2_REV_NUM                                        0x000F
#define ADIN1200_PHY_ID_2_REV_NUM_DEFAULT                                0x0000

//Autonegotiation Advertisement register
#define ADIN1200_AUTONEG_ADV_NEXT_PAGE_ADV                               0x8000
#define ADIN1200_AUTONEG_ADV_REM_FLT_ADV                                 0x2000
#define ADIN1200_AUTONEG_ADV_EXT_NEXT_PAGE_ADV                           0x1000
#define ADIN1200_AUTONEG_ADV_APAUSE_ADV                                  0x0800
#define ADIN1200_AUTONEG_ADV_PAUSE_ADV                                   0x0400
#define ADIN1200_AUTONEG_ADV_T_4_ADV                                     0x0200
#define ADIN1200_AUTONEG_ADV_FD_100_ADV                                  0x0100
#define ADIN1200_AUTONEG_ADV_HD_100_ADV                                  0x0080
#define ADIN1200_AUTONEG_ADV_FD_10_ADV                                   0x0040
#define ADIN1200_AUTONEG_ADV_HD_10_ADV                                   0x0020
#define ADIN1200_AUTONEG_ADV_SELECTOR_ADV                                0x001F
#define ADIN1200_AUTONEG_ADV_SELECTOR_ADV_DEFAULT                        0x0001

//Autonegotiation Link Partner Base Page Ability register
#define ADIN1200_LP_ABILITY_LP_NEXT_PAGE                                 0x8000
#define ADIN1200_LP_ABILITY_LP_ACK                                       0x4000
#define ADIN1200_LP_ABILITY_LP_REM_FLT                                   0x2000
#define ADIN1200_LP_ABILITY_LP_EXT_NEXT_PAGE_ABLE                        0x1000
#define ADIN1200_LP_ABILITY_LP_APAUSE_ABLE                               0x0800
#define ADIN1200_LP_ABILITY_LP_PAUSE_ABLE                                0x0400
#define ADIN1200_LP_ABILITY_LP_T_4_ABLE                                  0x0200
#define ADIN1200_LP_ABILITY_LP_FD_100_ABLE                               0x0100
#define ADIN1200_LP_ABILITY_LP_HD_100_ABLE                               0x0080
#define ADIN1200_LP_ABILITY_LP_FD_10_ABLE                                0x0040
#define ADIN1200_LP_ABILITY_LP_HD_10_ABLE                                0x0020
#define ADIN1200_LP_ABILITY_LP_SELECTOR                                  0x001F

//Autonegotiation Expansion register
#define ADIN1200_AUTONEG_EXP_RX_NP_LOC_ABLE                              0x0040
#define ADIN1200_AUTONEG_EXP_RX_NP_LOC                                   0x0020
#define ADIN1200_AUTONEG_EXP_PAR_DET_FLT                                 0x0010
#define ADIN1200_AUTONEG_EXP_LP_NP_ABLE                                  0x0008
#define ADIN1200_AUTONEG_EXP_NP_ABLE                                     0x0004
#define ADIN1200_AUTONEG_EXP_PAGE_RX_LAT                                 0x0002
#define ADIN1200_AUTONEG_EXP_LP_AUTONEG_ABLE                             0x0001

//Autonegotiation Next Page Transmit register
#define ADIN1200_TX_NEXT_PAGE_NP_NEXT_PAGE                               0x8000
#define ADIN1200_TX_NEXT_PAGE_NP_MSG_PAGE                                0x2000
#define ADIN1200_TX_NEXT_PAGE_NP_ACK_2                                   0x1000
#define ADIN1200_TX_NEXT_PAGE_NP_TOGGLE                                  0x0800
#define ADIN1200_TX_NEXT_PAGE_NP_CODE                                    0x07FF

//Autonegotiation Link Partner Received Next Page register
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_NEXT_PAGE                         0x8000
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_ACK                               0x4000
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_MSG_PAGE                          0x2000
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_ACK_2                             0x1000
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_TOGGLE                            0x0800
#define ADIN1200_LP_RX_NEXT_PAGE_LP_NP_CODE                              0x07FF

//Master Slave Status register
#define ADIN1200_MSTR_SLV_STATUS_LOC_RCVR_STATUS                         0x2000
#define ADIN1200_MSTR_SLV_STATUS_REM_RCVR_STATUS                         0x1000
#define ADIN1200_MSTR_SLV_STATUS_LP_FD_1000_ABLE                         0x0800
#define ADIN1200_MSTR_SLV_STATUS_LP_HD_1000_ABLE                         0x0400
#define ADIN1200_MSTR_SLV_STATUS_IDLE_ERR_CNT                            0x00FF

//Extended Status register
#define ADIN1200_EXT_STATUS_FD_1000_X_SPRT                               0x8000
#define ADIN1200_EXT_STATUS_HD_1000_X_SPRT                               0x4000
#define ADIN1200_EXT_STATUS_FD_1000_SPRT                                 0x2000
#define ADIN1200_EXT_STATUS_HD_1000_SPRT                                 0x1000

//PHY Control 1 register
#define ADIN1200_PHY_CTRL_1_AUTO_MDI_EN                                  0x0400
#define ADIN1200_PHY_CTRL_1_MAN_MDIX                                     0x0200
#define ADIN1200_PHY_CTRL_1_DIAG_CLK_EN                                  0x0004

//PHY Control Status 1 register
#define ADIN1200_PHY_CTRL_STATUS_1_LB_ALL_DIG_SEL                        0x1000
#define ADIN1200_PHY_CTRL_STATUS_1_LB_LD_SEL                             0x0400
#define ADIN1200_PHY_CTRL_STATUS_1_LB_REMOTE_EN                          0x0200
#define ADIN1200_PHY_CTRL_STATUS_1_ISOLATE_RX                            0x0100
#define ADIN1200_PHY_CTRL_STATUS_1_LB_EXT_EN                             0x0080
#define ADIN1200_PHY_CTRL_STATUS_1_LB_TX_SUP                             0x0040
#define ADIN1200_PHY_CTRL_STATUS_1_LB_MII_LS_OK                          0x0001

//PHY Control Status 2 register
#define ADIN1200_PHY_CTRL_STATUS_2_NRG_PD_EN                             0x0008
#define ADIN1200_PHY_CTRL_STATUS_2_NRG_PD_TX_EN                          0x0004
#define ADIN1200_PHY_CTRL_STATUS_2_PHY_IN_NRG_PD                         0x0002

//PHY Control 2 register
#define ADIN1200_PHY_CTRL_2_DN_SPEED_TO_10_EN                            0x0400
#define ADIN1200_PHY_CTRL_2_GROUP_MDIO_EN                                0x0040

//PHY Control 3 register
#define ADIN1200_PHY_CTRL_3_LINK_EN                                      0x2000
#define ADIN1200_PHY_CTRL_3_NUM_SPEED_RETRY                              0x1C00

//Interrupt Mask register
#define ADIN1200_IRQ_MASK_CBL_DIAG_IRQ_EN                                0x0400
#define ADIN1200_IRQ_MASK_MDIO_SYNC_IRQ_EN                               0x0200
#define ADIN1200_IRQ_MASK_AN_STAT_CHNG_IRQ_EN                            0x0100
#define ADIN1200_IRQ_MASK_FC_FG_IRQ_EN                                   0x0080
#define ADIN1200_IRQ_MASK_PAGE_RX_IRQ_EN                                 0x0040
#define ADIN1200_IRQ_MASK_IDLE_ERR_CNT_IRQ_EN                            0x0020
#define ADIN1200_IRQ_MASK_FIFO_OU_IRQ_EN                                 0x0010
#define ADIN1200_IRQ_MASK_RX_STAT_CHNG_IRQ_EN                            0x0008
#define ADIN1200_IRQ_MASK_LNK_STAT_CHNG_IRQ_EN                           0x0004
#define ADIN1200_IRQ_MASK_SPEED_CHNG_IRQ_EN                              0x0002
#define ADIN1200_IRQ_MASK_HW_IRQ_EN                                      0x0001

//Interrupt Status register
#define ADIN1200_IRQ_STATUS_CBL_DIAG_IRQ_STAT                            0x0400
#define ADIN1200_IRQ_STATUS_MDIO_SYNC_IRQ_STAT                           0x0200
#define ADIN1200_IRQ_STATUS_AN_STAT_CHNG_IRQ_STAT                        0x0100
#define ADIN1200_IRQ_STATUS_FC_FG_IRQ_STAT                               0x0080
#define ADIN1200_IRQ_STATUS_PAGE_RX_IRQ_STAT                             0x0040
#define ADIN1200_IRQ_STATUS_IDLE_ERR_CNT_IRQ_STAT                        0x0020
#define ADIN1200_IRQ_STATUS_FIFO_OU_IRQ_STAT                             0x0010
#define ADIN1200_IRQ_STATUS_RX_STAT_CHNG_IRQ_STAT                        0x0008
#define ADIN1200_IRQ_STATUS_LNK_STAT_CHNG_IRQ_STAT                       0x0004
#define ADIN1200_IRQ_STATUS_SPEED_CHNG_IRQ_STAT                          0x0002
#define ADIN1200_IRQ_STATUS_IRQ_PENDING                                  0x0001

//PHY Status 1 register
#define ADIN1200_PHY_STATUS_1_PHY_IN_STNDBY                              0x8000
#define ADIN1200_PHY_STATUS_1_PAR_DET_FLT_STAT                           0x2000
#define ADIN1200_PHY_STATUS_1_AUTONEG_STAT                               0x1000
#define ADIN1200_PHY_STATUS_1_PAIR_01_SWAP                               0x0800
#define ADIN1200_PHY_STATUS_1_B_10_POL_INV                               0x0400
#define ADIN1200_PHY_STATUS_1_HCD_TECH                                   0x0380
#define ADIN1200_PHY_STATUS_1_HCD_TECH_10BT_HD                           0x0000
#define ADIN1200_PHY_STATUS_1_HCD_TECH_10BT_FD                           0x0080
#define ADIN1200_PHY_STATUS_1_HCD_TECH_100BTX_HD                         0x0100
#define ADIN1200_PHY_STATUS_1_HCD_TECH_100BTX_FD                         0x0180
#define ADIN1200_PHY_STATUS_1_LINK_STAT                                  0x0040
#define ADIN1200_PHY_STATUS_1_TX_EN_STAT                                 0x0020
#define ADIN1200_PHY_STATUS_1_RX_DV_STAT                                 0x0010
#define ADIN1200_PHY_STATUS_1_COL_STAT                                   0x0008
#define ADIN1200_PHY_STATUS_1_AUTONEG_SUP                                0x0004
#define ADIN1200_PHY_STATUS_1_LP_PAUSE_ADV                               0x0002
#define ADIN1200_PHY_STATUS_1_LP_APAUSE_ADV                              0x0001

//LED Control 1 register
#define ADIN1200_LED_CTRL_1_LED_A_EXT_CFG_EN                             0x0400
#define ADIN1200_LED_CTRL_1_LED_PAT_PAUSE_DUR                            0x00F0
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_DUR_SEL                          0x000C
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_DUR_SEL_32MS                     0x0000
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_DUR_SEL_64MS                     0x0004
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_DUR_SEL_102MS                    0x0008
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_DUR_SEL_USER                     0x000C
#define ADIN1200_LED_CTRL_1_LED_OE_N                                     0x0002
#define ADIN1200_LED_CTRL_1_LED_PUL_STR_EN                               0x0001

//LED Control 2 register
#define ADIN1200_LED_CTRL_2_LED_A_CFG                                    0x001F
#define ADIN1200_LED_CTRL_2_LED_A_CFG_BLINK_100                          0x0003
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_LINK                            0x0004
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_TX                              0x0005
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_RX                              0x0006
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_ACT                             0x0007
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_FD                              0x0008
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_COL                             0x0009
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_LINK_BLINK_ACT                  0x000A
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_LINK_BLINK_RX                   0x000B
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_FD_BLINK_COL                    0x000C
#define ADIN1200_LED_CTRL_2_LED_A_CFG_BLINK                              0x000D
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON                                 0x000E
#define ADIN1200_LED_CTRL_2_LED_A_CFG_OFF                                0x000F
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_10_BLINK_100                    0x0010
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_10_BLINK_ACT                    0x0012
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_100_BLINK_ACT                   0x0013
#define ADIN1200_LED_CTRL_2_LED_A_CFG_BLINK_ACT                          0x0019
#define ADIN1200_LED_CTRL_2_LED_A_CFG_BLINK_TX                           0x001A
#define ADIN1200_LED_CTRL_2_LED_A_CFG_BLINK_10                           0x001B
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_100                             0x001C
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_100_BLINK_10                    0x001D
#define ADIN1200_LED_CTRL_2_LED_A_CFG_ON_10                              0x001E

//LED Control 3 register
#define ADIN1200_LED_CTRL_3_LED_PAT_SEL                                  0xC000
#define ADIN1200_LED_CTRL_3_LED_PAT_SEL_DEFAULT                          0x0000
#define ADIN1200_LED_CTRL_3_LED_PAT_TICK_DUR                             0x3F00
#define ADIN1200_LED_CTRL_3_LED_PAT_TICK_DUR_DEFAULT                     0x1800
#define ADIN1200_LED_CTRL_3_LED_PAT                                      0x00FF
#define ADIN1200_LED_CTRL_3_LED_PAT_DEFAULT                              0x0055

//PHY Status 2 register
#define ADIN1200_PHY_STATUS_2_PAIR_1_POL_INV                             0x0800
#define ADIN1200_PHY_STATUS_2_PAIR_0_POL_INV                             0x0400

//Energy Efficient Ethernet Capability register
#define ADIN1200_EEE_CAPABILITY_EEE_10_G_KR_SPRT                         0x0040
#define ADIN1200_EEE_CAPABILITY_EEE_10_G_KX_4_SPRT                       0x0020
#define ADIN1200_EEE_CAPABILITY_EEE_1000_KX_SPRT                         0x0010
#define ADIN1200_EEE_CAPABILITY_EEE_10_G_SPRT                            0x0008
#define ADIN1200_EEE_CAPABILITY_EEE_1000_SPRT                            0x0004
#define ADIN1200_EEE_CAPABILITY_EEE_100_SPRT                             0x0002

//Energy Efficient Ethernet Advertisement register
#define ADIN1200_EEE_ADV_EEE_10_G_KR_ADV                                 0x0040
#define ADIN1200_EEE_ADV_EEE_10_G_KX_4_ADV                               0x0020
#define ADIN1200_EEE_ADV_EEE_1000_KX_ADV                                 0x0010
#define ADIN1200_EEE_ADV_EEE_10_G_ADV                                    0x0008
#define ADIN1200_EEE_ADV_EEE_1000_ADV                                    0x0004
#define ADIN1200_EEE_ADV_EEE_100_ADV                                     0x0002

//Energy Efficient Ethernet Link Partner Ability register
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_10_G_KR_ABLE                      0x0040
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_10_G_KX_4_ABLE                    0x0020
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_1000_KX_ABLE                      0x0010
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_10_G_ABLE                         0x0008
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_1000_ABLE                         0x0004
#define ADIN1200_EEE_LP_ABILITY_LP_EEE_100_ABLE                          0x0002

//Energy Efficient Ethernet Resolved register
#define ADIN1200_EEE_RSLVD_EEE_RSLVD                                     0x0001

//Mean Square Error A register
#define ADIN1200_MSE_A_MSE_A                                             0x00FF

//Enhanced Link Detection Enable register
#define ADIN1200_FLD_EN_FLD_PCS_ERR_B_100_EN                             0x0080
#define ADIN1200_FLD_EN_FLD_SLCR_OUT_STUCK_B_100_EN                      0x0020
#define ADIN1200_FLD_EN_FLD_SLCR_IN_ZDET_B_100_EN                        0x0008
#define ADIN1200_FLD_EN_FLD_SLCR_IN_INVLD_B_100_EN                       0x0002

//Enhanced Link Detection Latched Status register
#define ADIN1200_FLD_STAT_LAT_FAST_LINK_DOWN_LAT                         0x2000

//Receive MII Clock Stop Enable register
#define ADIN1200_RX_MII_CLK_STOP_EN_RX_MII_CLK_STOP_EN                   0x0400

//Physical Coding Sublayer (PCS) Status 1 register
#define ADIN1200_PCS_STATUS_1_TX_LPI_RCVD                                0x0800
#define ADIN1200_PCS_STATUS_1_RX_LPI_RCVD                                0x0400
#define ADIN1200_PCS_STATUS_1_TX_LPI                                     0x0200
#define ADIN1200_PCS_STATUS_1_RX_LPI                                     0x0100
#define ADIN1200_PCS_STATUS_1_TX_MII_CLK_STOP_CPBL                       0x0040

//Frame Checker Enable register
#define ADIN1200_FC_EN_FC_EN                                             0x0001

//Frame Checker Interrupt Enable register
#define ADIN1200_FC_IRQ_EN_FC_IRQ_EN                                     0x0001

//Frame Checker Transmit Select register
#define ADIN1200_FC_TX_SEL_FC_TX_SEL                                     0x0001

//Frame Generator Enable register
#define ADIN1200_FG_EN_FG_EN                                             0x0001

//Frame Generator Control and Restart register
#define ADIN1200_FG_CNTRL_RSTRT_FG_RSTRT                                 0x0008
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL                                 0x0007
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_NO_FRAMES                       0x0000
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_RANDOM                          0x0001
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_ALL_ZEROS                       0x0002
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_ALL_ONES                        0x0003
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_ALT                             0x0004
#define ADIN1200_FG_CNTRL_RSTRT_FG_CNTRL_DEC                             0x0005

//Frame Generator Continuous Mode Enable register
#define ADIN1200_FG_CONT_MODE_EN_FG_CONT_MODE_EN                         0x0001

//Frame Generator Interrupt Enable register
#define ADIN1200_FG_IRQ_EN_FG_IRQ_EN                                     0x0001

//Frame Generator Interframe Gap Length register
#define ADIN1200_FG_IFG_LEN_FG_IFG_LEN                                   0x00FF

//Frame Generator Done register
#define ADIN1200_FG_DONE_FG_DONE                                         0x0001

//FIFO Sync register
#define ADIN1200_FIFO_SYNC_FIFO_SYNC                                     0x0001

//Start of Packet Control register
#define ADIN1200_SOP_CTRL_SOP_N_8_CYCM_1                                 0x0070
#define ADIN1200_SOP_CTRL_SOP_NCYC_EN                                    0x0008
#define ADIN1200_SOP_CTRL_SOP_SFD_EN                                     0x0004
#define ADIN1200_SOP_CTRL_SOP_RX_EN                                      0x0002
#define ADIN1200_SOP_CTRL_SOP_TX_EN                                      0x0001

//Start of Packet Receive Detection Delay register
#define ADIN1200_SOP_RX_DEL_SOP_RX_10_DEL_NCYC                           0xF800
#define ADIN1200_SOP_RX_DEL_SOP_RX_100_DEL_NCYC                          0x07C0

//Start of Packet Transmit Detection Delay register
#define ADIN1200_SOP_TX_DEL_SOP_TX_10_DEL_N_8_NS                         0x1F00
#define ADIN1200_SOP_TX_DEL_SOP_TX_100_DEL_N_8_NS                        0x00F0

//Control of FIFO Depth for MII Modes register
#define ADIN1200_DPTH_MII_BYTE_DPTH_MII_BYTE                             0x0001

//Base 10e Enable register
#define ADIN1200_B_10_E_EN_B_10_E_EN                                     0x0001

//10BASE-T Transmit Test Mode register
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE                       0x0007
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE_DISABLED              0x0000
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE_10MHZ_DIM_0           0x0001
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE_10MHZ_DIM_1           0x0002
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE_5MHZ_DIM_0            0x0003
#define ADIN1200_B_10_TX_TST_MODE_B_10_TX_TST_MODE_5MHZ_DIM_1            0x0004

//100BASE-TX Transmit Test Mode register
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE                     0x0007
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE_DISABLED            0x0000
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE_MLT3_16NS_DIM_0     0x0001
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE_MLT3_16NS_DIM_1     0x0002
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE_MLT3_112NS_DIM_0    0x0003
#define ADIN1200_B_100_TX_TST_MODE_B_100_TX_TST_MODE_MLT3_112NS_DIM_1    0x0004

//Run Automated Cable Diagnostics register
#define ADIN1200_CDIAG_RUN_CDIAG_RUN                                     0x0001

//Cable Diagnostics Cross Pair Fault Checking Disable register
#define ADIN1200_CDIAG_XPAIR_DIS_CDIAG_XPAIR_DIS                         0x0001

//Cable Diagnostics Results 0 register
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_BSY                     0x0400
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_XSIM_1                  0x0080
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_SIM                     0x0040
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_XSHRT_1                 0x0008
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_SHRT                    0x0004
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_OPN                     0x0002
#define ADIN1200_CDIAG_DTLD_RSLTS_0_CDIAG_RSLT_0_GD                      0x0001

//Cable Diagnostics Results 1 register
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_BSY                     0x0400
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_XSIM_0                  0x0080
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_SIM                     0x0040
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_XSHRT_0                 0x0008
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_SHRT                    0x0004
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_OPN                     0x0002
#define ADIN1200_CDIAG_DTLD_RSLTS_1_CDIAG_RSLT_1_GD                      0x0001

//Cable Diagnostics Fault Distance Pair 0 register
#define ADIN1200_CDIAG_FLT_DIST_0_CDIAG_FLT_DIST_0                       0x00FF

//Cable Diagnostics Fault Distance Pair 1 register
#define ADIN1200_CDIAG_FLT_DIST_1_CDIAG_FLT_DIST_1                       0x00FF

//Cable Diagnostics Cable Length Estimate register
#define ADIN1200_CDIAG_CBL_LEN_EST_CDIAG_CBL_LEN_EST                     0x00FF

//LED Pulse Stretching Duration register
#define ADIN1200_LED_PUL_STR_DUR_LED_PUL_STR_DUR                         0x003F

//Subsystem Software Reset register
#define ADIN1200_GE_SFT_RST_GE_SFT_RST                                   0x0001

//Subsystem Software Reset Configuration Enable register
#define ADIN1200_GE_SFT_RST_CFG_EN_GE_SFT_RST_CFG_EN                     0x0001

//Subsystem Clock Configuration register
#define ADIN1200_GE_CLK_CFG_GE_CLK_RCVR_125_EN                           0x0020
#define ADIN1200_GE_CLK_CFG_GE_CLK_FREE_125_EN                           0x0010
#define ADIN1200_GE_CLK_CFG_GE_CLK_HRT_RCVR_EN                           0x0004
#define ADIN1200_GE_CLK_CFG_GE_CLK_HRT_FREE_EN                           0x0002
#define ADIN1200_GE_CLK_CFG_GE_CLK_25_EN                                 0x0001

//Subsystem RGMII Configuration register
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_100_LOW_LTNCY_EN                  0x0400
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_10_LOW_LTNCY_EN                   0x0200
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_RX_SEL                            0x01C0
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_GTX_SEL                           0x0038
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_RX_ID_EN                          0x0004
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_TX_ID_EN                          0x0002
#define ADIN1200_GE_RGMII_CFG_GE_RGMII_EN                                0x0001

//Subsystem RMII Configuration register
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_RST                            0x0080
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH                           0x0070
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_4_BITS                    0x0000
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_8_BITS                    0x0010
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_12_BITS                   0x0020
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_16_BITS                   0x0030
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_20_BITS                   0x0040
#define ADIN1200_GE_RMII_CFG_GE_RMII_FIFO_DPTH_24_BITS                   0x0050
#define ADIN1200_GE_RMII_CFG_GE_RMII_TXD_CHK_EN                          0x0008
#define ADIN1200_GE_RMII_CFG_GE_RMII_CRS_EN                              0x0004
#define ADIN1200_GE_RMII_CFG_GE_RMII_BAD_SSD_RX_ER_EN                    0x0002
#define ADIN1200_GE_RMII_CFG_GE_RMII_EN                                  0x0001

//Subsystem PHY Base Configuration register
#define ADIN1200_GE_PHY_BASE_CFG_GE_FLD_100_EN_CFG                       0x0400
#define ADIN1200_GE_PHY_BASE_CFG_GE_PHY_SFT_PD_CFG                       0x0008

//Subsystem Link Status Invert Enable register
#define ADIN1200_GE_LNK_STAT_INV_EN_GE_LNK_STAT_INV_EN                   0x0001

//Subsystem GP_CLK Pin Override Control register
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL             0x0007
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_DEFAULT     0x0000
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_LINK_STATUS 0x0001
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_TX_SOF      0x0002
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_RX_SOF      0x0003
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_CRS         0x0004
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_COL         0x0005
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_RX_ER       0x0006
#define ADIN1200_GE_IO_GP_CLK_OR_CNTRL_GE_IO_GP_CLK_OR_CNTRL_PHY_CLK     0x0007

//Subsystem LINK_ST Pin Override Control register
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL             0x0007
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_DEFAULT     0x0000
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_LINK_STATUS 0x0001
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_TX_SOF      0x0002
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_RX_SOF      0x0003
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_CRS         0x0004
#define ADIN1200_GE_IO_GP_OUT_OR_CNTRL_GE_IO_GP_OUT_OR_CNTRL_COL         0x0005

//Subsystem INT_N Pin Override Control register
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL               0x0007
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_DEFAULT       0x0000
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_LINK_STATUS   0x0001
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_TX_SOF        0x0002
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_RX_SOF        0x0003
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_CRS           0x0004
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_COL           0x0005
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_TX_ER         0x0006
#define ADIN1200_GE_IO_INT_N_OR_CNTRL_GE_IO_INT_N_OR_CNTRL_INT_N         0x0007

//Subsystem LED_0 Pin Override Control register
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL               0x000F
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_DEFAULT       0x0000
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_LINK_STATUS   0x0001
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_TX_SOF        0x0002
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_RX_SOF        0x0003
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_CRS           0x0004
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_COL           0x0005
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_TX_ER         0x0006
#define ADIN1200_GE_IO_LED_A_OR_CNTRL_GE_IO_LED_A_OR_CNTRL_LED_0         0x0007

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ADIN1200 Ethernet PHY driver
extern const PhyDriver adin1200PhyDriver;

//ADIN1200 related functions
error_t adin1200Init(NetInterface *interface);
void adin1200InitHook(NetInterface *interface);

void adin1200Tick(NetInterface *interface);

void adin1200EnableIrq(NetInterface *interface);
void adin1200DisableIrq(NetInterface *interface);

void adin1200EventHandler(NetInterface *interface);

void adin1200WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t adin1200ReadPhyReg(NetInterface *interface, uint8_t address);

void adin1200DumpPhyReg(NetInterface *interface);

void adin1200WriteExtReg(NetInterface *interface, uint16_t address,
   uint16_t data);

uint16_t adin1200ReadExtReg(NetInterface *interface, uint16_t address);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
