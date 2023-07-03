/**
 * @file dp83826_driver.h
 * @brief DP83826 Ethernet PHY driver
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

#ifndef _DP83826_DRIVER_H
#define _DP83826_DRIVER_H

//Dependencies
#include "core/nic.h"

//PHY address
#ifndef DP83826_PHY_ADDR
   #define DP83826_PHY_ADDR 0
#elif (DP83826_PHY_ADDR < 0 || DP83826_PHY_ADDR > 31)
   #error DP83826_PHY_ADDR parameter is not valid
#endif

//DP83826 PHY registers
#define DP83826_BMCR                               0x00
#define DP83826_BMSR                               0x01
#define DP83826_PHYIDR1                            0x02
#define DP83826_PHYIDR2                            0x03
#define DP83826_ANAR                               0x04
#define DP83826_ANLPAR                             0x05
#define DP83826_ANER                               0x06
#define DP83826_ANNPTR                             0x07
#define DP83826_ANLNPTR                            0x08
#define DP83826_CR1                                0x09
#define DP83826_CR2                                0x0A
#define DP83826_CR3                                0x0B
#define DP83826_REG_12                             0x0C
#define DP83826_REGCR                              0x0D
#define DP83826_ADDAR                              0x0E
#define DP83826_FLDS                               0x0F
#define DP83826_PHYSTS                             0x10
#define DP83826_PHYSCR                             0x11
#define DP83826_MISR1                              0x12
#define DP83826_MISR2                              0x13
#define DP83826_FCSCR                              0x14
#define DP83826_RECR                               0x15
#define DP83826_BISCR                              0x16
#define DP83826_RCSR                               0x17
#define DP83826_LEDCR                              0x18
#define DP83826_PHYCR                              0x19
#define DP83826_10BTSCR                            0x1A
#define DP83826_BICSR1                             0x1B
#define DP83826_BICSR2                             0x1C
#define DP83826_CDCR                               0x1E
#define DP83826_PHYRCR                             0x1F

//DP83826 MMD registers
#define DP83826_MMD7_EEE_ADVERTISEMENT             0x07, 0x203C
#define DP83826_MLEDCR                             0x1F, 0x0025
#define DP83826_COMPT                              0x1F, 0x0027
#define DP83826_10M_CFG                            0x1F, 0x002A
#define DP83826_FLD_CFG1                           0x1F, 0x0117
#define DP83826_REG_123                            0x1F, 0x0123
#define DP83826_FLD_CFG2                           0x1F, 0x0131
#define DP83826_CDSCR                              0x1F, 0x0170
#define DP83826_CDSCR2                             0x1F, 0x0171
#define DP83826_TDR_172                            0x1F, 0x0172
#define DP83826_CDSCR3                             0x1F, 0x0173
#define DP83826_TDR_174                            0x1F, 0x0174
#define DP83826_TDR_175                            0x1F, 0x0175
#define DP83826_TDR_176                            0x1F, 0x0176
#define DP83826_CDSCR4                             0x1F, 0x0177
#define DP83826_TDR_178                            0x1F, 0x0178
#define DP83826_CDLRR1                             0x1F, 0x0180
#define DP83826_CDLRR2                             0x1F, 0x0181
#define DP83826_CDLRR3                             0x1F, 0x0182
#define DP83826_CDLRR4                             0x1F, 0x0183
#define DP83826_CDLRR5                             0x1F, 0x0184
#define DP83826_CDLAR1                             0x1F, 0x0185
#define DP83826_CDLAR2                             0x1F, 0x0186
#define DP83826_CDLAR3                             0x1F, 0x0187
#define DP83826_CDLAR4                             0x1F, 0x0188
#define DP83826_CDLAR5                             0x1F, 0x0189
#define DP83826_CDLAR6                             0x1F, 0x018A
#define DP83826_IO_CFG1                            0x1F, 0x0302
#define DP83826_LED0_GPIO_CFG                      0x1F, 0x0303
#define DP83826_LED1_GPIO_CFG                      0x1F, 0x0304
#define DP83826_LED2_GPIO_CFG                      0x1F, 0x0305
#define DP83826_LED3_GPIO_CFG                      0x1F, 0x0306
#define DP83826_CLK_OUT_LED_STATUS                 0x1F, 0x0308
#define DP83826_VOD_CFG1                           0x1F, 0x030B
#define DP83826_VOD_CFG2                           0x1F, 0x030C
#define DP83826_VOD_CFG3                           0x1F, 0x030E
#define DP83826_DSP_CFG_12                         0x1F, 0x031B
#define DP83826_DSP_CFG_16                         0x1F, 0x031F
#define DP83826_DSP_CFG_27                         0x1F, 0x033E
#define DP83826_DSP_CFG_28                         0x1F, 0x033F
#define DP83826_ANA_LD_PROG_SL                     0x1F, 0x0404
#define DP83826_ANA_RX10BT_CTRL                    0x1F, 0x040D
#define DP83826_REG_416                            0x1F, 0x0416
#define DP83826_GENCFG                             0x1F, 0x0456
#define DP83826_LEDCFG                             0x1F, 0x0460
#define DP83826_IOCTRL                             0x1F, 0x0461
#define DP83826_REG_466                            0x1F, 0x0466
#define DP83826_SOR1                               0x1F, 0x0467
#define DP83826_SOR2                               0x1F, 0x0468
#define DP83826_LEDCFG2                            0x1F, 0x0469
#define DP83826_RXFCFG1                            0x1F, 0x04A0
#define DP83826_RXFS                               0x1F, 0x04A1
#define DP83826_RXFPMD1                            0x1F, 0x04A2
#define DP83826_RXFPMD2                            0x1F, 0x04A3
#define DP83826_RXFPMD3                            0x1F, 0x04A4
#define DP83826_RXFSOP1                            0x1F, 0x04A5
#define DP83826_RXFSOP2                            0x1F, 0x04A6
#define DP83826_RXFSOP3                            0x1F, 0x04A7
#define DP83826_REG_4CF                            0x1F, 0x04CF
#define DP83826_EEECFG3                            0x1F, 0x04D1
#define DP83826_REG_4DF                            0x1F, 0x04DF
#define DP83826_REG_4E0                            0x1F, 0x04E0
#define DP83826_REG_4F3                            0x1F, 0x04F3
#define DP83826_REG_4F4                            0x1F, 0x04F4
#define DP83826_REG_4F5                            0x1F, 0x04F5

//BMCR register
#define DP83826_BMCR_RESET                         0x8000
#define DP83826_BMCR_LOOPBACK                      0x4000
#define DP83826_BMCR_SPEED_SEL                     0x2000
#define DP83826_BMCR_AN_EN                         0x1000
#define DP83826_BMCR_POWER_DOWN                    0x0800
#define DP83826_BMCR_ISOLATE                       0x0400
#define DP83826_BMCR_RESTART_AN                    0x0200
#define DP83826_BMCR_DUPLEX_MODE                   0x0100
#define DP83826_BMCR_COL_TEST                      0x0080

//BMSR register
#define DP83826_BMSR_100BT4                        0x8000
#define DP83826_BMSR_100BTX_FD                     0x4000
#define DP83826_BMSR_100BTX_HD                     0x2000
#define DP83826_BMSR_10BT_FD                       0x1000
#define DP83826_BMSR_10BT_HD                       0x0800
#define DP83826_BMSR_SMI_PREAMBLE_SUPPR            0x0040
#define DP83826_BMSR_AN_COMPLETE                   0x0020
#define DP83826_BMSR_REMOTE_FAULT                  0x0010
#define DP83826_BMSR_AN_CAPABLE                    0x0008
#define DP83826_BMSR_LINK_STATUS                   0x0004
#define DP83826_BMSR_JABBER_DETECT                 0x0002
#define DP83826_BMSR_EXTENDED_CAPABLE              0x0001

//PHYIDR1 register
#define DP83826_PHYIDR1_OUI_MSB                    0xFFFF
#define DP83826_PHYIDR1_OUI_MSB_DEFAULT            0x2000

//PHYIDR2 register
#define DP83826_PHYIDR2_OUI_LSB                    0xFC00
#define DP83826_PHYIDR2_OUI_LSB_DEFAULT            0xA000
#define DP83826_PHYIDR2_MODEL_NUMBER               0x03F0
#define DP83826_PHYIDR2_MODEL_NUMBER_DEFAULT       0x0130
#define DP83826_PHYIDR2_REV_NUMBER                 0x000F

//ANAR register
#define DP83826_ANAR_NEXT_PAGE                     0x8000
#define DP83826_ANAR_REMOTE_FAULT                  0x2000
#define DP83826_ANAR_ASYM_DIR                      0x0800
#define DP83826_ANAR_PAUSE                         0x0400
#define DP83826_ANAR_100BT4                        0x0200
#define DP83826_ANAR_100BTX_FD                     0x0100
#define DP83826_ANAR_100BTX_HD                     0x0080
#define DP83826_ANAR_10BT_FD                       0x0040
#define DP83826_ANAR_10BT_HD                       0x0020
#define DP83826_ANAR_SELECTOR                      0x001F
#define DP83826_ANAR_SELECTOR_DEFAULT              0x0001

//ANLPAR register
#define DP83826_ANLPAR_NEXT_PAGE                   0x8000
#define DP83826_ANLPAR_ACK                         0x4000
#define DP83826_ANLPAR_REMOTE_FAULT                0x2000
#define DP83826_ANLPAR_ASYM_DIR                    0x0800
#define DP83826_ANLPAR_PAUSE                       0x0400
#define DP83826_ANLPAR_100BT4                      0x0200
#define DP83826_ANLPAR_100BTX_FD                   0x0100
#define DP83826_ANLPAR_100BTX_HD                   0x0080
#define DP83826_ANLPAR_10BT_FD                     0x0040
#define DP83826_ANLPAR_10BT_HD                     0x0020
#define DP83826_ANLPAR_SELECTOR                    0x001F
#define DP83826_ANLPAR_SELECTOR_DEFAULT            0x0001

//ANER register
#define DP83826_ANER_PAR_DETECT_FAULT              0x0010
#define DP83826_ANER_LP_NEXT_PAGE_ABLE             0x0008
#define DP83826_ANER_NEXT_PAGE_ABLE                0x0004
#define DP83826_ANER_PAGE_RECEIVED                 0x0002
#define DP83826_ANER_LP_AN_ABLE                    0x0001

//ANNPTR register
#define DP83826_ANNPTR_NEXT_PAGE                   0x8000
#define DP83826_ANNPTR_MSG_PAGE                    0x2000
#define DP83826_ANNPTR_ACK2                        0x1000
#define DP83826_ANNPTR_TOGGLE                      0x0800
#define DP83826_ANNPTR_CODE                        0x07FF

//ANLNPTR register
#define DP83826_ANLNPTR_NEXT_PAGE                  0x8000
#define DP83826_ANLNPTR_ACK                        0x4000
#define DP83826_ANLNPTR_MSG_PAGE                   0x2000
#define DP83826_ANLNPTR_ACK2                       0x1000
#define DP83826_ANLNPTR_TOGGLE                     0x0800
#define DP83826_ANLNPTR_MESSAGE                    0x07FF

//CR1 register
#define DP83826_CR1_TDR_AUTO_RUN                   0x0100
#define DP83826_CR1_ROBUST_AUTO_MDIX               0x0020
#define DP83826_CR1_FAST_RX_DV_DETECT              0x0002

//CR2 register
#define DP83826_CR2_EXTENDED_FD_ABLE               0x0020
#define DP83826_CR2_RX_ER_DURING_IDLE              0x0004
#define DP83826_CR2_ODD_NIBBLE_DETECT_DIS          0x0002

//CR3 register
#define DP83826_CR3_DESCRAMBLER_FAST_LINK_DOWN     0x0400
#define DP83826_CR3_POLARITY_SWAP                  0x0040
#define DP83826_CR3_MDIX_SWAP                      0x0020
#define DP83826_CR3_FAST_LINK_DOWN_MODE            0x000F

//REGCR register
#define DP83826_REGCR_CMD                          0xC000
#define DP83826_REGCR_CMD_ADDR                     0x0000
#define DP83826_REGCR_CMD_DATA_NO_POST_INC         0x4000
#define DP83826_REGCR_CMD_DATA_POST_INC_RW         0x8000
#define DP83826_REGCR_CMD_DATA_POST_INC_W          0xC000
#define DP83826_REGCR_DEVAD                        0x001F

//FLDS register
#define DP83826_FLDS_FAST_LINK_DOWN_STATUS         0x01F0

//PHYSTS register
#define DP83826_PHYSTS_MDIX_MODE                   0x4000
#define DP83826_PHYSTS_RECEIVE_ERROR_LATCH         0x2000
#define DP83826_PHYSTS_POLARITY_STATUS             0x1000
#define DP83826_PHYSTS_FALSE_CARRIER_SENSE_LATCH   0x0800
#define DP83826_PHYSTS_SIGNAL_DETECT               0x0400
#define DP83826_PHYSTS_DESCRAMBLER_LOCK            0x0200
#define DP83826_PHYSTS_PAGE_RECEIVED               0x0100
#define DP83826_PHYSTS_MII_INTERRUPT               0x0080
#define DP83826_PHYSTS_REMOTE_FAULT                0x0040
#define DP83826_PHYSTS_JABBER_DETECT               0x0020
#define DP83826_PHYSTS_AN_STATUS                   0x0010
#define DP83826_PHYSTS_LOOPBACK_STATUS             0x0008
#define DP83826_PHYSTS_DUPLEX_STATUS               0x0004
#define DP83826_PHYSTS_SPEED_STATUS                0x0002
#define DP83826_PHYSTS_LINK_STATUS                 0x0001

//PHYSCR register
#define DP83826_PHYSCR_PLL_DIS                     0x8000
#define DP83826_PHYSCR_POWER_SAVE_MODE_EN          0x4000
#define DP83826_PHYSCR_POWER_SAVE_MODE             0x3000
#define DP83826_PHYSCR_SCRAMBLER_BYPASS            0x0800
#define DP83826_PHYSCR_LOOPBACK_FIFO_DEPTH         0x0300
#define DP83826_PHYSCR_COL_FD_EN                   0x0010
#define DP83826_PHYSCR_INT_POLARITY                0x0008
#define DP83826_PHYSCR_TEST_INT                    0x0004
#define DP83826_PHYSCR_INT_EN                      0x0002
#define DP83826_PHYSCR_INT_OE                      0x0001

//MISR1 register
#define DP83826_MISR1_LQ_INT                       0x8000
#define DP83826_MISR1_ED_INT                       0x4000
#define DP83826_MISR1_LINK_INT                     0x2000
#define DP83826_MISR1_SPD_INT                      0x1000
#define DP83826_MISR1_DUP_INT                      0x0800
#define DP83826_MISR1_ANC_INT                      0x0400
#define DP83826_MISR1_FHF_INT                      0x0200
#define DP83826_MISR1_RHF_INT                      0x0100
#define DP83826_MISR1_LQ_INT_EN                    0x0080
#define DP83826_MISR1_ED_INT_EN                    0x0040
#define DP83826_MISR1_LINK_INT_EN                  0x0020
#define DP83826_MISR1_SPD_INT_EN                   0x0010
#define DP83826_MISR1_DUP_INT_EN                   0x0008
#define DP83826_MISR1_ANC_INT_EN                   0x0004
#define DP83826_MISR1_FHF_INT_EN                   0x0002
#define DP83826_MISR1_RHF_INT_EN                   0x0001

//MISR2 register
#define DP83826_MISR2_EEE_ERROR_INT                0x8000
#define DP83826_MISR2_AN_ERROR_INT                 0x4000
#define DP83826_MISR2_PR_INT                       0x2000
#define DP83826_MISR2_FIFO_OF_UF_INT               0x1000
#define DP83826_MISR2_MDI_CHANGE_INT               0x0800
#define DP83826_MISR2_SLEEP_MODE_INT               0x0400
#define DP83826_MISR2_POL_CHANGE_INT               0x0200
#define DP83826_MISR2_JABBER_DETECT_INT            0x0100
#define DP83826_MISR2_EEE_ERROR_INT_EN             0x0080
#define DP83826_MISR2_AN_ERROR_INT_EN              0x0040
#define DP83826_MISR2_PR_INT_EN                    0x0020
#define DP83826_MISR2_FIFO_OF_UF_INT_EN            0x0010
#define DP83826_MISR2_MDI_CHANGE_INT_EN            0x0008
#define DP83826_MISR2_SLEEP_MODE_INT_EN            0x0004
#define DP83826_MISR2_POL_CHANGE_INT_EN            0x0002
#define DP83826_MISR2_JABBER_DETECT_INT_EN         0x0001

//FCSCR register
#define DP83826_FCSCR_FCSCNT                       0x00FF

//RECR register
#define DP83826_RECR_RXERCNT                       0xFFFF

//BISCR register
#define DP83826_BISCR_ERROR_COUNTER_MODE           0x4000
#define DP83826_BISCR_PRBS_CHECKER                 0x2000
#define DP83826_BISCR_PACKET_GEN_EN                0x1000
#define DP83826_BISCR_PRBS_CHECKER_LOCK_SYNC       0x0800
#define DP83826_BISCR_PRBS_CHECKER_SYNC_LOSS       0x0400
#define DP83826_BISCR_PACKET_GEN_STATUS            0x0200
#define DP83826_BISCR_POWER_MODE                   0x0100
#define DP83826_BISCR_TX_MII_LOOPBACK              0x0040
#define DP83826_BISCR_LOOPBACK_MODE                0x001F
#define DP83826_BISCR_LOOPBACK_MODE_PCS_INPUT      0x0001
#define DP83826_BISCR_LOOPBACK_MODE_PCS_OUTPUT     0x0002
#define DP83826_BISCR_LOOPBACK_MODE_DIGITAL        0x0004
#define DP83826_BISCR_LOOPBACK_MODE_ANALOG         0x0008
#define DP83826_BISCR_LOOPBACK_MODE_REVERSE        0x0010

//RCSR register
#define DP83826_RCSR_RMII_TX_CLOCK_SHIFT           0x0100
#define DP83826_RCSR_RMII_CLK_SEL                  0x0080
#define DP83826_RCSR_RMII_REV_SEL                  0x0010
#define DP83826_RCSR_RMII_OVF_STATUS               0x0008
#define DP83826_RCSR_RMII_UNF_STATUS               0x0004
#define DP83826_RCSR_RX_ELAST_BUFFER_SIZE          0x0003
#define DP83826_RCSR_RX_ELAST_BUFFER_SIZE_14_BITS  0x0000
#define DP83826_RCSR_RX_ELAST_BUFFER_SIZE_2_BITS   0x0001
#define DP83826_RCSR_RX_ELAST_BUFFER_SIZE_6_BITS   0x0002
#define DP83826_RCSR_RX_ELAST_BUFFER_SIZE_10_BITS  0x0003

//LEDCR register
#define DP83826_LEDCR_BLINK_RATE                   0x0600
#define DP83826_LEDCR_BLINK_RATE_20MHZ             0x0000
#define DP83826_LEDCR_BLINK_RATE_10MHZ             0x0200
#define DP83826_LEDCR_BLINK_RATE_5MHZ              0x0400
#define DP83826_LEDCR_BLINK_RATE_2MHZ              0x0600
#define DP83826_LEDCR_LED_LINK_POLARITY            0x0080
#define DP83826_LEDCR_DRIVE_LINK_LED               0x0010
#define DP83826_LEDCR_LINK_LED_ON_OFF              0x0002

//PHYCR register
#define DP83826_PHYCR_MDIX_EN                      0x8000
#define DP83826_PHYCR_FORCE_MDIX                   0x4000
#define DP83826_PHYCR_PAUSE_RX_STATUS              0x2000
#define DP83826_PHYCR_PAUSE_TX_STATUS              0x1000
#define DP83826_PHYCR_MII_LINK_STATUS              0x0800
#define DP83826_PHYCR_BYPASS_LED_STRETCH           0x0080
#define DP83826_PHYCR_LED_CONFIG                   0x0020
#define DP83826_PHYCR_PHY_ADDR                     0x001F

//10BTSCR register
#define DP83826_10BTSCR_RX_THRESHOLD_EN            0x2000
#define DP83826_10BTSCR_SQUELCH                    0x1E00
#define DP83826_10BTSCR_SQUELCH_200MV              0x0000
#define DP83826_10BTSCR_SQUELCH_250MV              0x0200
#define DP83826_10BTSCR_SQUELCH_300MV              0x0400
#define DP83826_10BTSCR_SQUELCH_350MV              0x0600
#define DP83826_10BTSCR_SQUELCH_400MV              0x0800
#define DP83826_10BTSCR_SQUELCH_450MV              0x0A00
#define DP83826_10BTSCR_SQUELCH_500MV              0x0C00
#define DP83826_10BTSCR_SQUELCH_550MV              0x0E00
#define DP83826_10BTSCR_SQUELCH_600MV              0x1000
#define DP83826_10BTSCR_NLP_DIS                    0x0080
#define DP83826_10BTSCR_POLARITY_STATUS            0x0010
#define DP83826_10BTSCR_JABBER_DIS                 0x0001

//BICSR1 register
#define DP83826_BICSR1_BIST_ERROR_COUNT            0xFF00
#define DP83826_BICSR1_BIST_IPG_LENGTH             0x00FF

//BICSR2 register
#define DP83826_BICSR2_BIST_PACKET_LENGTH          0x07FF

//CDCR register
#define DP83826_CDCR_CABLE_DIAG_START              0x8000
#define DP83826_CDCR_CFG_RESCAL_EN                 0x4000
#define DP83826_CDCR_CDCR_CABLE_DIAG_STATUS        0x0002
#define DP83826_CDCR_CDCR_CABLE_DIAG_TEST_FAIL     0x0001

//PHYRCR register
#define DP83826_PHYRCR_SOFT_HARD_RESET             0x8000
#define DP83826_PHYRCR_DIGITAL_RESET               0x4000

//MLEDCR register
#define DP83826_MLEDCR_MLED_POLARITY_SWAP          0x0200
#define DP83826_MLEDCR_LED0_CONFIG                 0x0078
#define DP83826_MLEDCR_LED0_CONFIG_LINK            0x0000
#define DP83826_MLEDCR_LED0_CONFIG_ACT             0x0008
#define DP83826_MLEDCR_LED0_CONFIG_TX_ACT          0x0010
#define DP83826_MLEDCR_LED0_CONFIG_RX_ACT          0x0018
#define DP83826_MLEDCR_LED0_CONFIG_COL             0x0020
#define DP83826_MLEDCR_LED0_CONFIG_SPEED_100       0x0028
#define DP83826_MLEDCR_LED0_CONFIG_SPEED_10        0x0030
#define DP83826_MLEDCR_LED0_CONFIG_FD              0x0038
#define DP83826_MLEDCR_LED0_CONFIG_LINK_ACT        0x0040
#define DP83826_MLEDCR_LED0_CONFIG_ACT_STRETCH_SIG 0x0048
#define DP83826_MLEDCR_LED0_CONFIG_MII_LINK        0x0050
#define DP83826_MLEDCR_LED0_CONFIG_LPI_MODE        0x0058
#define DP83826_MLEDCR_LED0_CONFIG_MII_ERR         0x0060
#define DP83826_MLEDCR_LED0_CONFIG_LINK_LOST       0x0068
#define DP83826_MLEDCR_LED0_CONFIG_PRBS_ERR        0x0070
#define DP83826_MLEDCR_CFG_MLED_EN                 0x0001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DP83826 Ethernet PHY driver
extern const PhyDriver dp83826PhyDriver;

//DP83826 related functions
error_t dp83826Init(NetInterface *interface);
void dp83826InitHook(NetInterface *interface);

void dp83826Tick(NetInterface *interface);

void dp83826EnableIrq(NetInterface *interface);
void dp83826DisableIrq(NetInterface *interface);

void dp83826EventHandler(NetInterface *interface);

void dp83826WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data);

uint16_t dp83826ReadPhyReg(NetInterface *interface, uint8_t address);

void dp83826DumpPhyReg(NetInterface *interface);

void dp83826WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data);

uint16_t dp83826ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
