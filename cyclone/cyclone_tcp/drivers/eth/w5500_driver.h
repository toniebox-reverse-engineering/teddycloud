/**
 * @file w5500_driver.h
 * @brief WIZnet W5500 Ethernet controller
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

#ifndef _W5500_DRIVER_H
#define _W5500_DRIVER_H

//Dependencies
#include "core/nic.h"

//TX buffer size
#ifndef W5500_ETH_TX_BUFFER_SIZE
   #define W5500_ETH_TX_BUFFER_SIZE 1536
#elif (W5500_ETH_TX_BUFFER_SIZE != 1536)
   #error W5500_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//RX buffer size
#ifndef W5500_ETH_RX_BUFFER_SIZE
   #define W5500_ETH_RX_BUFFER_SIZE 1536
#elif (W5500_ETH_RX_BUFFER_SIZE != 1536)
   #error W5500_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Control byte
#define W5500_CTRL_BSB                  0xF8
#define W5500_CTRL_BSB_COMMON_REG       0x00
#define W5500_CTRL_BSB_S0_REG           0x08
#define W5500_CTRL_BSB_S0_TX_BUFFER     0x10
#define W5500_CTRL_BSB_S0_RX_BUFFER     0x18
#define W5500_CTRL_BSB_S1_REG           0x28
#define W5500_CTRL_BSB_S1_TX_BUFFER     0x30
#define W5500_CTRL_BSB_S1_RX_BUFFER     0x38
#define W5500_CTRL_BSB_S2_REG           0x48
#define W5500_CTRL_BSB_S2_TX_BUFFER     0x50
#define W5500_CTRL_BSB_S2_RX_BUFFER     0x58
#define W5500_CTRL_BSB_S3_REG           0x68
#define W5500_CTRL_BSB_S3_TX_BUFFER     0x70
#define W5500_CTRL_BSB_S3_RX_BUFFER     0x78
#define W5500_CTRL_BSB_S4_REG           0x88
#define W5500_CTRL_BSB_S4_TX_BUFFER     0x90
#define W5500_CTRL_BSB_S4_RX_BUFFER     0x98
#define W5500_CTRL_BSB_S5_REG           0xA8
#define W5500_CTRL_BSB_S5_TX_BUFFER     0xB0
#define W5500_CTRL_BSB_S5_RX_BUFFER     0xB8
#define W5500_CTRL_BSB_S6_REG           0xC8
#define W5500_CTRL_BSB_S6_TX_BUFFER     0xD0
#define W5500_CTRL_BSB_S6_RX_BUFFER     0xD8
#define W5500_CTRL_BSB_S7_REG           0xE8
#define W5500_CTRL_BSB_S7_TX_BUFFER     0xF0
#define W5500_CTRL_BSB_S7_RX_BUFFER     0xF8
#define W5500_CTRL_RWB                  0x04
#define W5500_CTRL_RWB_READ             0x00
#define W5500_CTRL_RWB_WRITE            0x04
#define W5500_CTRL_OM                   0x03
#define W5500_CTRL_OM_VDM               0x00
#define W5500_CTRL_OM_FDM1              0x01
#define W5500_CTRL_OM_FDM2              0x02
#define W5500_CTRL_OM_FDM4              0x03

//Common register block
#define W5500_MR                        0x00
#define W5500_GAR0                      0x01
#define W5500_GAR1                      0x01
#define W5500_GAR2                      0x02
#define W5500_GAR3                      0x03
#define W5500_SUBR0                     0x05
#define W5500_SUBR1                     0x06
#define W5500_SUBR2                     0x07
#define W5500_SUBR3                     0x08
#define W5500_SHAR0                     0x09
#define W5500_SHAR1                     0x0A
#define W5500_SHAR2                     0x0B
#define W5500_SHAR3                     0x0C
#define W5500_SHAR4                     0x0D
#define W5500_SHAR5                     0x0E
#define W5500_SIPR0                     0x0F
#define W5500_SIPR1                     0x10
#define W5500_SIPR2                     0x11
#define W5500_SIPR3                     0x12
#define W5500_INTLEVEL0                 0x13
#define W5500_INTLEVEL1                 0x14
#define W5500_IR                        0x15
#define W5500_IMR                       0x16
#define W5500_SIR                       0x17
#define W5500_SIMR                      0x18
#define W5500_RTR0                      0x19
#define W5500_RTR1                      0x1A
#define W5500_RCR                       0x1B
#define W5500_PTIMER                    0x1C
#define W5500_PMAGIC                    0x1D
#define W5500_PHAR0                     0x1E
#define W5500_PHAR1                     0x1F
#define W5500_PHAR2                     0x20
#define W5500_PHAR3                     0x21
#define W5500_PHAR4                     0x22
#define W5500_PHAR5                     0x23
#define W5500_PSID0                     0x24
#define W5500_PSID1                     0x25
#define W5500_PMRU0                     0x26
#define W5500_PMRU1                     0x27
#define W5500_UIPR0                     0x28
#define W5500_UIPR1                     0x29
#define W5500_UIPR2                     0x2A
#define W5500_UIPR3                     0x2B
#define W5500_UPORTR0                   0x2C
#define W5500_UPORTR1                   0x2D
#define W5500_PHYCFGR                   0x2E
#define W5500_VERSIONR                  0x39

//Socket register block
#define W5500_Sn_MR                     0x00
#define W5500_Sn_CR                     0x01
#define W5500_Sn_IR                     0x02
#define W5500_Sn_SR                     0x03
#define W5500_Sn_PORT0                  0x04
#define W5500_Sn_PORT1                  0x05
#define W5500_Sn_DHAR0                  0x06
#define W5500_Sn_DHAR1                  0x07
#define W5500_Sn_DHAR2                  0x08
#define W5500_Sn_DHAR3                  0x09
#define W5500_Sn_DHAR4                  0x0A
#define W5500_Sn_DHAR5                  0x0B
#define W5500_Sn_DIPR0                  0x0C
#define W5500_Sn_DIPR1                  0x0D
#define W5500_Sn_DIPR2                  0x0E
#define W5500_Sn_DIPR3                  0x0F
#define W5500_Sn_DPORT0                 0x10
#define W5500_Sn_DPORT1                 0x11
#define W5500_Sn_MSSR0                  0x12
#define W5500_Sn_MSSR1                  0x13
#define W5500_Sn_TOS                    0x15
#define W5500_Sn_TTL                    0x16
#define W5500_Sn_RXBUF_SIZE             0x1E
#define W5500_Sn_TXBUF_SIZE             0x1F
#define W5500_Sn_TX_FSR0                0x20
#define W5500_Sn_TX_FSR1                0x21
#define W5500_Sn_TX_RD0                 0x22
#define W5500_Sn_TX_RD1                 0x23
#define W5500_Sn_TX_WR0                 0x24
#define W5500_Sn_TX_WR1                 0x25
#define W5500_Sn_RX_RSR0                0x26
#define W5500_Sn_RX_RSR1                0x27
#define W5500_Sn_RX_RD0                 0x28
#define W5500_Sn_RX_RD1                 0x29
#define W5500_Sn_RX_WR0                 0x2A
#define W5500_Sn_RX_WR1                 0x2B
#define W5500_Sn_IMR                    0x2C
#define W5500_Sn_FRAG0                  0x2D
#define W5500_Sn_FRAG1                  0x2E
#define W5500_Sn_KPALVTR                0x2F

//Mode register
#define W5500_MR_RST                    0x80
#define W5500_MR_WOL                    0x20
#define W5500_MR_PB                     0x10
#define W5500_MR_PPPOE                  0x08
#define W5500_MR_FARP                   0x02

//Interrupt register
#define W5500_IR_CONFLICT               0x80
#define W5500_IR_UNREACH                0x40
#define W5500_IR_PPPOE                  0x20
#define W5500_IR_MP                     0x10

//Interrupt Mask register
#define W5500_IMR_CONFLICT              0x80
#define W5500_IMR_UNREACH               0x40
#define W5500_IMR_PPPOE                 0x20
#define W5500_IMR_MP                    0x10

//Socket Interrupt register
#define W5500_SIR_S7_INT                0x80
#define W5500_SIR_S6_INT                0x40
#define W5500_SIR_S5_INT                0x20
#define W5500_SIR_S4_INT                0x10
#define W5500_SIR_S3_INT                0x08
#define W5500_SIR_S2_INT                0x04
#define W5500_SIR_S1_INT                0x02
#define W5500_SIR_S0_INT                0x01

//Socket Interrupt Mask register
#define W5500_SIMR_S7_IMR               0x80
#define W5500_SIMR_S6_IMR               0x40
#define W5500_SIMR_S5_IMR               0x20
#define W5500_SIMR_S4_IMR               0x10
#define W5500_SIMR_S3_IMR               0x08
#define W5500_SIMR_S2_IMR               0x04
#define W5500_SIMR_S1_IMR               0x02
#define W5500_SIMR_S0_IMR               0x01

//PHY Configuration register
#define W5500_PHYCFGR_RST               0x80
#define W5500_PHYCFGR_OPMD              0x40
#define W5500_PHYCFGR_OPMDC             0x38
#define W5500_PHYCFGR_OPMDC_10BT_HD     0x00
#define W5500_PHYCFGR_OPMDC_10BT_FD     0x08
#define W5500_PHYCFGR_OPMDC_100BT_HD    0x10
#define W5500_PHYCFGR_OPMDC_100BT_FD    0x18
#define W5500_PHYCFGR_OPMDC_100BT_HD_AN 0x20
#define W5500_PHYCFGR_OPMDC_PD          0x30
#define W5500_PHYCFGR_OPMDC_ALL_AN      0x38
#define W5500_PHYCFGR_DPX               0x04
#define W5500_PHYCFGR_SPD               0x02
#define W5500_PHYCFGR_LNK               0x01

//Chip Version register
#define W5500_VERSIONR_DEFAULT          0x04

//Socket n Mode register
#define W5500_Sn_MR_MULTI               0x80
#define W5500_Sn_MR_MFEN                0x80
#define W5500_Sn_MR_BCASTB              0x40
#define W5500_Sn_MR_ND                  0x20
#define W5500_Sn_MR_MC                  0x20
#define W5500_Sn_MR_MMB                 0x20
#define W5500_Sn_MR_UCASTB              0x10
#define W5500_Sn_MR_MIP6B               0x10
#define W5500_Sn_MR_PROTOCOL            0x0F
#define W5500_Sn_MR_PROTOCOL_CLOSED     0x00
#define W5500_Sn_MR_PROTOCOL_TCP        0x01
#define W5500_Sn_MR_PROTOCOL_UDP        0x02
#define W5500_Sn_MR_PROTOCOL_MACRAW     0x04

//Socket n Command register
#define W5500_Sn_CR_OPEN                0x01
#define W5500_Sn_CR_LISTEN              0x02
#define W5500_Sn_CR_CONNECT             0x04
#define W5500_Sn_CR_DISCON              0x08
#define W5500_Sn_CR_CLOSE               0x10
#define W5500_Sn_CR_SEND                0x20
#define W5500_Sn_CR_SEND_MAC            0x21
#define W5500_Sn_CR_SEND_KEEP           0x22
#define W5500_Sn_CR_RECV                0x40

//Socket n Interrupt register
#define W5500_Sn_IR_SEND_OK             0x10
#define W5500_Sn_IR_TIMEOUT             0x08
#define W5500_Sn_IR_RECV                0x04
#define W5500_Sn_IR_DISCON              0x02
#define W5500_Sn_IR_CON                 0x01

//Socket n Status register
#define W5500_Sn_SR_SOCK_CLOSED         0x00
#define W5500_Sn_SR_SOCK_INIT           0x13
#define W5500_Sn_SR_SOCK_LISTEN         0x14
#define W5500_Sn_SR_SOCK_SYNSENT        0x15
#define W5500_Sn_SR_SOCK_SYNRECV        0x16
#define W5500_Sn_SR_SOCK_ESTABLISHED    0x17
#define W5500_Sn_SR_SOCK_FIN_WAIT       0x18
#define W5500_Sn_SR_SOCK_CLOSING        0x1A
#define W5500_Sn_SR_SOCK_TIME_WAIT      0x1B
#define W5500_Sn_SR_SOCK_CLOSE_WAIT     0x1C
#define W5500_Sn_SR_SOCK_LAST_ACK       0x1D
#define W5500_Sn_SR_SOCK_UDP            0x22
#define W5500_Sn_SR_SOCK_MACRAW         0x42

//Socket n Receive Buffer Size register
#define W5500_Sn_RXBUF_SIZE_0KB         0x00
#define W5500_Sn_RXBUF_SIZE_1KB         0x01
#define W5500_Sn_RXBUF_SIZE_2KB         0x02
#define W5500_Sn_RXBUF_SIZE_4KB         0x04
#define W5500_Sn_RXBUF_SIZE_8KB         0x08
#define W5500_Sn_RXBUF_SIZE_16KB        0x10

//Socket n Transmit Buffer Size register
#define W5500_Sn_TXBUF_SIZE_0KB         0x00
#define W5500_Sn_TXBUF_SIZE_1KB         0x01
#define W5500_Sn_TXBUF_SIZE_2KB         0x02
#define W5500_Sn_TXBUF_SIZE_4KB         0x04
#define W5500_Sn_TXBUF_SIZE_8KB         0x08
#define W5500_Sn_TXBUF_SIZE_16KB        0x10

//Socket n Interrupt Mask register
#define W5500_Sn_IMR_SEND_OK            0x10
#define W5500_Sn_IMR_TIMEOUT            0x08
#define W5500_Sn_IMR_RECV               0x04
#define W5500_Sn_IMR_DISCON             0x02
#define W5500_Sn_IMR_CON                0x01

//Block Select Bits
#define W5500_CTRL_BSB_Sn_REG(n)        (0x08 + (n) * 0x20)
#define W5500_CTRL_BSB_Sn_TX_BUFFER(n)  (0x10 + (n) * 0x20)
#define W5500_CTRL_BSB_Sn_RX_BUFFER(n)  (0x18 + (n) * 0x20)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//W5500 driver
extern const NicDriver w5500Driver;

//W5500 related functions
error_t w5500Init(NetInterface *interface);

void w5500Tick(NetInterface *interface);

void w5500EnableIrq(NetInterface *interface);
void w5500DisableIrq(NetInterface *interface);
bool_t w5500IrqHandler(NetInterface *interface);
void w5500EventHandler(NetInterface *interface);

error_t w5500SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t w5500ReceivePacket(NetInterface *interface);

error_t w5500UpdateMacAddrFilter(NetInterface *interface);

void w5500WriteReg8(NetInterface *interface, uint8_t control,
   uint16_t address, uint8_t data);

uint8_t w5500ReadReg8(NetInterface *interface, uint8_t control,
   uint16_t address);

void w5500WriteReg16(NetInterface *interface, uint8_t control,
   uint16_t address, uint16_t data);

uint16_t w5500ReadReg16(NetInterface *interface, uint8_t control,
   uint16_t address);

void w5500WriteBuffer(NetInterface *interface, uint8_t control,
   uint16_t address, const uint8_t *data, size_t length);

void w5500ReadBuffer(NetInterface *interface, uint8_t control,
   uint16_t address, uint8_t *data, size_t length);

void w5500DumpReg(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
