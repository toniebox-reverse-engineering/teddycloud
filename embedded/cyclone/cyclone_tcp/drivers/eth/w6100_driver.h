/**
 * @file w6100_driver.h
 * @brief WIZnet W6100 Ethernet controller
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

#ifndef _W6100_DRIVER_H
#define _W6100_DRIVER_H

//Dependencies
#include "core/nic.h"

//TX buffer size
#ifndef W6100_ETH_TX_BUFFER_SIZE
   #define W6100_ETH_TX_BUFFER_SIZE 1536
#elif (W6100_ETH_TX_BUFFER_SIZE != 1536)
   #error W6100_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//RX buffer size
#ifndef W6100_ETH_RX_BUFFER_SIZE
   #define W6100_ETH_RX_BUFFER_SIZE 1536
#elif (W6100_ETH_RX_BUFFER_SIZE != 1536)
   #error W6100_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Control byte
#define W6100_CTRL_BSB                  0xF8
#define W6100_CTRL_BSB_COMMON_REG       0x00
#define W6100_CTRL_BSB_S0_REG           0x08
#define W6100_CTRL_BSB_S0_TX_BUFFER     0x10
#define W6100_CTRL_BSB_S0_RX_BUFFER     0x18
#define W6100_CTRL_BSB_S1_REG           0x28
#define W6100_CTRL_BSB_S1_TX_BUFFER     0x30
#define W6100_CTRL_BSB_S1_RX_BUFFER     0x38
#define W6100_CTRL_BSB_S2_REG           0x48
#define W6100_CTRL_BSB_S2_TX_BUFFER     0x50
#define W6100_CTRL_BSB_S2_RX_BUFFER     0x58
#define W6100_CTRL_BSB_S3_REG           0x68
#define W6100_CTRL_BSB_S3_TX_BUFFER     0x70
#define W6100_CTRL_BSB_S3_RX_BUFFER     0x78
#define W6100_CTRL_BSB_S4_REG           0x88
#define W6100_CTRL_BSB_S4_TX_BUFFER     0x90
#define W6100_CTRL_BSB_S4_RX_BUFFER     0x98
#define W6100_CTRL_BSB_S5_REG           0xA8
#define W6100_CTRL_BSB_S5_TX_BUFFER     0xB0
#define W6100_CTRL_BSB_S5_RX_BUFFER     0xB8
#define W6100_CTRL_BSB_S6_REG           0xC8
#define W6100_CTRL_BSB_S6_TX_BUFFER     0xD0
#define W6100_CTRL_BSB_S6_RX_BUFFER     0xD8
#define W6100_CTRL_BSB_S7_REG           0xE8
#define W6100_CTRL_BSB_S7_TX_BUFFER     0xF0
#define W6100_CTRL_BSB_S7_RX_BUFFER     0xF8
#define W6100_CTRL_RWB                  0x04
#define W6100_CTRL_RWB_READ             0x00
#define W6100_CTRL_RWB_WRITE            0x04
#define W6100_CTRL_OM                   0x03
#define W6100_CTRL_OM_VDM               0x00
#define W6100_CTRL_OM_FDM1              0x01
#define W6100_CTRL_OM_FDM2              0x02
#define W6100_CTRL_OM_FDM4              0x03

//Common register block
#define W6100_CIDR0                  0x0000
#define W6100_CIDR1                  0x0001
#define W6100_VER0                   0x0002
#define W6100_VER1                   0x0003
#define W6100_SYSR                   0x2000
#define W6100_SYCR0                  0x2004
#define W6100_SYCR1                  0x2005
#define W6100_TCNTR0                 0x2016
#define W6100_TCNTR1                 0x2017
#define W6100_TCNTCLR                0x2020
#define W6100_IR                     0x2100
#define W6100_SIR                    0x2101
#define W6100_SLIR                   0x2102
#define W6100_IMR                    0x2104
#define W6100_IRCLR                  0x2108
#define W6100_SIMR                   0x2114
#define W6100_SLIMR                  0x2124
#define W6100_SLIRCLR                0x2128
#define W6100_SLPSR                  0x212C
#define W6100_SLCR                   0x2130
#define W6100_PHYSR                  0x3000
#define W6100_PHYRAR                 0x3008
#define W6100_PHYDIR0                0x300C
#define W6100_PHYDIR1                0x300D
#define W6100_PHYDOR0                0x3010
#define W6100_PHYDOR1                0x3011
#define W6100_PHYACR                 0x3014
#define W6100_PHYDIVR                0x3018
#define W6100_PHYCR0                 0x301C
#define W6100_PHYCR1                 0x301D
#define W6100_NET4MR                 0x4000
#define W6100_NET6MR                 0x4004
#define W6100_NETMR                  0x4008
#define W6100_NETMR2                 0x4009
#define W6100_PTMR                   0x4100
#define W6100_PMNR                   0x4104
#define W6100_PHAR0                  0x4108
#define W6100_PHAR1                  0x4109
#define W6100_PHAR2                  0x410A
#define W6100_PHAR3                  0x410B
#define W6100_PHAR4                  0x410C
#define W6100_PHAR5                  0x410D
#define W6100_PSIDR0                 0x4110
#define W6100_PSIDR1                 0x4111
#define W6100_PMRUR0                 0x4114
#define W6100_PMRUR1                 0x4115
#define W6100_SHAR0                  0x4120
#define W6100_SHAR1                  0x4121
#define W6100_SHAR2                  0x4122
#define W6100_SHAR3                  0x4123
#define W6100_SHAR4                  0x4124
#define W6100_SHAR5                  0x4125
#define W6100_GAR0                   0x4130
#define W6100_GAR1                   0x4131
#define W6100_GAR2                   0x4132
#define W6100_GAR3                   0x4133
#define W6100_SUBR0                  0x4134
#define W6100_SUBR1                  0x4135
#define W6100_SUBR2                  0x4136
#define W6100_SUBR3                  0x4137
#define W6100_SIPR0                  0x4138
#define W6100_SIPR1                  0x4139
#define W6100_SIPR2                  0x413A
#define W6100_SIPR3                  0x413B
#define W6100_LLAR0                  0x4140
#define W6100_LLAR1                  0x4141
#define W6100_LLAR2                  0x4142
#define W6100_LLAR3                  0x4143
#define W6100_LLAR4                  0x4144
#define W6100_LLAR5                  0x4145
#define W6100_LLAR6                  0x4146
#define W6100_LLAR7                  0x4147
#define W6100_LLAR8                  0x4148
#define W6100_LLAR9                  0x4149
#define W6100_LLAR10                 0x414A
#define W6100_LLAR11                 0x414B
#define W6100_LLAR12                 0x414C
#define W6100_LLAR13                 0x414D
#define W6100_LLAR14                 0x414E
#define W6100_LLAR15                 0x414F
#define W6100_GUAR0                  0x4150
#define W6100_GUAR1                  0x4151
#define W6100_GUAR2                  0x4152
#define W6100_GUAR3                  0x4153
#define W6100_GUAR4                  0x4154
#define W6100_GUAR5                  0x4155
#define W6100_GUAR6                  0x4156
#define W6100_GUAR7                  0x4157
#define W6100_GUAR8                  0x4158
#define W6100_GUAR9                  0x4159
#define W6100_GUAR10                 0x415A
#define W6100_GUAR11                 0x415B
#define W6100_GUAR12                 0x415C
#define W6100_GUAR13                 0x415D
#define W6100_GUAR14                 0x415E
#define W6100_GUAR15                 0x415F
#define W6100_SUB6R0                 0x4160
#define W6100_SUB6R1                 0x4161
#define W6100_SUB6R2                 0x4162
#define W6100_SUB6R3                 0x4163
#define W6100_SUB6R4                 0x4164
#define W6100_SUB6R5                 0x4165
#define W6100_SUB6R6                 0x4166
#define W6100_SUB6R7                 0x4167
#define W6100_SUB6R8                 0x4168
#define W6100_SUB6R9                 0x4169
#define W6100_SUB6R10                0x416A
#define W6100_SUB6R11                0x416B
#define W6100_SUB6R12                0x416C
#define W6100_SUB6R13                0x416D
#define W6100_SUB6R14                0x416E
#define W6100_SUB6R15                0x416F
#define W6100_GA6R0                  0x4170
#define W6100_GA6R1                  0x4171
#define W6100_GA6R2                  0x4172
#define W6100_GA6R3                  0x4173
#define W6100_GA6R4                  0x4174
#define W6100_GA6R5                  0x4175
#define W6100_GA6R6                  0x4176
#define W6100_GA6R7                  0x4177
#define W6100_GA6R8                  0x4178
#define W6100_GA6R9                  0x4179
#define W6100_GA6R10                 0x417A
#define W6100_GA6R11                 0x417B
#define W6100_GA6R12                 0x417C
#define W6100_GA6R13                 0x417D
#define W6100_GA6R14                 0x417E
#define W6100_GA6R15                 0x417F
#define W6100_SLDIP6R0               0x4180
#define W6100_SLDIP6R1               0x4181
#define W6100_SLDIP6R2               0x4182
#define W6100_SLDIP6R3               0x4183
#define W6100_SLDIP6R4               0x4184
#define W6100_SLDIP6R5               0x4185
#define W6100_SLDIP6R6               0x4186
#define W6100_SLDIP6R7               0x4187
#define W6100_SLDIP6R8               0x4188
#define W6100_SLDIP6R9               0x4189
#define W6100_SLDIP6R10              0x418A
#define W6100_SLDIP6R11              0x418B
#define W6100_SLDIP6R12              0x418C
#define W6100_SLDIP6R13              0x418D
#define W6100_SLDIP6R14              0x418E
#define W6100_SLDIP6R15              0x418F
#define W6100_SLDHAR0                0x4190
#define W6100_SLDHAR1                0x4191
#define W6100_SLDHAR2                0x4192
#define W6100_SLDHAR3                0x4193
#define W6100_SLDHAR4                0x4194
#define W6100_SLDHAR5                0x4195
#define W6100_PINGIDR0               0x4198
#define W6100_PINGIDR1               0x4199
#define W6100_PINGSEQR0              0x419C
#define W6100_PINGSEQR1              0x419D
#define W6100_UIPR0                  0x41A0
#define W6100_UIPR1                  0x41A1
#define W6100_UIPR2                  0x41A2
#define W6100_UIPR3                  0x41A3
#define W6100_UPORTR0                0x41A4
#define W6100_UPORTR1                0x41A5
#define W6100_UIP6R0                 0x41B0
#define W6100_UIP6R1                 0x41B1
#define W6100_UIP6R2                 0x41B2
#define W6100_UIP6R3                 0x41B3
#define W6100_UIP6R4                 0x41B4
#define W6100_UIP6R5                 0x41B5
#define W6100_UIP6R6                 0x41B6
#define W6100_UIP6R7                 0x41B7
#define W6100_UIP6R8                 0x41B8
#define W6100_UIP6R9                 0x41B9
#define W6100_UIP6R10                0x41BA
#define W6100_UIP6R11                0x41BB
#define W6100_UIP6R12                0x41BC
#define W6100_UIP6R13                0x41BD
#define W6100_UIP6R14                0x41BE
#define W6100_UIP6R15                0x41BF
#define W6100_UPORT6R0               0x41C0
#define W6100_UPORT6R1               0x41C1
#define W6100_INTPTMR0               0x41C5
#define W6100_INTPTMR1               0x41C6
#define W6100_PLR                    0x41D0
#define W6100_PFR                    0x41D4
#define W6100_VLTR0                  0x41D8
#define W6100_VLTR1                  0x41D9
#define W6100_VLTR2                  0x41DA
#define W6100_VLTR3                  0x41DB
#define W6100_PLTR0                  0x41DC
#define W6100_PLTR1                  0x41DD
#define W6100_PLTR2                  0x41DE
#define W6100_PLTR3                  0x41DF
#define W6100_PAR0                   0x41E0
#define W6100_PAR1                   0x41E1
#define W6100_PAR2                   0x41E2
#define W6100_PAR3                   0x41E3
#define W6100_PAR4                   0x41E4
#define W6100_PAR5                   0x41E5
#define W6100_PAR6                   0x41E6
#define W6100_PAR7                   0x41E7
#define W6100_PAR8                   0x41E8
#define W6100_PAR9                   0x41E9
#define W6100_PAR10                  0x41EA
#define W6100_PAR11                  0x41EB
#define W6100_PAR12                  0x41EC
#define W6100_PAR13                  0x41ED
#define W6100_PAR14                  0x41EE
#define W6100_PAR15                  0x41EF
#define W6100_ICMP6BLKR              0x41F0
#define W6100_CHPLCKR                0x41F4
#define W6100_NETLCKR                0x41F5
#define W6100_PHYLCKR                0x41F6
#define W6100_RTR0                   0x4200
#define W6100_RTR1                   0x4201
#define W6100_RCR                    0x4204
#define W6100_SLRTR0                 0x4208
#define W6100_SLRTR1                 0x4209
#define W6100_SLRCR                  0x420C
#define W6100_SLHOPR                 0x420F

//Socket register block
#define W6100_Sn_MR                  0x0000
#define W6100_Sn_PSR                 0x0004
#define W6100_Sn_CR                  0x0010
#define W6100_Sn_IR                  0x0020
#define W6100_Sn_IMR                 0x0024
#define W6100_Sn_IRCLR               0x0028
#define W6100_Sn_SR                  0x0030
#define W6100_Sn_ESR                 0x0031
#define W6100_Sn_PNR                 0x0100
#define W6100_Sn_TOSR                0x0104
#define W6100_Sn_TTLR                0x0108
#define W6100_Sn_FRGR0               0x010C
#define W6100_Sn_FRGR1               0x010D
#define W6100_Sn_MSSR0               0x0110
#define W6100_Sn_MSSR1               0x0111
#define W6100_Sn_PORTR0              0x0114
#define W6100_Sn_PORTR1              0x0115
#define W6100_Sn_DHAR0               0x0118
#define W6100_Sn_DHAR1               0x0119
#define W6100_Sn_DHAR2               0x011A
#define W6100_Sn_DHAR3               0x011B
#define W6100_Sn_DHAR4               0x011C
#define W6100_Sn_DHAR5               0x011D
#define W6100_Sn_DIPR0               0x0120
#define W6100_Sn_DIPR1               0x0121
#define W6100_Sn_DIPR2               0x0122
#define W6100_Sn_DIPR3               0x0123
#define W6100_Sn_DIP6R0              0x0130
#define W6100_Sn_DIP6R1              0x0131
#define W6100_Sn_DIP6R2              0x0132
#define W6100_Sn_DIP6R3              0x0133
#define W6100_Sn_DIP6R4              0x0134
#define W6100_Sn_DIP6R5              0x0135
#define W6100_Sn_DIP6R6              0x0136
#define W6100_Sn_DIP6R7              0x0137
#define W6100_Sn_DIP6R8              0x0138
#define W6100_Sn_DIP6R9              0x0139
#define W6100_Sn_DIP6R10             0x013A
#define W6100_Sn_DIP6R11             0x013B
#define W6100_Sn_DIP6R12             0x013C
#define W6100_Sn_DIP6R13             0x013D
#define W6100_Sn_DIP6R14             0x013E
#define W6100_Sn_DIP6R15             0x013F
#define W6100_Sn_DPORTR0             0x0140
#define W6100_Sn_DPORTR1             0x0141
#define W6100_Sn_MR2                 0x0144
#define W6100_Sn_RTR0                0x0180
#define W6100_Sn_RTR1                0x0181
#define W6100_Sn_RCR                 0x0184
#define W6100_Sn_KPALVTR             0x0188
#define W6100_Sn_TX_BSR              0x0200
#define W6100_Sn_TX_FSR0             0x0204
#define W6100_Sn_TX_FSR1             0x0205
#define W6100_Sn_TX_RD0              0x0208
#define W6100_Sn_TX_RD1              0x0209
#define W6100_Sn_TX_WR0              0x020C
#define W6100_Sn_TX_WR1              0x020D
#define W6100_Sn_RX_BSR              0x0220
#define W6100_Sn_RX_RSR0             0x0224
#define W6100_Sn_RX_RSR1             0x0225
#define W6100_Sn_RX_RD0              0x0228
#define W6100_Sn_RX_RD1              0x0229
#define W6100_Sn_RX_WR0              0x022C
#define W6100_Sn_RX_WR1              0x022D

//Chip Identification 0 register
#define W6100_CIDR0_DEFAULT          0x61

//Chip Identification 1 register
#define W6100_CIDR1_DEFAULT          0x00

//Chip Version 0 register
#define W6100_VER0_DEFAULT           0x46

//Chip Version 1 register
#define W6100_VER1_DEFAULT           0x61

//System Status register
#define W6100_SYSR_CHPL              0x80
#define W6100_SYSR_NETL              0x40
#define W6100_SYSR_PHYL              0x20
#define W6100_SYSR_IND               0x02
#define W6100_SYSR_SPI               0x01

//System Config 0 register
#define W6100_SYCR0_RST              0x80

//System Config 1 register
#define W6100_SYCR1_IEN              0x80
#define W6100_SYCR1_CLKSEL           0x01

//Interrupt register
#define W6100_IR_WOL                 0x80
#define W6100_IR_UNR6                0x10
#define W6100_IR_IPCONF              0x04
#define W6100_IR_UNR4                0x02
#define W6100_IR_PTERM               0x01

//Socket Interrupt register
#define W6100_SIR_S7_INT             0x80
#define W6100_SIR_S6_INT             0x40
#define W6100_SIR_S5_INT             0x20
#define W6100_SIR_S4_INT             0x10
#define W6100_SIR_S3_INT             0x08
#define W6100_SIR_S2_INT             0x04
#define W6100_SIR_S1_INT             0x02
#define W6100_SIR_S0_INT             0x01

//Socket-less Interrupt register
#define W6100_SLIR_TOUT              0x80
#define W6100_SLIR_ARP4              0x40
#define W6100_SLIR_PING4             0x20
#define W6100_SLIR_ARP6              0x10
#define W6100_SLIR_PING6             0x08
#define W6100_SLIR_NS                0x04
#define W6100_SLIR_RS                0x02
#define W6100_SLIR_RA                0x01

//Interrupt Mask register
#define W6100_IMR_WOL                0x80
#define W6100_IMR_UNR6               0x10
#define W6100_IMR_IPCONF             0x04
#define W6100_IMR_UNR4               0x02
#define W6100_IMR_PTERM              0x01

//IR Clear register
#define W6100_IRCLR_WOL              0x80
#define W6100_IRCLR_UNR6             0x10
#define W6100_IRCLR_IPCONF           0x04
#define W6100_IRCLR_UNR4             0x02
#define W6100_IRCLR_PTERM            0x01

//Socket Interrupt Mask register
#define W6100_SIMR_S7_INT            0x80
#define W6100_SIMR_S6_INT            0x40
#define W6100_SIMR_S5_INT            0x20
#define W6100_SIMR_S4_INT            0x10
#define W6100_SIMR_S3_INT            0x08
#define W6100_SIMR_S2_INT            0x04
#define W6100_SIMR_S1_INT            0x02
#define W6100_SIMR_S0_INT            0x01

//Socket-less Interrupt Mask register
#define W6100_SLIMR_TOUT             0x80
#define W6100_SLIMR_ARP4             0x40
#define W6100_SLIMR_PING4            0x20
#define W6100_SLIMR_ARP6             0x10
#define W6100_SLIMR_PING6            0x08
#define W6100_SLIMR_NS               0x04
#define W6100_SLIMR_RS               0x02
#define W6100_SLIMR_RA               0x01

//SLIR Clear register
#define W6100_SLIRCLR_TOUT           0x80
#define W6100_SLIRCLR_ARP4           0x40
#define W6100_SLIRCLR_PING4          0x20
#define W6100_SLIRCLR_ARP6           0x10
#define W6100_SLIRCLR_PING6          0x08
#define W6100_SLIRCLR_NS             0x04
#define W6100_SLIRCLR_RS             0x02
#define W6100_SLIRCLR_RA             0x01

//Socket-less Prefer Source IPv6 Address register
#define W6100_SLPSR_AUTO             0x00
#define W6100_SLPSR_LLA              0x02
#define W6100_SLPSR_GUA              0x03

//Socket-less Command register
#define W6100_SLCR_ARP4              0x40
#define W6100_SLCR_PING4             0x20
#define W6100_SLCR_ARP6              0x10
#define W6100_SLCR_PING6             0x08
#define W6100_SLCR_NS                0x04
#define W6100_SLCR_RS                0x02
#define W6100_SLCR_NA                0x01

//PHY Status register
#define W6100_PHYSR_CAB              0x80
#define W6100_PHYSR_MODE             0x38
#define W6100_PHYSR_MODE_AN          0x00
#define W6100_PHYSR_MODE_100BTX_FD   0x20
#define W6100_PHYSR_MODE_100BTX_HD   0x28
#define W6100_PHYSR_MODE_10BT_FD     0x30
#define W6100_PHYSR_MODE_10BT_HD     0x38
#define W6100_PHYSR_DPX              0x04
#define W6100_PHYSR_SPD              0x02
#define W6100_PHYSR_LNK              0x01

//PHY Register Address register
#define W6100_PHYRAR_ADDR            0x1F

//PHY Division register
#define W6100_PHYDIVR_DIV32          0x00
#define W6100_PHYDIVR_DIV64          0x01
#define W6100_PHYDIVR_DIV128         0x02

//PHY Control 0 register
#define W6100_PHYCR0_MODE            0x07
#define W6100_PHYCR0_MODE_AN         0x00
#define W6100_PHYCR0_MODE_100BTX_FD  0x04
#define W6100_PHYCR0_MODE_100BTX_HD  0x05
#define W6100_PHYCR0_MODE_10BT_FD    0x06
#define W6100_PHYCR0_MODE_10BT_HD    0x07

//PHY Control 1 register
#define W6100_PHYCR1_PWDN            0x20
#define W6100_PHYCR1_TE              0x08
#define W6100_PHYCR1_RST             0x01

//Network IPv4 Mode register
#define W6100_NET4MR_UNRB            0x08
#define W6100_NET4MR_PARP            0x04
#define W6100_NET4MR_RSTB            0x02
#define W6100_NET4MR_PB              0x01

//Network IPv6 Mode register
#define W6100_NET6MR_UNRB            0x08
#define W6100_NET6MR_PARP            0x04
#define W6100_NET6MR_RSTB            0x02
#define W6100_NET6MR_PB              0x01

//Network Mode register
#define W6100_NETMR_ANB              0x20
#define W6100_NETMR_M6B              0x10
#define W6100_NETMR_WOL              0x04
#define W6100_NETMR_IP6B             0x02
#define W6100_NETMR_IP4B             0x01

//Network Mode 2 register
#define W6100_NETMR2_DHAS            0x80
#define W6100_NETMR2_PPPOE           0x01

//ICMPv6 Block register
#define W6100_ICMP6BLKR_PING6        0x10
#define W6100_ICMP6BLKR_MLD          0x08
#define W6100_ICMP6BLKR_RA           0x04
#define W6100_ICMP6BLKR_NA           0x02
#define W6100_ICMP6BLKR_NS           0x01

//Chip Lock register
#define W6100_CHPLCKR_LOCK           0x00
#define W6100_CHPLCKR_UNLOCK         0xCE

//Network Lock register
#define W6100_NETLCKR_UNLOCK         0x3A
#define W6100_NETLCKR_LOCK           0xC5

//PHY Lock register
#define W6100_PHYLCKR_LOCK           0x00
#define W6100_PHYLCKR_UNLOCK         0x53

//Socket n Mode register
#define W6100_Sn_MR_MULTI            0x80
#define W6100_Sn_MR_MF               0x80
#define W6100_Sn_MR_BRDB             0x40
#define W6100_Sn_MR_FPSH             0x40
#define W6100_Sn_MR_ND               0x20
#define W6100_Sn_MR_MC               0x20
#define W6100_Sn_MR_SMB              0x20
#define W6100_Sn_MR_MMB              0x20
#define W6100_Sn_MR_UNIB             0x10
#define W6100_Sn_MR_MMB6             0x10
#define W6100_Sn_MR_PROTOCOL         0x0F
#define W6100_Sn_MR_PROTOCOL_CLOSED  0x00
#define W6100_Sn_MR_PROTOCOL_TCP4    0x01
#define W6100_Sn_MR_PROTOCOL_UDP4    0x02
#define W6100_Sn_MR_PROTOCOL_IPRAW4  0x03
#define W6100_Sn_MR_PROTOCOL_MACRAW  0x07
#define W6100_Sn_MR_PROTOCOL_TCP6    0x09
#define W6100_Sn_MR_PROTOCOL_UDP6    0x0A
#define W6100_Sn_MR_PROTOCOL_IPRAW6  0x0B
#define W6100_Sn_MR_PROTOCOL_TCPD    0x0D
#define W6100_Sn_MR_PROTOCOL_UDPD    0x0F

//Socket n Prefer Source IPv6 Address register
#define W6100_Sn_PSR_AUTO            0x00
#define W6100_Sn_PSR_LLA             0x02
#define W6100_Sn_PSR_GUA             0x03

//Socket n Command register
#define W6100_Sn_CR_OPEN             0x01
#define W6100_Sn_CR_LISTEN           0x02
#define W6100_Sn_CR_CONNECT          0x04
#define W6100_Sn_CR_DISCON           0x08
#define W6100_Sn_CR_CLOSE            0x10
#define W6100_Sn_CR_SEND             0x20
#define W6100_Sn_CR_SEND_KEEP        0x22
#define W6100_Sn_CR_RECV             0x40
#define W6100_Sn_CR_CONNECT6         0x84
#define W6100_Sn_CR_SEND6            0xA6

//Socket n Interrupt register
#define W6100_Sn_IR_SENDOK           0x10
#define W6100_Sn_IR_TIMEOUT          0x08
#define W6100_Sn_IR_RECV             0x04
#define W6100_Sn_IR_DISCON           0x02
#define W6100_Sn_IR_CON              0x01

//Socket n Interrupt Mask register
#define W6100_Sn_IMR_SENDOK          0x10
#define W6100_Sn_IMR_TIMEOUT         0x08
#define W6100_Sn_IMR_RECV            0x04
#define W6100_Sn_IMR_DISCON          0x02
#define W6100_Sn_IMR_CON             0x01

//Sn_IR Clear register
#define W6100_Sn_IRCLR_SENDOK        0x10
#define W6100_Sn_IRCLR_TIMEOUT       0x08
#define W6100_Sn_IRCLR_RECV          0x04
#define W6100_Sn_IRCLR_DISCON        0x02
#define W6100_Sn_IRCLR_CON           0x01

//Socket n Status register
#define W6100_Sn_SR_SOCK_CLOSED      0x00
#define W6100_Sn_SR_SOCK_INIT        0x13
#define W6100_Sn_SR_SOCK_LISTEN      0x14
#define W6100_Sn_SR_SOCK_SYNSENT     0x15
#define W6100_Sn_SR_SOCK_SYNRECV     0x16
#define W6100_Sn_SR_SOCK_ESTABLISHED 0x17
#define W6100_Sn_SR_SOCK_FIN_WAIT    0x18
#define W6100_Sn_SR_SOCK_TIME_WAIT   0x1B
#define W6100_Sn_SR_SOCK_CLOSE_WAIT  0x1C
#define W6100_Sn_SR_SOCK_LAST_ACK    0x1D
#define W6100_Sn_SR_SOCK_UDP         0x22
#define W6100_Sn_SR_SOCK_IPRAW       0x32
#define W6100_Sn_SR_SOCK_IPRAW6      0x33
#define W6100_Sn_SR_SOCK_MACRAW      0x42

//Socket n Extension Status register
#define W6100_Sn_ESR_TCPM            0x04
#define W6100_Sn_ESR_TCPM_TCP4       0x00
#define W6100_Sn_ESR_TCPM_TCP6       0x04
#define W6100_Sn_ESR_TCPOP           0x02
#define W6100_Sn_ESR_TCPOP_CLIENT    0x00
#define W6100_Sn_ESR_TCPOP_SERVER    0x02
#define W6100_Sn_ESR_IP6T            0x01
#define W6100_Sn_ESR_IP6T_LLA        0x00
#define W6100_Sn_ESR_IP6T_GUA        0x01

//Socket n Mode 2 register
#define W6100_Sn_MR2_DHAM            0x02
#define W6100_Sn_MR2_FARP            0x01

//Socket n TX Buffer Size register
#define W6100_Sn_TX_BSR_0KB          0x00
#define W6100_Sn_TX_BSR_1KB          0x01
#define W6100_Sn_TX_BSR_2KB          0x02
#define W6100_Sn_TX_BSR_4KB          0x04
#define W6100_Sn_TX_BSR_8KB          0x08
#define W6100_Sn_TX_BSR_16KB         0x10

//Socket n RX Buffer Size register
#define W6100_Sn_RX_BSR_0KB          0x00
#define W6100_Sn_RX_BSR_1KB          0x01
#define W6100_Sn_RX_BSR_2KB          0x02
#define W6100_Sn_RX_BSR_4KB          0x04
#define W6100_Sn_RX_BSR_8KB          0x08
#define W6100_Sn_RX_BSR_16KB         0x10

//Block Select Bits
#define W6100_CTRL_BSB_Sn_REG(n)        (0x08 + (n) * 0x20)
#define W6100_CTRL_BSB_Sn_TX_BUFFER(n)  (0x10 + (n) * 0x20)
#define W6100_CTRL_BSB_Sn_RX_BUFFER(n)  (0x18 + (n) * 0x20)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//W6100 driver
extern const NicDriver w6100Driver;

//W6100 related functions
error_t w6100Init(NetInterface *interface);

void w6100Tick(NetInterface *interface);

void w6100EnableIrq(NetInterface *interface);
void w6100DisableIrq(NetInterface *interface);
bool_t w6100IrqHandler(NetInterface *interface);
void w6100EventHandler(NetInterface *interface);

error_t w6100SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t w6100ReceivePacket(NetInterface *interface);

error_t w6100UpdateMacAddrFilter(NetInterface *interface);

void w6100WriteReg8(NetInterface *interface, uint8_t control,
   uint16_t address, uint8_t data);

uint8_t w6100ReadReg8(NetInterface *interface, uint8_t control,
   uint16_t address);

void w6100WriteReg16(NetInterface *interface, uint8_t control,
   uint16_t address, uint16_t data);

uint16_t w6100ReadReg16(NetInterface *interface, uint8_t control,
   uint16_t address);

void w6100WriteBuffer(NetInterface *interface, uint8_t control,
   uint16_t address, const uint8_t *data, size_t length);

void w6100ReadBuffer(NetInterface *interface, uint8_t control,
   uint16_t address, uint8_t *data, size_t length);

void w6100DumpReg(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
