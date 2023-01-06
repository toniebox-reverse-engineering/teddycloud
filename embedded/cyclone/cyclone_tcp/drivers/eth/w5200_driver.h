/**
 * @file w5200_driver.h
 * @brief WIZnet W5200 Ethernet controller
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

#ifndef _W5200_DRIVER_H
#define _W5200_DRIVER_H

//Dependencies
#include "core/nic.h"

//TX buffer size
#ifndef W5200_ETH_TX_BUFFER_SIZE
   #define W5200_ETH_TX_BUFFER_SIZE 1536
#elif (W5200_ETH_TX_BUFFER_SIZE != 1536)
   #error W5200_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//RX buffer size
#ifndef W5200_ETH_RX_BUFFER_SIZE
   #define W5200_ETH_RX_BUFFER_SIZE 1536
#elif (W5200_ETH_RX_BUFFER_SIZE != 1536)
   #error W5200_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Opcodes
#define W5200_OP_READ                0x00
#define W5200_OP_WRITE               0x80

//W5200 Common registers
#define W5200_MR                     0x00
#define W5200_GAR0                   0x01
#define W5200_GAR1                   0x02
#define W5200_GAR2                   0x03
#define W5200_GAR3                   0x04
#define W5200_SUBR0                  0x05
#define W5200_SUBR1                  0x06
#define W5200_SUBR2                  0x07
#define W5200_SUBR3                  0x08
#define W5200_SHAR0                  0x09
#define W5200_SHAR1                  0x0A
#define W5200_SHAR2                  0x0B
#define W5200_SHAR3                  0x0C
#define W5200_SHAR4                  0x0D
#define W5200_SHAR5                  0x0E
#define W5200_SIPR0                  0x0F
#define W5200_SIPR1                  0x10
#define W5200_SIPR2                  0x11
#define W5200_SIPR3                  0x12
#define W5200_IR                     0x15
#define W5200_IMR                    0x16
#define W5200_RTR0                   0x17
#define W5200_RTR1                   0x18
#define W5200_RCR                    0x19
#define W5200_PATR0                  0x1C
#define W5200_PATR1                  0x1D
#define W5200_PPPALGO                0x1E
#define W5200_VERSIONR               0x1F
#define W5200_PTIMER                 0x28
#define W5200_PMAGIC                 0x29
#define W5200_INTLEVEL0              0x30
#define W5200_INTLEVEL1              0x31
#define W5200_IR2                    0x34
#define W5200_PSTATUS                0x35
#define W5200_IMR2                   0x36

//W5200 Socket registers
#define W5200_S0_MR                  0x4000
#define W5200_S0_CR                  0x4001
#define W5200_S0_IR                  0x4002
#define W5200_S0_SR                  0x4003
#define W5200_S0_PORT0               0x4004
#define W5200_S0_PORT1               0x4005
#define W5200_S0_DHAR0               0x4006
#define W5200_S0_DHAR1               0x4007
#define W5200_S0_DHAR2               0x4008
#define W5200_S0_DHAR3               0x4009
#define W5200_S0_DHAR4               0x400A
#define W5200_S0_DHAR5               0x400B
#define W5200_S0_DIPR0               0x400C
#define W5200_S0_DIPR1               0x400D
#define W5200_S0_DIPR2               0x400E
#define W5200_S0_DIPR3               0x400F
#define W5200_S0_DPORT0              0x4010
#define W5200_S0_DPORT1              0x4011
#define W5200_S0_MSSR0               0x4012
#define W5200_S0_MSSR1               0x4013
#define W5200_S0_PROTO               0x4014
#define W5200_S0_TOS                 0x4015
#define W5200_S0_TTL                 0x4016
#define W5200_S0_RXMEM_SIZE          0x401E
#define W5200_S0_TXMEM_SIZE          0x401F
#define W5200_S0_TX_FSR0             0x4020
#define W5200_S0_TX_FSR1             0x4021
#define W5200_S0_TX_RD0              0x4022
#define W5200_S0_TX_RD1              0x4023
#define W5200_S0_TX_WR0              0x4024
#define W5200_S0_TX_WR1              0x4025
#define W5200_S0_RX_RSR0             0x4026
#define W5200_S0_RX_RSR1             0x4027
#define W5200_S0_RX_RD0              0x4028
#define W5200_S0_RX_RD1              0x4029
#define W5200_S0_RX_WR0              0x402A
#define W5200_S0_RX_WR1              0x402B
#define W5200_S0_IMR                 0x402C
#define W5200_S0_FRAG0               0x402D
#define W5200_S0_FRAG1               0x402E
#define W5200_S1_MR                  0x4100
#define W5200_S1_CR                  0x4101
#define W5200_S1_IR                  0x4102
#define W5200_S1_SR                  0x4103
#define W5200_S1_PORT0               0x4104
#define W5200_S1_PORT1               0x4105
#define W5200_S1_DHAR0               0x4106
#define W5200_S1_DHAR1               0x4107
#define W5200_S1_DHAR2               0x4108
#define W5200_S1_DHAR3               0x4109
#define W5200_S1_DHAR4               0x410A
#define W5200_S1_DHAR5               0x410B
#define W5200_S1_DIPR0               0x410C
#define W5200_S1_DIPR1               0x410D
#define W5200_S1_DIPR2               0x410E
#define W5200_S1_DIPR3               0x410F
#define W5200_S1_DPORT0              0x4110
#define W5200_S1_DPORT1              0x4111
#define W5200_S1_MSSR0               0x4112
#define W5200_S1_MSSR1               0x4113
#define W5200_S1_PROTO               0x4114
#define W5200_S1_TOS                 0x4115
#define W5200_S1_TTL                 0x4116
#define W5200_S1_RXMEM_SIZE          0x411E
#define W5200_S1_TXMEM_SIZE          0x411F
#define W5200_S1_TX_FSR0             0x4120
#define W5200_S1_TX_FSR1             0x4121
#define W5200_S1_TX_RD0              0x4122
#define W5200_S1_TX_RD1              0x4123
#define W5200_S1_TX_WR0              0x4124
#define W5200_S1_TX_WR1              0x4125
#define W5200_S1_RX_RSR0             0x4126
#define W5200_S1_RX_RSR1             0x4127
#define W5200_S1_RX_RD0              0x4128
#define W5200_S1_RX_RD1              0x4129
#define W5200_S1_RX_WR0              0x412A
#define W5200_S1_RX_WR1              0x412B
#define W5200_S1_IMR                 0x412C
#define W5200_S1_FRAG0               0x412D
#define W5200_S1_FRAG1               0x412E
#define W5200_S2_MR                  0x4200
#define W5200_S2_CR                  0x4201
#define W5200_S2_IR                  0x4202
#define W5200_S2_SR                  0x4203
#define W5200_S2_PORT0               0x4204
#define W5200_S2_PORT1               0x4205
#define W5200_S2_DHAR0               0x4206
#define W5200_S2_DHAR1               0x4207
#define W5200_S2_DHAR2               0x4208
#define W5200_S2_DHAR3               0x4209
#define W5200_S2_DHAR4               0x420A
#define W5200_S2_DHAR5               0x420B
#define W5200_S2_DIPR0               0x420C
#define W5200_S2_DIPR1               0x420D
#define W5200_S2_DIPR2               0x420E
#define W5200_S2_DIPR3               0x420F
#define W5200_S2_DPORT0              0x4210
#define W5200_S2_DPORT1              0x4211
#define W5200_S2_MSSR0               0x4212
#define W5200_S2_MSSR1               0x4213
#define W5200_S2_PROTO               0x4214
#define W5200_S2_TOS                 0x4215
#define W5200_S2_TTL                 0x4216
#define W5200_S2_RXMEM_SIZE          0x421E
#define W5200_S2_TXMEM_SIZE          0x421F
#define W5200_S2_TX_FSR0             0x4220
#define W5200_S2_TX_FSR1             0x4221
#define W5200_S2_TX_RD0              0x4222
#define W5200_S2_TX_RD1              0x4223
#define W5200_S2_TX_WR0              0x4224
#define W5200_S2_TX_WR1              0x4225
#define W5200_S2_RX_RSR0             0x4226
#define W5200_S2_RX_RSR1             0x4227
#define W5200_S2_RX_RD0              0x4228
#define W5200_S2_RX_RD1              0x4229
#define W5200_S2_RX_WR0              0x422A
#define W5200_S2_RX_WR1              0x422B
#define W5200_S2_IMR                 0x422C
#define W5200_S2_FRAG0               0x422D
#define W5200_S2_FRAG1               0x422E
#define W5200_S3_MR                  0x4300
#define W5200_S3_CR                  0x4301
#define W5200_S3_IR                  0x4302
#define W5200_S3_SR                  0x4303
#define W5200_S3_PORT0               0x4304
#define W5200_S3_PORT1               0x4305
#define W5200_S3_DHAR0               0x4306
#define W5200_S3_DHAR1               0x4307
#define W5200_S3_DHAR2               0x4308
#define W5200_S3_DHAR3               0x4309
#define W5200_S3_DHAR4               0x430A
#define W5200_S3_DHAR5               0x430B
#define W5200_S3_DIPR0               0x430C
#define W5200_S3_DIPR1               0x430D
#define W5200_S3_DIPR2               0x430E
#define W5200_S3_DIPR3               0x430F
#define W5200_S3_DPORT0              0x4310
#define W5200_S3_DPORT1              0x4311
#define W5200_S3_MSSR0               0x4312
#define W5200_S3_MSSR1               0x4313
#define W5200_S3_PROTO               0x4314
#define W5200_S3_TOS                 0x4315
#define W5200_S3_TTL                 0x4316
#define W5200_S3_RXMEM_SIZE          0x431E
#define W5200_S3_TXMEM_SIZE          0x431F
#define W5200_S3_TX_FSR0             0x4320
#define W5200_S3_TX_FSR1             0x4321
#define W5200_S3_TX_RD0              0x4322
#define W5200_S3_TX_RD1              0x4323
#define W5200_S3_TX_WR0              0x4324
#define W5200_S3_TX_WR1              0x4325
#define W5200_S3_RX_RSR0             0x4326
#define W5200_S3_RX_RSR1             0x4327
#define W5200_S3_RX_RD0              0x4328
#define W5200_S3_RX_RD1              0x4329
#define W5200_S3_RX_WR0              0x432A
#define W5200_S3_RX_WR1              0x432B
#define W5200_S3_IMR                 0x432C
#define W5200_S3_FRAG0               0x432D
#define W5200_S3_FRAG1               0x432E
#define W5200_S4_MR                  0x4400
#define W5200_S4_CR                  0x4401
#define W5200_S4_IR                  0x4402
#define W5200_S4_SR                  0x4403
#define W5200_S4_PORT0               0x4404
#define W5200_S4_PORT1               0x4405
#define W5200_S4_DHAR0               0x4406
#define W5200_S4_DHAR1               0x4407
#define W5200_S4_DHAR2               0x4408
#define W5200_S4_DHAR3               0x4409
#define W5200_S4_DHAR4               0x440A
#define W5200_S4_DHAR5               0x440B
#define W5200_S4_DIPR0               0x440C
#define W5200_S4_DIPR1               0x440D
#define W5200_S4_DIPR2               0x440E
#define W5200_S4_DIPR3               0x440F
#define W5200_S4_DPORT0              0x4410
#define W5200_S4_DPORT1              0x4411
#define W5200_S4_MSSR0               0x4412
#define W5200_S4_MSSR1               0x4413
#define W5200_S4_PROTO               0x4414
#define W5200_S4_TOS                 0x4415
#define W5200_S4_TTL                 0x4416
#define W5200_S4_RXMEM_SIZE          0x441E
#define W5200_S4_TXMEM_SIZE          0x441F
#define W5200_S4_TX_FSR0             0x4420
#define W5200_S4_TX_FSR1             0x4421
#define W5200_S4_TX_RD0              0x4422
#define W5200_S4_TX_RD1              0x4423
#define W5200_S4_TX_WR0              0x4424
#define W5200_S4_TX_WR1              0x4425
#define W5200_S4_RX_RSR0             0x4426
#define W5200_S4_RX_RSR1             0x4427
#define W5200_S4_RX_RD0              0x4428
#define W5200_S4_RX_RD1              0x4429
#define W5200_S4_RX_WR0              0x442A
#define W5200_S4_RX_WR1              0x442B
#define W5200_S4_IMR                 0x442C
#define W5200_S4_FRAG0               0x442D
#define W5200_S4_FRAG1               0x442E
#define W5200_S5_MR                  0x4500
#define W5200_S5_CR                  0x4501
#define W5200_S5_IR                  0x4502
#define W5200_S5_SR                  0x4503
#define W5200_S5_PORT0               0x4504
#define W5200_S5_PORT1               0x4505
#define W5200_S5_DHAR0               0x4506
#define W5200_S5_DHAR1               0x4507
#define W5200_S5_DHAR2               0x4508
#define W5200_S5_DHAR3               0x4509
#define W5200_S5_DHAR4               0x450A
#define W5200_S5_DHAR5               0x450B
#define W5200_S5_DIPR0               0x450C
#define W5200_S5_DIPR1               0x450D
#define W5200_S5_DIPR2               0x450E
#define W5200_S5_DIPR3               0x450F
#define W5200_S5_DPORT0              0x4510
#define W5200_S5_DPORT1              0x4511
#define W5200_S5_MSSR0               0x4512
#define W5200_S5_MSSR1               0x4513
#define W5200_S5_PROTO               0x4514
#define W5200_S5_TOS                 0x4515
#define W5200_S5_TTL                 0x4516
#define W5200_S5_RXMEM_SIZE          0x451E
#define W5200_S5_TXMEM_SIZE          0x451F
#define W5200_S5_TX_FSR0             0x4520
#define W5200_S5_TX_FSR1             0x4521
#define W5200_S5_TX_RD0              0x4522
#define W5200_S5_TX_RD1              0x4523
#define W5200_S5_TX_WR0              0x4524
#define W5200_S5_TX_WR1              0x4525
#define W5200_S5_RX_RSR0             0x4526
#define W5200_S5_RX_RSR1             0x4527
#define W5200_S5_RX_RD0              0x4528
#define W5200_S5_RX_RD1              0x4529
#define W5200_S5_RX_WR0              0x452A
#define W5200_S5_RX_WR1              0x452B
#define W5200_S5_IMR                 0x452C
#define W5200_S5_FRAG0               0x452D
#define W5200_S5_FRAG1               0x452E
#define W5200_S6_MR                  0x4600
#define W5200_S6_CR                  0x4601
#define W5200_S6_IR                  0x4602
#define W5200_S6_SR                  0x4603
#define W5200_S6_PORT0               0x4604
#define W5200_S6_PORT1               0x4605
#define W5200_S6_DHAR0               0x4606
#define W5200_S6_DHAR1               0x4607
#define W5200_S6_DHAR2               0x4608
#define W5200_S6_DHAR3               0x4609
#define W5200_S6_DHAR4               0x460A
#define W5200_S6_DHAR5               0x460B
#define W5200_S6_DIPR0               0x460C
#define W5200_S6_DIPR1               0x460D
#define W5200_S6_DIPR2               0x460E
#define W5200_S6_DIPR3               0x460F
#define W5200_S6_DPORT0              0x4610
#define W5200_S6_DPORT1              0x4611
#define W5200_S6_MSSR0               0x4612
#define W5200_S6_MSSR1               0x4613
#define W5200_S6_PROTO               0x4614
#define W5200_S6_TOS                 0x4615
#define W5200_S6_TTL                 0x4616
#define W5200_S6_RXMEM_SIZE          0x461E
#define W5200_S6_TXMEM_SIZE          0x461F
#define W5200_S6_TX_FSR0             0x4620
#define W5200_S6_TX_FSR1             0x4621
#define W5200_S6_TX_RD0              0x4622
#define W5200_S6_TX_RD1              0x4623
#define W5200_S6_TX_WR0              0x4624
#define W5200_S6_TX_WR1              0x4625
#define W5200_S6_RX_RSR0             0x4626
#define W5200_S6_RX_RSR1             0x4627
#define W5200_S6_RX_RD0              0x4628
#define W5200_S6_RX_RD1              0x4629
#define W5200_S6_RX_WR0              0x462A
#define W5200_S6_RX_WR1              0x462B
#define W5200_S6_IMR                 0x462C
#define W5200_S6_FRAG0               0x462D
#define W5200_S6_FRAG1               0x462E
#define W5200_S7_MR                  0x4700
#define W5200_S7_CR                  0x4701
#define W5200_S7_IR                  0x4702
#define W5200_S7_SR                  0x4703
#define W5200_S7_PORT0               0x4704
#define W5200_S7_PORT1               0x4705
#define W5200_S7_DHAR0               0x4706
#define W5200_S7_DHAR1               0x4707
#define W5200_S7_DHAR2               0x4708
#define W5200_S7_DHAR3               0x4709
#define W5200_S7_DHAR4               0x470A
#define W5200_S7_DHAR5               0x470B
#define W5200_S7_DIPR0               0x470C
#define W5200_S7_DIPR1               0x470D
#define W5200_S7_DIPR2               0x470E
#define W5200_S7_DIPR3               0x470F
#define W5200_S7_DPORT0              0x4710
#define W5200_S7_DPORT1              0x4711
#define W5200_S7_MSSR0               0x4712
#define W5200_S7_MSSR1               0x4713
#define W5200_S7_PROTO               0x4714
#define W5200_S7_TOS                 0x4715
#define W5200_S7_TTL                 0x4716
#define W5200_S7_RXMEM_SIZE          0x471E
#define W5200_S7_TXMEM_SIZE          0x471F
#define W5200_S7_TX_FSR0             0x4720
#define W5200_S7_TX_FSR1             0x4721
#define W5200_S7_TX_RD0              0x4722
#define W5200_S7_TX_RD1              0x4723
#define W5200_S7_TX_WR0              0x4724
#define W5200_S7_TX_WR1              0x4725
#define W5200_S7_RX_RSR0             0x4726
#define W5200_S7_RX_RSR1             0x4727
#define W5200_S7_RX_RD0              0x4728
#define W5200_S7_RX_RD1              0x4729
#define W5200_S7_RX_WR0              0x472A
#define W5200_S7_RX_WR1              0x472B
#define W5200_S7_IMR                 0x472C
#define W5200_S7_FRAG0               0x472D
#define W5200_S7_FRAG1               0x472E

//W5200 Socket register access macros
#define W5200_Sn_MR(n)               (0x4000 + ((n) * 0x0100))
#define W5200_Sn_CR(n)               (0x4001 + ((n) * 0x0100))
#define W5200_Sn_IR(n)               (0x4002 + ((n) * 0x0100))
#define W5200_Sn_SR(n)               (0x4003 + ((n) * 0x0100))
#define W5200_Sn_PORT0(n)            (0x4004 + ((n) * 0x0100))
#define W5200_Sn_PORT1(n)            (0x4005 + ((n) * 0x0100))
#define W5200_Sn_DHAR0(n)            (0x4006 + ((n) * 0x0100))
#define W5200_Sn_DHAR1(n)            (0x4007 + ((n) * 0x0100))
#define W5200_Sn_DHAR2(n)            (0x4008 + ((n) * 0x0100))
#define W5200_Sn_DHAR3(n)            (0x4009 + ((n) * 0x0100))
#define W5200_Sn_DHAR4(n)            (0x400A + ((n) * 0x0100))
#define W5200_Sn_DHAR5(n)            (0x400B + ((n) * 0x0100))
#define W5200_Sn_DIPR0(n)            (0x400C + ((n) * 0x0100))
#define W5200_Sn_DIPR1(n)            (0x400D + ((n) * 0x0100))
#define W5200_Sn_DIPR2(n)            (0x400E + ((n) * 0x0100))
#define W5200_Sn_DIPR3(n)            (0x400F + ((n) * 0x0100))
#define W5200_Sn_DPORT0(n)           (0x4010 + ((n) * 0x0100))
#define W5200_Sn_DPORT1(n)           (0x4011 + ((n) * 0x0100))
#define W5200_Sn_MSSR0(n)            (0x4012 + ((n) * 0x0100))
#define W5200_Sn_MSSR1(n)            (0x4013 + ((n) * 0x0100))
#define W5200_Sn_PROTO(n)            (0x4014 + ((n) * 0x0100))
#define W5200_Sn_TOS(n)              (0x4015 + ((n) * 0x0100))
#define W5200_Sn_TTL(n)              (0x4016 + ((n) * 0x0100))
#define W5200_Sn_RXMEM_SIZE(n)       (0x401E + ((n) * 0x0100))
#define W5200_Sn_TXMEM_SIZE(n)       (0x401F + ((n) * 0x0100))
#define W5200_Sn_TX_FSR0(n)          (0x4020 + ((n) * 0x0100))
#define W5200_Sn_TX_FSR1(n)          (0x4021 + ((n) * 0x0100))
#define W5200_Sn_TX_RD0(n)           (0x4022 + ((n) * 0x0100))
#define W5200_Sn_TX_RD1(n)           (0x4023 + ((n) * 0x0100))
#define W5200_Sn_TX_WR0(n)           (0x4024 + ((n) * 0x0100))
#define W5200_Sn_TX_WR1(n)           (0x4025 + ((n) * 0x0100))
#define W5200_Sn_RX_RSR0(n)          (0x4026 + ((n) * 0x0100))
#define W5200_Sn_RX_RSR1(n)          (0x4027 + ((n) * 0x0100))
#define W5200_Sn_RX_RD0(n)           (0x4028 + ((n) * 0x0100))
#define W5200_Sn_RX_RD1(n)           (0x4029 + ((n) * 0x0100))
#define W5200_Sn_RX_WR0(n)           (0x402A + ((n) * 0x0100))
#define W5200_Sn_RX_WR1(n)           (0x402B + ((n) * 0x0100))
#define W5200_Sn_IMR(n)              (0x402C + ((n) * 0x0100))
#define W5200_Sn_FRAG0(n)            (0x402D + ((n) * 0x0100))
#define W5200_Sn_FRAG1(n)            (0x402E + ((n) * 0x0100))

//TX and RX buffers
#define W5200_TX_BUFFER              0x8000
#define W5200_RX_BUFFER              0xC000

//Mode register
#define W5200_MR_RST                 0x80
#define W5200_MR_WOL                 0x20
#define W5200_MR_PB                  0x10
#define W5200_MR_PPPOE               0x08

//Interrupt register
#define W5200_IR_CONFLICT            0x80
#define W5200_IR_PPPOE               0x20

//Interrupt Mask register
#define W5200_IMR_S7_IMR             0x80
#define W5200_IMR_S6_IMR             0x40
#define W5200_IMR_S5_IMR             0x20
#define W5200_IMR_S4_IMR             0x10
#define W5200_IMR_S3_IMR             0x08
#define W5200_IMR_S2_IMR             0x04
#define W5200_IMR_S1_IMR             0x02
#define W5200_IMR_S0_IMR             0x01

//Chip version register
#define W5200_VERSIONR_DEFAULT       0x03

//Socket Interrupt register
#define W5200_IR2_S7_INT             0x80
#define W5200_IR2_S6_INT             0x40
#define W5200_IR2_S5_INT             0x20
#define W5200_IR2_S4_INT             0x10
#define W5200_IR2_S3_INT             0x08
#define W5200_IR2_S2_INT             0x04
#define W5200_IR2_S1_INT             0x02
#define W5200_IR2_S0_INT             0x01

//PHY Status register
#define W5200_PSTATUS_LINK           0x20
#define W5200_PSTATUS_POWERSAVE      0x10
#define W5200_PSTATUS_POWERDOWN      0x08

//Socket Interrupt Mask register
#define W5200_IMR2_IM_IR7            0x80
#define W5200_IMR2_IM_IR5            0x20

//Socket n Mode register
#define W5200_Sn_MR_MULTI            0x80
#define W5200_Sn_MR_MF               0x40
#define W5200_Sn_MR_ND               0x20
#define W5200_Sn_MR_MC               0x20
#define W5200_Sn_MR_PROTOCOL         0x0F
#define W5200_Sn_MR_PROTOCOL_CLOSED  0x00
#define W5200_Sn_MR_PROTOCOL_TCP     0x01
#define W5200_Sn_MR_PROTOCOL_UDP     0x02
#define W5200_Sn_MR_PROTOCOL_IPRAW   0x03
#define W5200_Sn_MR_PROTOCOL_MACRAW  0x04
#define W5200_Sn_MR_PROTOCOL_PPPOE   0x05

//Socket n Command register
#define W5200_Sn_CR_OPEN             0x01
#define W5200_Sn_CR_LISTEN           0x02
#define W5200_Sn_CR_CONNECT          0x04
#define W5200_Sn_CR_DISCON           0x08
#define W5200_Sn_CR_CLOSE            0x10
#define W5200_Sn_CR_SEND             0x20
#define W5200_Sn_CR_SEND_MAC         0x21
#define W5200_Sn_CR_SEND_KEEP        0x22
#define W5200_Sn_CR_PCON             0x23
#define W5200_Sn_CR_PDISCON          0x24
#define W5200_Sn_CR_PCR              0x25
#define W5200_Sn_CR_PCN              0x26
#define W5200_Sn_CR_PCJ              0x27
#define W5200_Sn_CR_RECV             0x40

//Socket n Interrupt register
#define W5200_Sn_IR_PRECV            0x80
#define W5200_Sn_IR_PFAIL            0x40
#define W5200_Sn_IR_PNEXT            0x20
#define W5200_Sn_IR_SENDOK           0x10
#define W5200_Sn_IR_TIMEOUT          0x08
#define W5200_Sn_IR_RECV             0x04
#define W5200_Sn_IR_DISCON           0x02
#define W5200_Sn_IR_CON              0x01

//Socket n Status register
#define W5200_Sn_SR_SOCK_CLOSED      0x00
#define W5200_Sn_SR_SOCK_ARP         0x01
#define W5200_Sn_SR_SOCK_INIT        0x13
#define W5200_Sn_SR_SOCK_LISTEN      0x14
#define W5200_Sn_SR_SOCK_SYNSENT     0x15
#define W5200_Sn_SR_SOCK_SYNRECV     0x16
#define W5200_Sn_SR_SOCK_ESTABLISHED 0x17
#define W5200_Sn_SR_SOCK_FIN_WAIT    0x18
#define W5200_Sn_SR_SOCK_CLOSING     0x1A
#define W5200_Sn_SR_SOCK_TIME_WAIT   0x1B
#define W5200_Sn_SR_SOCK_CLOSE_WAIT  0x1C
#define W5200_Sn_SR_SOCK_LAST_ACK    0x1D
#define W5200_Sn_SR_SOCK_UDP         0x22
#define W5200_Sn_SR_SOCK_IPRAW       0x32
#define W5200_Sn_SR_SOCK_MACRAW      0x42
#define W5200_Sn_SR_SOCK_PPPOE       0x5F

//Socket n Receive Memory Size register
#define W5200_Sn_RXMEM_SIZE_0KB      0x00
#define W5200_Sn_RXMEM_SIZE_1KB      0x01
#define W5200_Sn_RXMEM_SIZE_2KB      0x02
#define W5200_Sn_RXMEM_SIZE_4KB      0x04
#define W5200_Sn_RXMEM_SIZE_8KB      0x08
#define W5200_Sn_RXMEM_SIZE_16KB     0x10

//Socket n Transmit Memory Size register
#define W5200_Sn_TXMEM_SIZE_0KB      0x00
#define W5200_Sn_TXMEM_SIZE_1KB      0x01
#define W5200_Sn_TXMEM_SIZE_2KB      0x02
#define W5200_Sn_TXMEM_SIZE_4KB      0x04
#define W5200_Sn_TXMEM_SIZE_8KB      0x08
#define W5200_Sn_TXMEM_SIZE_16KB     0x10

//Socket n Interrupt Mask register
#define W5200_Sn_IMR_PRECV           0x80
#define W5200_Sn_IMR_PFAIL           0x40
#define W5200_Sn_IMR_PNEXT           0x20
#define W5200_Sn_IMR_SENDOK          0x10
#define W5200_Sn_IMR_TIMEOUT         0x08
#define W5200_Sn_IMR_RECV            0x04
#define W5200_Sn_IMR_DISCON          0x02
#define W5200_Sn_IMR_CON             0x01

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//W5200 driver
extern const NicDriver w5200Driver;

//W5200 related functions
error_t w5200Init(NetInterface *interface);

void w5200Tick(NetInterface *interface);

void w5200EnableIrq(NetInterface *interface);
void w5200DisableIrq(NetInterface *interface);
bool_t w5200IrqHandler(NetInterface *interface);
void w5200EventHandler(NetInterface *interface);

error_t w5200SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t w5200ReceivePacket(NetInterface *interface);

error_t w5200UpdateMacAddrFilter(NetInterface *interface);

void w5200WriteReg8(NetInterface *interface, uint16_t address, uint8_t data);
uint8_t w5200ReadReg8(NetInterface *interface, uint16_t address);

void w5200WriteReg16(NetInterface *interface, uint16_t address, uint16_t data);
uint16_t w5200ReadReg16(NetInterface *interface, uint16_t address);

void w5200WriteData(NetInterface *interface, const uint8_t *data,
   size_t length);

void w5200ReadData(NetInterface *interface, uint8_t *data, size_t length);

void w5200WriteBuffer(NetInterface *interface, uint16_t offset,
   const uint8_t *data, size_t length);

void w5200ReadBuffer(NetInterface *interface, uint16_t address, uint8_t *data,
   size_t length);

void w5200DumpReg(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
