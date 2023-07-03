/**
 * @file w5100s_driver.h
 * @brief WIZnet W5100S Ethernet controller
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

#ifndef _W5100S_DRIVER_H
#define _W5100S_DRIVER_H

//Dependencies
#include "core/nic.h"

//TX buffer size
#ifndef W5100S_ETH_TX_BUFFER_SIZE
   #define W5100S_ETH_TX_BUFFER_SIZE 1536
#elif (W5100S_ETH_TX_BUFFER_SIZE != 1536)
   #error W5100S_ETH_TX_BUFFER_SIZE parameter is not valid
#endif

//RX buffer size
#ifndef W5100S_ETH_RX_BUFFER_SIZE
   #define W5100S_ETH_RX_BUFFER_SIZE 1536
#elif (W5100S_ETH_RX_BUFFER_SIZE != 1536)
   #error W5100S_ETH_RX_BUFFER_SIZE parameter is not valid
#endif

//Control byte
#define W5100S_CTRL_READ              0x0F
#define W5100S_CTRL_WRITE             0xF0

//W5100S Common registers
#define W5100S_MR                     0x00
#define W5100S_GAR0                   0x01
#define W5100S_GAR1                   0x02
#define W5100S_GAR2                   0x03
#define W5100S_GAR3                   0x04
#define W5100S_SUBR0                  0x05
#define W5100S_SUBR1                  0x06
#define W5100S_SUBR2                  0x07
#define W5100S_SUBR3                  0x08
#define W5100S_SHAR0                  0x09
#define W5100S_SHAR1                  0x0A
#define W5100S_SHAR2                  0x0B
#define W5100S_SHAR3                  0x0C
#define W5100S_SHAR4                  0x0D
#define W5100S_SHAR5                  0x0E
#define W5100S_SIPR0                  0x0F
#define W5100S_SIPR1                  0x10
#define W5100S_SIPR2                  0x11
#define W5100S_SIPR3                  0x12
#define W5100S_INTPTMR0               0x13
#define W5100S_INTPTMR1               0x14
#define W5100S_IR                     0x15
#define W5100S_IMR                    0x16
#define W5100S_RTR0                   0x17
#define W5100S_RTR1                   0x18
#define W5100S_RCR                    0x19
#define W5100S_RMSR                   0x1A
#define W5100S_TMSR                   0x1B
#define W5100S_IR2                    0x20
#define W5100S_IMR2                   0x21
#define W5100S_PTIMER                 0x28
#define W5100S_PMAGIC                 0x29
#define W5100S_UIPR0                  0x2A
#define W5100S_UIPR1                  0x2B
#define W5100S_UIPR2                  0x2C
#define W5100S_UIPR3                  0x2D
#define W5100S_UPORTR0                0x2E
#define W5100S_UPORTR1                0x2F
#define W5100S_MR2                    0x30
#define W5100S_PHAR0                  0x32
#define W5100S_PHAR1                  0x33
#define W5100S_PHAR2                  0x34
#define W5100S_PHAR3                  0x35
#define W5100S_PHAR4                  0x36
#define W5100S_PHAR5                  0x37
#define W5100S_PSIDR0                 0x38
#define W5100S_PSIDR1                 0x39
#define W5100S_PMRUR0                 0x3A
#define W5100S_PMRUR1                 0x3B
#define W5100S_PHYSR0                 0x3C
#define W5100S_PHYSR1                 0x3D
#define W5100S_PHYAR                  0x3E
#define W5100S_PHYRAR                 0x3F
#define W5100S_PHYDIR0                0x40
#define W5100S_PHYDIR1                0x41
#define W5100S_PHYDOR0                0x42
#define W5100S_PHYDOR1                0x43
#define W5100S_PHYACR                 0x44
#define W5100S_PHYDIVR                0x45
#define W5100S_PHYCR0                 0x46
#define W5100S_PHYCR1                 0x47
#define W5100S_SLCR                   0x4C
#define W5100S_SLRTR0                 0x4D
#define W5100S_SLRTR1                 0x4E
#define W5100S_SLRCR                  0x4F
#define W5100S_SLPIPR0                0x50
#define W5100S_SLPIPR1                0x51
#define W5100S_SLPIPR2                0x52
#define W5100S_SLPIPR3                0x53
#define W5100S_SLPHAR0                0x54
#define W5100S_SLPHAR1                0x55
#define W5100S_SLPHAR2                0x56
#define W5100S_SLPHAR3                0x57
#define W5100S_SLPHAR4                0x58
#define W5100S_SLPHAR5                0x59
#define W5100S_PINGSEQR0              0x5A
#define W5100S_PINGSEQR1              0x5B
#define W5100S_PINGIDR0               0x5C
#define W5100S_PINGIDR1               0x5D
#define W5100S_SLIMR                  0x5E
#define W5100S_SLIR                   0x5F
#define W5100S_CLKLCKR                0x70
#define W5100S_NETLCKR                0x71
#define W5100S_PHYLCKR                0x72
#define W5100S_VERR                   0x80
#define W5100S_TCNTR0                 0x82
#define W5100S_TCNTR1                 0x83
#define W5100S_TCNTCLR                0x88

//W5100S Socket registers
#define W5100S_S0_MR                  0x0400
#define W5100S_S0_CR                  0x0401
#define W5100S_S0_IR                  0x0402
#define W5100S_S0_SR                  0x0403
#define W5100S_S0_PORTR0              0x0404
#define W5100S_S0_PORTR1              0x0405
#define W5100S_S0_DHAR0               0x0406
#define W5100S_S0_DHAR1               0x0407
#define W5100S_S0_DHAR2               0x0408
#define W5100S_S0_DHAR3               0x0409
#define W5100S_S0_DHAR4               0x040A
#define W5100S_S0_DHAR5               0x040B
#define W5100S_S0_DIPR0               0x040C
#define W5100S_S0_DIPR1               0x040D
#define W5100S_S0_DIPR2               0x040E
#define W5100S_S0_DIPR3               0x040F
#define W5100S_S0_DPORTR0             0x0410
#define W5100S_S0_DPORTR1             0x0411
#define W5100S_S0_MSS0                0x0412
#define W5100S_S0_MSS1                0x0413
#define W5100S_S0_PROTOR              0x0414
#define W5100S_S0_TOS                 0x0415
#define W5100S_S0_TTL                 0x0416
#define W5100S_S0_RXBUF_SIZE          0x041E
#define W5100S_S0_TXBUF_SIZE          0x041F
#define W5100S_S0_TX_FSR0             0x0420
#define W5100S_S0_TX_FSR1             0x0421
#define W5100S_S0_TX_RD0              0x0422
#define W5100S_S0_TX_RD1              0x0423
#define W5100S_S0_TX_WR0              0x0424
#define W5100S_S0_TX_WR1              0x0425
#define W5100S_S0_RX_RSR0             0x0426
#define W5100S_S0_RX_RSR1             0x0427
#define W5100S_S0_RX_RD0              0x0428
#define W5100S_S0_RX_RD1              0x0429
#define W5100S_S0_RX_WR0              0x042A
#define W5100S_S0_RX_WR1              0x042B
#define W5100S_S0_IMR                 0x042C
#define W5100S_S0_FRAGR0              0x042D
#define W5100S_S0_FRAGR1              0x042E
#define W5100S_S0_MR2                 0x042F
#define W5100S_S0_KPALVTR             0x0430
#define W5100S_S0_RTR0                0x0432
#define W5100S_S0_RTR1                0x0433
#define W5100S_S0_RCR                 0x0434
#define W5100S_S1_MR                  0x0500
#define W5100S_S1_CR                  0x0501
#define W5100S_S1_IR                  0x0502
#define W5100S_S1_SR                  0x0503
#define W5100S_S1_PORTR0              0x0504
#define W5100S_S1_PORTR1              0x0505
#define W5100S_S1_DHAR0               0x0506
#define W5100S_S1_DHAR1               0x0507
#define W5100S_S1_DHAR2               0x0508
#define W5100S_S1_DHAR3               0x0509
#define W5100S_S1_DHAR4               0x050A
#define W5100S_S1_DHAR5               0x050B
#define W5100S_S1_DIPR0               0x050C
#define W5100S_S1_DIPR1               0x050D
#define W5100S_S1_DIPR2               0x050E
#define W5100S_S1_DIPR3               0x050F
#define W5100S_S1_DPORTR0             0x0510
#define W5100S_S1_DPORTR1             0x0511
#define W5100S_S1_MSS0                0x0512
#define W5100S_S1_MSS1                0x0513
#define W5100S_S1_PROTOR              0x0514
#define W5100S_S1_TOS                 0x0515
#define W5100S_S1_TTL                 0x0516
#define W5100S_S1_RXBUF_SIZE          0x051E
#define W5100S_S1_TXBUF_SIZE          0x051F
#define W5100S_S1_TX_FSR0             0x0520
#define W5100S_S1_TX_FSR1             0x0521
#define W5100S_S1_TX_RD0              0x0522
#define W5100S_S1_TX_RD1              0x0523
#define W5100S_S1_TX_WR0              0x0524
#define W5100S_S1_TX_WR1              0x0525
#define W5100S_S1_RX_RSR0             0x0526
#define W5100S_S1_RX_RSR1             0x0527
#define W5100S_S1_RX_RD0              0x0528
#define W5100S_S1_RX_RD1              0x0529
#define W5100S_S1_RX_WR0              0x052A
#define W5100S_S1_RX_WR1              0x052B
#define W5100S_S1_IMR                 0x052C
#define W5100S_S1_FRAGR0              0x052D
#define W5100S_S1_FRAGR1              0x052E
#define W5100S_S1_MR2                 0x052F
#define W5100S_S1_KPALVTR             0x0530
#define W5100S_S1_RTR0                0x0532
#define W5100S_S1_RTR1                0x0533
#define W5100S_S1_RCR                 0x0534
#define W5100S_S2_MR                  0x0600
#define W5100S_S2_CR                  0x0601
#define W5100S_S2_IR                  0x0602
#define W5100S_S2_SR                  0x0603
#define W5100S_S2_PORTR0              0x0604
#define W5100S_S2_PORTR1              0x0605
#define W5100S_S2_DHAR0               0x0606
#define W5100S_S2_DHAR1               0x0607
#define W5100S_S2_DHAR2               0x0608
#define W5100S_S2_DHAR3               0x0609
#define W5100S_S2_DHAR4               0x060A
#define W5100S_S2_DHAR5               0x060B
#define W5100S_S2_DIPR0               0x060C
#define W5100S_S2_DIPR1               0x060D
#define W5100S_S2_DIPR2               0x060E
#define W5100S_S2_DIPR3               0x060F
#define W5100S_S2_DPORTR0             0x0610
#define W5100S_S2_DPORTR1             0x0611
#define W5100S_S2_MSS0                0x0612
#define W5100S_S2_MSS1                0x0613
#define W5100S_S2_PROTOR              0x0614
#define W5100S_S2_TOS                 0x0615
#define W5100S_S2_TTL                 0x0616
#define W5100S_S2_RXBUF_SIZE          0x061E
#define W5100S_S2_TXBUF_SIZE          0x061F
#define W5100S_S2_TX_FSR0             0x0620
#define W5100S_S2_TX_FSR1             0x0621
#define W5100S_S2_TX_RD0              0x0622
#define W5100S_S2_TX_RD1              0x0623
#define W5100S_S2_TX_WR0              0x0624
#define W5100S_S2_TX_WR1              0x0625
#define W5100S_S2_RX_RSR0             0x0626
#define W5100S_S2_RX_RSR1             0x0627
#define W5100S_S2_RX_RD0              0x0628
#define W5100S_S2_RX_RD1              0x0629
#define W5100S_S2_RX_WR0              0x062A
#define W5100S_S2_RX_WR1              0x062B
#define W5100S_S2_IMR                 0x062C
#define W5100S_S2_FRAGR0              0x062D
#define W5100S_S2_FRAGR1              0x062E
#define W5100S_S2_MR2                 0x062F
#define W5100S_S2_KPALVTR             0x0630
#define W5100S_S2_RTR0                0x0632
#define W5100S_S2_RTR1                0x0633
#define W5100S_S2_RCR                 0x0634
#define W5100S_S3_MR                  0x0700
#define W5100S_S3_CR                  0x0701
#define W5100S_S3_IR                  0x0702
#define W5100S_S3_SR                  0x0703
#define W5100S_S3_PORTR0              0x0704
#define W5100S_S3_PORTR1              0x0705
#define W5100S_S3_DHAR0               0x0706
#define W5100S_S3_DHAR1               0x0707
#define W5100S_S3_DHAR2               0x0708
#define W5100S_S3_DHAR3               0x0709
#define W5100S_S3_DHAR4               0x070A
#define W5100S_S3_DHAR5               0x070B
#define W5100S_S3_DIPR0               0x070C
#define W5100S_S3_DIPR1               0x070D
#define W5100S_S3_DIPR2               0x070E
#define W5100S_S3_DIPR3               0x070F
#define W5100S_S3_DPORTR0             0x0710
#define W5100S_S3_DPORTR1             0x0711
#define W5100S_S3_MSS0                0x0712
#define W5100S_S3_MSS1                0x0713
#define W5100S_S3_PROTOR              0x0714
#define W5100S_S3_TOS                 0x0715
#define W5100S_S3_TTL                 0x0716
#define W5100S_S3_RXBUF_SIZE          0x071E
#define W5100S_S3_TXBUF_SIZE          0x071F
#define W5100S_S3_TX_FSR0             0x0720
#define W5100S_S3_TX_FSR1             0x0721
#define W5100S_S3_TX_RD0              0x0722
#define W5100S_S3_TX_RD1              0x0723
#define W5100S_S3_TX_WR0              0x0724
#define W5100S_S3_TX_WR1              0x0725
#define W5100S_S3_RX_RSR0             0x0726
#define W5100S_S3_RX_RSR1             0x0727
#define W5100S_S3_RX_RD0              0x0728
#define W5100S_S3_RX_RD1              0x0729
#define W5100S_S3_RX_WR0              0x072A
#define W5100S_S3_RX_WR1              0x072B
#define W5100S_S3_IMR                 0x072C
#define W5100S_S3_FRAGR0              0x072D
#define W5100S_S3_FRAGR1              0x072E
#define W5100S_S3_MR2                 0x072F
#define W5100S_S3_KPALVTR             0x0730
#define W5100S_S3_RTR0                0x0732
#define W5100S_S3_RTR1                0x0733
#define W5100S_S3_RCR                 0x0734

//W5100S Socket register access macros
#define W5100S_Sn_MR(n)               (0x0400 + ((n) * 0x0100))
#define W5100S_Sn_CR(n)               (0x0401 + ((n) * 0x0100))
#define W5100S_Sn_IR(n)               (0x0402 + ((n) * 0x0100))
#define W5100S_Sn_SR(n)               (0x0403 + ((n) * 0x0100))
#define W5100S_Sn_PORTR0(n)           (0x0404 + ((n) * 0x0100))
#define W5100S_Sn_PORTR1(n)           (0x0405 + ((n) * 0x0100))
#define W5100S_Sn_DHAR0(n)            (0x0406 + ((n) * 0x0100))
#define W5100S_Sn_DHAR1(n)            (0x0407 + ((n) * 0x0100))
#define W5100S_Sn_DHAR2(n)            (0x0408 + ((n) * 0x0100))
#define W5100S_Sn_DHAR3(n)            (0x0409 + ((n) * 0x0100))
#define W5100S_Sn_DHAR4(n)            (0x040A + ((n) * 0x0100))
#define W5100S_Sn_DHAR5(n)            (0x040B + ((n) * 0x0100))
#define W5100S_Sn_DIPR0(n)            (0x040C + ((n) * 0x0100))
#define W5100S_Sn_DIPR1(n)            (0x040D + ((n) * 0x0100))
#define W5100S_Sn_DIPR2(n)            (0x040E + ((n) * 0x0100))
#define W5100S_Sn_DIPR3(n)            (0x040F + ((n) * 0x0100))
#define W5100S_Sn_DPORTR0(n)          (0x0410 + ((n) * 0x0100))
#define W5100S_Sn_DPORTR1(n)          (0x0411 + ((n) * 0x0100))
#define W5100S_Sn_MSS0(n)             (0x0412 + ((n) * 0x0100))
#define W5100S_Sn_MSS1(n)             (0x0413 + ((n) * 0x0100))
#define W5100S_Sn_PROTOR(n)           (0x0414 + ((n) * 0x0100))
#define W5100S_Sn_TOS(n)              (0x0415 + ((n) * 0x0100))
#define W5100S_Sn_TTL(n)              (0x0416 + ((n) * 0x0100))
#define W5100S_Sn_RXBUF_SIZE(n)       (0x041E + ((n) * 0x0100))
#define W5100S_Sn_TXBUF_SIZE(n)       (0x041F + ((n) * 0x0100))
#define W5100S_Sn_TX_FSR0(n)          (0x0420 + ((n) * 0x0100))
#define W5100S_Sn_TX_FSR1(n)          (0x0421 + ((n) * 0x0100))
#define W5100S_Sn_TX_RD0(n)           (0x0422 + ((n) * 0x0100))
#define W5100S_Sn_TX_RD1(n)           (0x0423 + ((n) * 0x0100))
#define W5100S_Sn_TX_WR0(n)           (0x0424 + ((n) * 0x0100))
#define W5100S_Sn_TX_WR1(n)           (0x0425 + ((n) * 0x0100))
#define W5100S_Sn_RX_RSR0(n)          (0x0426 + ((n) * 0x0100))
#define W5100S_Sn_RX_RSR1(n)          (0x0427 + ((n) * 0x0100))
#define W5100S_Sn_RX_RD0(n)           (0x0428 + ((n) * 0x0100))
#define W5100S_Sn_RX_RD1(n)           (0x0429 + ((n) * 0x0100))
#define W5100S_Sn_RX_WR0(n)           (0x042A + ((n) * 0x0100))
#define W5100S_Sn_RX_WR1(n)           (0x042B + ((n) * 0x0100))
#define W5100S_Sn_IMR(n)              (0x042C + ((n) * 0x0100))
#define W5100S_Sn_FRAGR0(n)           (0x042D + ((n) * 0x0100))
#define W5100S_Sn_FRAGR1(n)           (0x042E + ((n) * 0x0100))
#define W5100S_Sn_MR2(n)              (0x042F + ((n) * 0x0100))
#define W5100S_Sn_KPALVTR(n)          (0x0430 + ((n) * 0x0100))
#define W5100S_Sn_RTR0(n)             (0x0432 + ((n) * 0x0100))
#define W5100S_Sn_RTR1(n)             (0x0433 + ((n) * 0x0100))
#define W5100S_Sn_RCR(n)              (0x0434 + ((n) * 0x0100))

//TX and RX buffers
#define W5100S_TX_BUFFER              0x4000
#define W5100S_RX_BUFFER              0x6000

//Mode register
#define W5100S_MR_RST                 0x80
#define W5100S_MR_PB                  0x10
#define W5100S_MR_PPPOE               0x08

//Interrupt register
#define W5100S_IR_CONFLICT            0x80
#define W5100S_IR_UNREACH             0x40
#define W5100S_IR_PPPTERM             0x20
#define W5100S_IR_S3_INT              0x08
#define W5100S_IR_S2_INT              0x04
#define W5100S_IR_S1_INT              0x02
#define W5100S_IR_S0_INT              0x01

//Interrupt Mask register
#define W5100S_IMR_CNFT               0x80
#define W5100S_IMR_UNREACH            0x40
#define W5100S_IMR_PPPTERM            0x20
#define W5100S_IMR_S3_INT             0x08
#define W5100S_IMR_S2_INT             0x04
#define W5100S_IMR_S1_INT             0x02
#define W5100S_IMR_S0_INT             0x01

//RX Memory Size register
#define W5100S_RMSR_SOCKET3           0xC0
#define W5100S_RMSR_SOCKET3_1KB       0x00
#define W5100S_RMSR_SOCKET3_2KB       0x40
#define W5100S_RMSR_SOCKET3_4KB       0x80
#define W5100S_RMSR_SOCKET3_8KB       0xC0
#define W5100S_RMSR_SOCKET2           0x30
#define W5100S_RMSR_SOCKET2_1KB       0x00
#define W5100S_RMSR_SOCKET2_2KB       0x10
#define W5100S_RMSR_SOCKET2_4KB       0x20
#define W5100S_RMSR_SOCKET2_8KB       0x30
#define W5100S_RMSR_SOCKET1           0x0C
#define W5100S_RMSR_SOCKET1_1KB       0x00
#define W5100S_RMSR_SOCKET1_2KB       0x04
#define W5100S_RMSR_SOCKET1_4KB       0x08
#define W5100S_RMSR_SOCKET1_8KB       0x0C
#define W5100S_RMSR_SOCKET0           0x03
#define W5100S_RMSR_SOCKET0_1KB       0x00
#define W5100S_RMSR_SOCKET0_2KB       0x01
#define W5100S_RMSR_SOCKET0_4KB       0x02
#define W5100S_RMSR_SOCKET0_8KB       0x03

//TX Memory Size register
#define W5100S_TMSR_SOCKET3           0xC0
#define W5100S_TMSR_SOCKET3_1KB       0x00
#define W5100S_TMSR_SOCKET3_2KB       0x40
#define W5100S_TMSR_SOCKET3_4KB       0x80
#define W5100S_TMSR_SOCKET3_8KB       0xC0
#define W5100S_TMSR_SOCKET2           0x30
#define W5100S_TMSR_SOCKET2_1KB       0x00
#define W5100S_TMSR_SOCKET2_2KB       0x10
#define W5100S_TMSR_SOCKET2_4KB       0x20
#define W5100S_TMSR_SOCKET2_8KB       0x30
#define W5100S_TMSR_SOCKET1           0x0C
#define W5100S_TMSR_SOCKET1_1KB       0x00
#define W5100S_TMSR_SOCKET1_2KB       0x04
#define W5100S_TMSR_SOCKET1_4KB       0x08
#define W5100S_TMSR_SOCKET1_8KB       0x0C
#define W5100S_TMSR_SOCKET0           0x03
#define W5100S_TMSR_SOCKET0_1KB       0x00
#define W5100S_TMSR_SOCKET0_2KB       0x01
#define W5100S_TMSR_SOCKET0_4KB       0x02
#define W5100S_TMSR_SOCKET0_8KB       0x03

//Interrupt 2 register
#define W5100S_IR2_WOL                0x01

//Interrupt 2 Mask register
#define W5100S_IMR2_WOL               0x01

//Mode 2 register
#define W5100S_MR2_CLKSEL             0x80
#define W5100S_MR2_IEN                0x40
#define W5100S_MR2_NOTCPRST           0x20
#define W5100S_MR2_UDPURB             0x10
#define W5100S_MR2_WOL                0x08
#define W5100S_MR2_FARP               0x02

//PHY Status 0 register
#define W5100S_PHYSR0_CABOFF          0x80
#define W5100S_PHYSR0_AUTO            0x20
#define W5100S_PHYSR0_SPD             0x10
#define W5100S_PHYSR0_DPX             0x08
#define W5100S_PHYSR0_FDPX            0x04
#define W5100S_PHYSR0_FSPD            0x02
#define W5100S_PHYSR0_LINK            0x01

//PHY Status 1 register
#define W5100S_PHYSR1_ACT             0x80
#define W5100S_PHYSR1_RXP             0x04
#define W5100S_PHYSR1_LPI             0x02
#define W5100S_PHYSR1_CAL             0x01

//PHY Register Address register
#define W5100S_PHYRAR_ADDR            0x1F

//PHY Division register
#define W5100S_PHYDIVR_DIV32          0x00
#define W5100S_PHYDIVR_DIV64          0x01
#define W5100S_PHYDIVR_DIV128         0x02

//PHY Control 0 register
#define W5100S_PHYCR0_MODE            0x07
#define W5100S_PHYCR0_MODE_AN         0x00
#define W5100S_PHYCR0_MODE_100BTX_FD  0x04
#define W5100S_PHYCR0_MODE_100BTX_HD  0x05
#define W5100S_PHYCR0_MODE_10BT_FD    0x06
#define W5100S_PHYCR0_MODE_10BT_HD    0x07

//PHY Control 1 register
#define W5100S_PHYCR1_WOL             0x80
#define W5100S_PHYCR1_PWDN            0x20
#define W5100S_PHYCR1_RST             0x01

//Socket-less Command register
#define W5100S_SLCR_ARP               0x02
#define W5100S_SLCR_PING              0x01

//Socket-less Interrupt Mask register
#define W5100S_SLIMR_TIMEOUT          0x04
#define W5100S_SLIMR_ARP              0x02
#define W5100S_SLIMR_PING             0x01

//Socket-less Interrupt register
#define W5100S_SLIR_TIMEOUT           0x04
#define W5100S_SLIR_ARP               0x02
#define W5100S_SLIR_PING              0x01

//Clock Lock register
#define W5100S_CLKLCKR_LOCK           0x00
#define W5100S_CLKLCKR_UNLOCK         0xCE

//Network Lock register
#define W5100S_NETLCKR_UNLOCK         0x3A
#define W5100S_NETLCKR_LOCK           0xC5

//PHY Lock register
#define W5100S_PHYLCKR_LOCK           0x00
#define W5100S_PHYLCKR_UNLOCK         0x53

//Chip Version register
#define W5100S_VERR_DEFAULT           0x51

//Socket n Mode register
#define W5100S_Sn_MR_MULTI            0x80
#define W5100S_Sn_MR_MF               0x40
#define W5100S_Sn_MR_ND               0x20
#define W5100S_Sn_MR_MC               0x20
#define W5100S_Sn_MR_PROTOCOL         0x0F
#define W5100S_Sn_MR_PROTOCOL_CLOSED  0x00
#define W5100S_Sn_MR_PROTOCOL_TCP     0x01
#define W5100S_Sn_MR_PROTOCOL_UDP     0x02
#define W5100S_Sn_MR_PROTOCOL_IPRAW   0x03
#define W5100S_Sn_MR_PROTOCOL_MACRAW  0x04

//Socket n Command register
#define W5100S_Sn_CR_OPEN             0x01
#define W5100S_Sn_CR_LISTEN           0x02
#define W5100S_Sn_CR_CONNECT          0x04
#define W5100S_Sn_CR_DISCON           0x08
#define W5100S_Sn_CR_CLOSE            0x10
#define W5100S_Sn_CR_SEND             0x20
#define W5100S_Sn_CR_SEND_MAC         0x21
#define W5100S_Sn_CR_SEND_KEEP        0x22
#define W5100S_Sn_CR_RECV             0x40

//Socket n Interrupt register
#define W5100S_Sn_IR_SENDOK           0x10
#define W5100S_Sn_IR_TIMEOUT          0x08
#define W5100S_Sn_IR_RECV             0x04
#define W5100S_Sn_IR_DISCON           0x02
#define W5100S_Sn_IR_CON              0x01

//Socket n Status register
#define W5100S_Sn_SR_SOCK_CLOSED      0x00
#define W5100S_Sn_SR_SOCK_INIT        0x13
#define W5100S_Sn_SR_SOCK_LISTEN      0x14
#define W5100S_Sn_SR_SOCK_SYNSENT     0x15
#define W5100S_Sn_SR_SOCK_SYNRECV     0x16
#define W5100S_Sn_SR_SOCK_ESTABLISHED 0x17
#define W5100S_Sn_SR_SOCK_FIN_WAIT    0x18
#define W5100S_Sn_SR_SOCK_TIME_WAIT   0x1B
#define W5100S_Sn_SR_SOCK_CLOSE_WAIT  0x1C
#define W5100S_Sn_SR_SOCK_LAST_ACK    0x1D
#define W5100S_Sn_SR_SOCK_UDP         0x22
#define W5100S_Sn_SR_SOCK_IPRAW       0x32
#define W5100S_Sn_SR_SOCK_MACRAW      0x42

//Socket n RX Buffer Size register
#define W5100S_Sn_RXBUF_SIZE_0KB      0x00
#define W5100S_Sn_RXBUF_SIZE_1KB      0x01
#define W5100S_Sn_RXBUF_SIZE_2KB      0x02
#define W5100S_Sn_RXBUF_SIZE_4KB      0x04
#define W5100S_Sn_RXBUF_SIZE_8KB      0x08

//Socket n TX Buffer Size register
#define W5100S_Sn_TXBUF_SIZE_0KB      0x00
#define W5100S_Sn_TXBUF_SIZE_1KB      0x01
#define W5100S_Sn_TXBUF_SIZE_2KB      0x02
#define W5100S_Sn_TXBUF_SIZE_4KB      0x04
#define W5100S_Sn_TXBUF_SIZE_8KB      0x08

//Socket n Interrupt Mask register
#define W5100S_Sn_IMR_SENDOK          0x10
#define W5100S_Sn_IMR_TIMEOUT         0x08
#define W5100S_Sn_IMR_RECV            0x04
#define W5100S_Sn_IMR_DISCON          0x02
#define W5100S_Sn_IMR_CON             0x01

//Socket n Mode 2 register
#define W5100S_Sn_MR2_MBBLK           0x40
#define W5100S_Sn_MR2_MMBLK           0x20
#define W5100S_Sn_MR2_IPV6BLK         0x10
#define W5100S_Sn_MR2_BRDB            0x02
#define W5100S_Sn_MR2_UNIB            0x01

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//W5100S driver
extern const NicDriver w5100sDriver;

//W5100S related functions
error_t w5100sInit(NetInterface *interface);

void w5100sTick(NetInterface *interface);

void w5100sEnableIrq(NetInterface *interface);
void w5100sDisableIrq(NetInterface *interface);
bool_t w5100sIrqHandler(NetInterface *interface);
void w5100sEventHandler(NetInterface *interface);

error_t w5100sSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t w5100sReceivePacket(NetInterface *interface);

error_t w5100sUpdateMacAddrFilter(NetInterface *interface);

void w5100sWriteReg8(NetInterface *interface, uint16_t address, uint8_t data);
uint8_t w5100sReadReg8(NetInterface *interface, uint16_t address);

void w5100sWriteReg16(NetInterface *interface, uint16_t address, uint16_t data);
uint16_t w5100sReadReg16(NetInterface *interface, uint16_t address);

void w5100sWriteData(NetInterface *interface, const uint8_t *data,
   size_t length);

void w5100sReadData(NetInterface *interface, uint8_t *data, size_t length);

void w5100sWriteBuffer(NetInterface *interface, uint16_t offset,
   const uint8_t *data, size_t length);

void w5100sReadBuffer(NetInterface *interface, uint16_t address, uint8_t *data,
   size_t length);

void w5100sDumpReg(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
