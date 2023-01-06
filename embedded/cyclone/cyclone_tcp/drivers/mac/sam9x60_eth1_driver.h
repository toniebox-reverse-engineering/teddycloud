/**
 * @file sam9x60_eth_driver.h
 * @brief SAM9X60 Ethernet MAC driver (EMAC0 instance)
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

#ifndef _SAM9X60_ETH1_DRIVER_H
#define _SAM9X60_ETH1_DRIVER_H

//Number of TX buffers
#ifndef SAM9X60_ETH1_TX_BUFFER_COUNT
   #define SAM9X60_ETH1_TX_BUFFER_COUNT 8
#elif (SAM9X60_ETH1_TX_BUFFER_COUNT < 1)
   #error SAM9X60_ETH1_TX_BUFFER_COUNT parameter is not valid
#endif

//TX buffer size
#ifndef SAM9X60_ETH1_TX_BUFFER_SIZE
   #define SAM9X60_ETH1_TX_BUFFER_SIZE 1536
#elif (SAM9X60_ETH1_TX_BUFFER_SIZE != 1536)
   #error SAM9X60_ETH1_TX_BUFFER_SIZE parameter is not valid
#endif

//Number of RX buffers
#ifndef SAM9X60_ETH1_RX_BUFFER_COUNT
   #define SAM9X60_ETH1_RX_BUFFER_COUNT 96
#elif (SAM9X60_ETH1_RX_BUFFER_COUNT < 12)
   #error SAM9X60_ETH1_RX_BUFFER_COUNT parameter is not valid
#endif

//RX buffer size
#ifndef SAM9X60_ETH1_RX_BUFFER_SIZE
   #define SAM9X60_ETH1_RX_BUFFER_SIZE 128
#elif (SAM9X60_ETH1_RX_BUFFER_SIZE != 128)
   #error SAM9X60_ETH1_RX_BUFFER_SIZE parameter is not valid
#endif

//Ethernet interrupt priority
#ifndef SAM9X60_ETH1_IRQ_PRIORITY
   #define SAM9X60_ETH1_IRQ_PRIORITY 0
#elif (SAM9X60_ETH1_IRQ_PRIORITY < 0)
   #error SAM9X60_ETH1_IRQ_PRIORITY parameter is not valid
#endif

//Name of the section where to place DMA buffers
#ifndef SAM9X60_ETH1_RAM_SECTION
   #define SAM9X60_ETH1_RAM_SECTION ".region_nocache"
#endif

//RMII signals
#define EMAC0_RMII_MASK (PIO_PB10A_E0_TX1 | PIO_PB9A_E0_TX0 | \
   PIO_PB7A_E0_TXEN | PIO_PB6A_E0_MDC | PIO_PB5A_E0_MDIO | PIO_PB4A_E0_TXCK | \
   PIO_PB3A_E0_RXDV | PIO_PB2A_E0_RXER | PIO_PB1A_E0_RX1 | PIO_PB0A_E0_RX0)

//TX buffer descriptor flags
#define EMAC_TX_USED           0x80000000
#define EMAC_TX_WRAP           0x40000000
#define EMAC_TX_ERROR          0x20000000
#define EMAC_TX_UNDERRUN       0x10000000
#define EMAC_TX_EXHAUSTED      0x08000000
#define EMAC_TX_NO_CRC         0x00010000
#define EMAC_TX_LAST           0x00008000
#define EMAC_TX_LENGTH         0x000007FF

//RX buffer descriptor flags
#define EMAC_RX_ADDRESS        0xFFFFFFFC
#define EMAC_RX_WRAP           0x00000002
#define EMAC_RX_OWNERSHIP      0x00000001
#define EMAC_RX_BROADCAST      0x80000000
#define EMAC_RX_MULTICAST_HASH 0x40000000
#define EMAC_RX_UNICAST_HASH   0x20000000
#define EMAC_RX_EXT_ADDR       0x10000000
#define EMAC_RX_SAR1           0x04000000
#define EMAC_RX_SAR2           0x02000000
#define EMAC_RX_SAR3           0x01000000
#define EMAC_RX_SAR4           0x00800000
#define EMAC_RX_TYPE_ID        0x00400000
#define EMAC_RX_VLAN_TAG       0x00200000
#define EMAC_RX_PRIORITY_TAG   0x00100000
#define EMAC_RX_VLAN_PRIORITY  0x000E0000
#define EMAC_RX_CFI            0x00010000
#define EMAC_RX_EOF            0x00008000
#define EMAC_RX_SOF            0x00004000
#define EMAC_RX_OFFSET         0x00003000
#define EMAC_RX_LENGTH         0x00000FFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Transmit buffer descriptor
 **/

typedef struct
{
   uint32_t address;
   uint32_t status;
} Sam9x60Eth1TxBufferDesc;


/**
 * @brief Receive buffer descriptor
 **/

typedef struct
{
   uint32_t address;
   uint32_t status;
} Sam9x60Eth1RxBufferDesc;


//SAM9X60 Ethernet MAC driver (EMAC0 instance)
extern const NicDriver sam9x60Eth1Driver;

//SAM9X60 Ethernet MAC related functions
error_t sam9x60Eth1Init(NetInterface *interface);
void sam9x60Eth1InitGpio(NetInterface *interface);
void sam9x60Eth1InitBufferDesc(NetInterface *interface);

void sam9x60Eth1Tick(NetInterface *interface);

void sam9x60Eth1EnableIrq(NetInterface *interface);
void sam9x60Eth1DisableIrq(NetInterface *interface);
void sam9x60Eth1IrqHandler(void);
void sam9x60Eth1EventHandler(NetInterface *interface);

error_t sam9x60Eth1SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t sam9x60Eth1ReceivePacket(NetInterface *interface);

error_t sam9x60Eth1UpdateMacAddrFilter(NetInterface *interface);
error_t sam9x60Eth1UpdateMacConfig(NetInterface *interface);

void sam9x60Eth1WritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data);

uint16_t sam9x60Eth1ReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr);

//Wrapper for the interrupt service routine
void emacIrqWrapper(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
