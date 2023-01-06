/**
 * @file lan9250_driver.c
 * @brief LAN9250 Ethernet controller
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

//Switch to the appropriate trace level
#define TRACE_LEVEL NIC_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "drivers/eth/lan9250_driver.h"
#include "debug.h"


/**
 * @brief LAN9250 driver
 **/

const NicDriver lan9250Driver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   lan9250Init,
   lan9250Tick,
   lan9250EnableIrq,
   lan9250DisableIrq,
   lan9250EventHandler,
   lan9250SendPacket,
   lan9250UpdateMacAddrFilter,
   NULL,
   NULL,
   NULL,
   TRUE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief LAN9250 controller initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t lan9250Init(NetInterface *interface)
{
   uint32_t value;

   //Debug message
   TRACE_INFO("Initializing LAN9250 Ethernet controller...\r\n");

   //Initialize SPI interface
   interface->spiDriver->init();

   //Initialize external interrupt line driver
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->init();
   }

   //Before device initialization, the SPI interface will not return valid
   //data. To determine when the SPI interface is functional, the BYTE_TEST
   //register should be polled
   do
   {
      //Read BYTE_TEST register
      value = lan9250ReadSysReg(interface, LAN9250_BYTE_TEST);

      //Once the correct pattern is read, the interface can be considered
      //functional
   } while(value != LAN9250_BYTE_TEST_DEFAULT);

   //Perform multi-module reset
   lan9250WriteSysReg(interface, LAN9250_RESET_CTL, LAN9250_RESET_CTL_DIGITAL_RST);

   //Multi-module reset completion can be determined by polling the BYTE_TEST
   //register
   do
   {
      //Read BYTE_TEST register
      value = lan9250ReadSysReg(interface, LAN9250_BYTE_TEST);

      //Once the correct pattern is read, the reset has completed
   } while(value != LAN9250_BYTE_TEST_DEFAULT);

   //At this point, the READY bit in the HW_CFG register can be polled to
   //determine when the device is fully configured
   do
   {
      //Read HW_CFG register
      value = lan9250ReadSysReg(interface, LAN9250_HW_CFG);

      //When set, the READY bit indicates that the reset has completed and
      //the device is ready to be accessed
   } while((value & LAN9250_HW_CFG_DEVICE_READY) == 0);

   //Dump system registers for debugging purpose
   lan9250DumpSysReg(interface);
   //Dump host MAC registers for debugging purpose
   lan9250DumpMacReg(interface);
   //Dump PHY registers for debugging purpose
   lan9250DumpPhyReg(interface);

   //Set the lower 32 bits of the MAC address
   lan9250WriteMacReg(interface, LAN9250_HMAC_ADDRL, interface->macAddr.b[0] |
      (interface->macAddr.b[1] << 8) | (interface->macAddr.b[2] << 16) |
      (interface->macAddr.b[3] << 24));

   //Set the upper 16 bits of the MAC address
   lan9250WriteMacReg(interface, LAN9250_HMAC_ADDRH, interface->macAddr.b[4] |
      (interface->macAddr.b[5] << 8));

   //Configure the size of the TX FIFO
   lan9250WriteSysReg(interface, LAN9250_HW_CFG, LAN9250_HW_CFG_MBO |
      LAN9250_HW_CFG_TX_FIF_SZ_5KB);

   //The host can optionally choose to not read the TX status. The TX status
   //can be ignored by setting the TXSAO bit
   lan9250WriteSysReg(interface, LAN9250_TX_CFG, LAN9250_TX_CFG_TXSAO);

   //Configure address filtering
   lan9250WriteMacReg(interface, LAN9250_HMAC_CR, LAN9250_HMAC_CR_RCVOWN |
      LAN9250_HMAC_CR_FDPX | LAN9250_HMAC_CR_HPFILT);

   //Configure the IRQ pin
   lan9250WriteSysReg(interface, LAN9250_IRQ_CFG,
      LAN9250_IRQ_CFG_INT_DEAS_100US | LAN9250_IRQ_CFG_IRQ_EN |
      LAN9250_IRQ_CFG_IRQ_POL_LOW | LAN9250_IRQ_CFG_IRQ_TYPE_OD);

   //Configure interrupts as desired
   lan9250WriteSysReg(interface, LAN9250_INT_EN, LAN9250_INT_EN_PHY_INT_EN |
      LAN9250_INT_STS_TX_IOC | LAN9250_INT_EN_RSFL_EN);

   //Configure PHY interrupts as desired
   lan9250WritePhyReg(interface, LAN9250_PHY_INTERRUPT_MASK,
      LAN9250_PHY_INTERRUPT_MASK_LINK_UP | LAN9250_PHY_INTERRUPT_MASK_LINK_DOWN);

   //Enable transmitter
   value = lan9250ReadSysReg(interface, LAN9250_TX_CFG);
   value |= LAN9250_TX_CFG_TX_ON;
   lan9250WriteSysReg(interface, LAN9250_TX_CFG, value);

   //Enable host MAC transmitter and receiver
   value = lan9250ReadMacReg(interface, LAN9250_HMAC_CR);
   value |= LAN9250_HMAC_CR_TXEN | LAN9250_HMAC_CR_RXEN;
   lan9250WriteMacReg(interface, LAN9250_HMAC_CR, value);

   //Accept any packets from the upper layer
   osSetEvent(&interface->nicTxEvent);

   //Force the TCP/IP stack to poll the link state at startup
   interface->nicEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief LAN9250 timer handler
 * @param[in] interface Underlying network interface
 **/

void lan9250Tick(NetInterface *interface)
{
}


/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void lan9250EnableIrq(NetInterface *interface)
{
   //Enable interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->enableIrq();
   }
}


/**
 * @brief Disable interrupts
 * @param[in] interface Underlying network interface
 **/

void lan9250DisableIrq(NetInterface *interface)
{
   //Disable interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief LAN9250 interrupt service routine
 * @param[in] interface Underlying network interface
 * @return TRUE if a higher priority task must be woken. Else FALSE is returned
 **/

bool_t lan9250IrqHandler(NetInterface *interface)
{
   bool_t flag;
   size_t n;
   uint32_t ier;
   uint32_t isr;

   //This flag will be set if a higher priority task must be woken
   flag = FALSE;

   //Save interrupt enable register value
   ier = lan9250ReadSysReg(interface, LAN9250_INT_EN);
   //Disable interrupts to release the interrupt line
   lan9250WriteSysReg(interface, LAN9250_INT_EN, 0);

   //Read interrupt status register
   isr = lan9250ReadSysReg(interface, LAN9250_INT_STS);

   //PHY interrupt?
   if((isr & LAN9250_INT_STS_PHY_INT) != 0)
   {
      //Disable PHY interrupt
      ier &= ~LAN9250_INT_EN_PHY_INT_EN;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Packet transmission complete?
   if((isr & LAN9250_INT_STS_TX_IOC) != 0)
   {
      //Clear interrupt flag
      lan9250WriteSysReg(interface, LAN9250_INT_STS, LAN9250_INT_STS_TX_IOC);

      //Get the amount of free memory available in the TX FIFO
      n = lan9250ReadSysReg(interface, LAN9250_TX_FIFO_INF) &
         LAN9250_TX_FIFO_INF_TXFREE;

      //Check whether the TX FIFO is available for writing
      if(n >= (LAN9250_ETH_TX_BUFFER_SIZE + LAN9250_TX_CMD_SIZE))
      {
         //Notify the TCP/IP stack that the transmitter is ready to send
         flag |= osSetEventFromIsr(&interface->nicTxEvent);
      }
   }

   //Packet received?
   if((isr & LAN9250_INT_STS_RSFL) != 0)
   {
      //Disable RSFL interrupt
      ier &= ~LAN9250_INT_EN_RSFL_EN;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Re-enable interrupts once the interrupt has been serviced
   lan9250WriteSysReg(interface, LAN9250_INT_EN, ier);

   //A higher priority task must be woken?
   return flag;
}


/**
 * @brief LAN9250 event handler
 * @param[in] interface Underlying network interface
 **/

void lan9250EventHandler(NetInterface *interface)
{
   error_t error;
   uint32_t isr;
   uint32_t value;

   //Read interrupt status register
   isr = lan9250ReadSysReg(interface, LAN9250_INT_STS);

   //PHY interrupt?
   if((isr & LAN9250_INT_STS_PHY_INT) != 0)
   {
      //Read PHY interrupt source register
      value = lan9250ReadPhyReg(interface, LAN9250_PHY_INTERRUPT_SOURCE);

      //Link status change?
      if((value & LAN9250_PHY_INTERRUPT_SOURCE_LINK_UP) != 0 ||
         (value & LAN9250_PHY_INTERRUPT_SOURCE_LINK_DOWN) != 0)
      {
         //Any link failure condition is latched in the BMSR register. Reading
         //the register twice will always return the actual link status
         value = lan9250ReadPhyReg(interface, LAN9250_PHY_BASIC_STATUS);
         value = lan9250ReadPhyReg(interface, LAN9250_PHY_BASIC_STATUS);

         //Check link state
         if((value & LAN9250_PHY_BASIC_STATUS_LINK_STATUS) != 0)
         {
            //Read PHY special control status register
            value = lan9250ReadPhyReg(interface, LAN9250_PHY_SPECIAL_CONTROL_STATUS);

            //Check current operation mode
            switch(value & LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED)
            {
            //10BASE-T half-duplex
            case LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_10BT_HD:
               interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
               interface->duplexMode = NIC_HALF_DUPLEX_MODE;
               break;

            //10BASE-T full-duplex
            case LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_10BT_FD:
               interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
               interface->duplexMode = NIC_FULL_DUPLEX_MODE;
               break;

            //100BASE-TX half-duplex
            case LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_100BTX_HD:
               interface->linkSpeed = NIC_LINK_SPEED_100MBPS;
               interface->duplexMode = NIC_HALF_DUPLEX_MODE;
               break;

            //100BASE-TX full-duplex
            case LAN9250_PHY_SPECIAL_CONTROL_STATUS_SPEED_100BTX_FD:
               interface->linkSpeed = NIC_LINK_SPEED_100MBPS;
               interface->duplexMode = NIC_FULL_DUPLEX_MODE;
               break;

            //Unknown operation mode
            default:
               //Debug message
               TRACE_WARNING("Invalid operation mode!\r\n");
               break;
            }

            //Link is up
            interface->linkState = TRUE;
         }
         else
         {
            //Link is down
            interface->linkState = FALSE;
         }

         //Process link state change event
         nicNotifyLinkChange(interface);
      }
   }

   //Packet received?
   if((isr & LAN9250_INT_STS_RSFL) != 0)
   {
      //Clear interrupt flag
      lan9250WriteSysReg(interface, LAN9250_INT_STS, LAN9250_INT_STS_RSFL);

      //Process all pending packets
      do
      {
         //Read incoming packet
         error = lan9250ReceivePacket(interface);

         //No more data in the receive buffer?
      } while(error != ERROR_BUFFER_EMPTY);
   }

   //Re-enable interrupts
   lan9250WriteSysReg(interface, LAN9250_INT_EN, LAN9250_INT_EN_PHY_INT_EN |
      LAN9250_INT_STS_TX_IOC | LAN9250_INT_EN_RSFL_EN);
}


/**
 * @brief Send a packet
 * @param[in] interface Underlying network interface
 * @param[in] buffer Multi-part buffer containing the data to send
 * @param[in] offset Offset to the first data byte
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t lan9250SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary)
{
   static uint8_t temp[LAN9250_ETH_TX_BUFFER_SIZE];
   size_t n;
   size_t length;

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

   //Check the frame length
   if(length > LAN9250_ETH_TX_BUFFER_SIZE)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Get the amount of free memory available in the TX FIFO
   n = lan9250ReadSysReg(interface, LAN9250_TX_FIFO_INF) &
      LAN9250_TX_FIFO_INF_TXFREE;

   //Before writing the TX command and payload data to the TX FIFO, the host
   //must check the available TX FIFO space
   if(n < (length + LAN9250_TX_CMD_SIZE))
   {
      return ERROR_FAILURE;
   }

   //Copy user data
   netBufferRead(temp, buffer, offset, length);

   //The host proceeds to write the TX command by first writing TX command 'A'
   lan9250WriteSysReg(interface, LAN9250_TX_DATA_FIFO,
      LAN9250_TX_CMD_A_INT_ON_COMP | LAN9250_TX_CMD_A_BUFFER_ALIGN_4B |
      LAN9250_TX_CMD_A_START_OFFSET_0B | LAN9250_TX_CMD_A_FIRST_SEG |
      LAN9250_TX_CMD_A_LAST_SEG | length);

   //Then write TX command 'B'
   lan9250WriteSysReg(interface, LAN9250_TX_DATA_FIFO,
      LAN9250_TX_CMD_B_PACKET_TAG | length);

   //After writing the command, the host can then move the payload data into
   //the TX FIFO
   lan9250WriteFifo(interface, temp, length);

   //Get the amount of free memory available in the TX FIFO
   n = lan9250ReadSysReg(interface, LAN9250_TX_FIFO_INF) &
      LAN9250_TX_FIFO_INF_TXFREE;

   //Check whether the TX FIFO is available for writing
   if(n >= (LAN9250_ETH_TX_BUFFER_SIZE + LAN9250_TX_CMD_SIZE))
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Receive a packet
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t lan9250ReceivePacket(NetInterface *interface)
{
   static uint8_t temp[LAN9250_ETH_RX_BUFFER_SIZE];
   error_t error;
   size_t length;
   uint32_t status;

   //Get the amount of space currently used in the RX status FIFO
   length = (lan9250ReadSysReg(interface, LAN9250_RX_FIFO_INF) &
      LAN9250_RX_FIFO_INF_RXSUSED) >> 16;

   //Any packet pending in the receive buffer?
   if(length > 0)
   {
      //Read RX status word
      status = lan9250ReadSysReg(interface, LAN9250_RX_STATUS_FIFO);
      //Get the length of the received packet
      length = (status & LAN9250_RX_STS_PACKET_LEN) >> 16;

      //Make sure no error occurred
      if((status & LAN9250_RX_STS_ERROR_STATUS) == 0)
      {
         //Check packet length
         if(length > 0 && length <= LAN9250_ETH_RX_BUFFER_SIZE)
         {
            //Read packet data
            lan9250ReadFifo(interface, temp, length);
            //Valid packet received
            error = NO_ERROR;
         }
         else
         {
            //Discard the received packet
            lan9250DropPacket(interface, length);
            //Report an error
            error = ERROR_INVALID_LENGTH;
         }
      }
      else
      {
         //Discard the received packet
         lan9250DropPacket(interface, length);
         //Report an error
         error = ERROR_INVALID_PACKET;
      }
   }
   else
   {
      //No more data in the receive buffer
      error = ERROR_BUFFER_EMPTY;
   }

   //Check whether a valid packet has been received
   if(!error)
   {
      NetRxAncillary ancillary;

      //Additional options can be passed to the stack along with the packet
      ancillary = NET_DEFAULT_RX_ANCILLARY;

      //Pass the packet to the upper layer
      nicProcessPacket(interface, temp, length, &ancillary);
   }

   //Return status code
   return error;
}


/**
 * @brief Drop the received packet
 * @param[in] interface Underlying network interface
 * @param[in] length Length of the packet, in bytes
 **/

void lan9250DropPacket(NetInterface *interface, size_t length)
{
   size_t i;

   //When performing a fast-forward, there must be at least 4 words of data
   //in the RX data FIFO for the packet being discarded
   if(length >= 16)
   {
      //Using the RX_FFWD bit, the host can instruct the device to skip the
      //packet at the head of the RX data FIFO
      lan9250WriteSysReg(interface, LAN9250_RX_DP_CTRL,
         LAN9250_RX_DP_CTRL_RX_FFWD);

      //After initiating a fast-forward operation, do not perform any reads of
      //the RX data FIFO until the RX_FFWD bit is cleared
      while((lan9250ReadSysReg(interface, LAN9250_RX_DP_CTRL) &
         LAN9250_RX_DP_CTRL_RX_FFWD) != 0)
      {
      }
   }
   else
   {
      //For cases with less than 4 words, data must be read from the RX data
      //FIFO and discarded using standard PIO read operations
      for(i = 0; i < length; i += 4)
      {
         //Perform standard PIO read operation
         lan9250ReadSysReg(interface, LAN9250_RX_DATA_FIFO);
      }
   }
}


/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t lan9250UpdateMacAddrFilter(NetInterface *interface)
{
   uint_t i;
   uint_t k;
   uint32_t crc;
   uint32_t hashTable[2];
   MacFilterEntry *entry;

   //Debug message
   TRACE_DEBUG("Updating MAC filter...\r\n");

   //Clear hash table
   osMemset(hashTable, 0, sizeof(hashTable));

   //The MAC address filter contains the list of MAC addresses to accept
   //when receiving an Ethernet frame
   for(i = 0; i < MAC_ADDR_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->macAddrFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //Compute CRC over the current MAC address
         crc = lan9250CalcCrc(&entry->addr, sizeof(MacAddr));
         //Calculate the corresponding index in the table
         k = (crc >> 26) & 0x3F;
         //Update hash table contents
         hashTable[k / 32] |= (1 << (k % 32));
      }
   }

   //Write the hash table to the LAN9250 controller
   lan9250WriteMacReg(interface, LAN9250_HMAC_HASHL, hashTable[0]);
   lan9250WriteMacReg(interface, LAN9250_HMAC_HASHH, hashTable[1]);

   //Debug message
   TRACE_DEBUG("  HMAC_HASHL = %08" PRIX32 "\r\n",
      lan9250ReadMacReg(interface, LAN9250_HMAC_HASHL));
   TRACE_DEBUG("  HMAC_HASHH = %08" PRIX32 "\r\n",
      lan9250ReadMacReg(interface, LAN9250_HMAC_HASHH));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write system CSR register
 * @param[in] interface Underlying network interface
 * @param[in] address Register address
 * @param[in] data System register value
 **/

void lan9250WriteSysReg(NetInterface *interface, uint16_t address,
   uint32_t data)
{
   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(LAN9250_SPI_INSTR_WRITE);

   //Write address
   interface->spiDriver->transfer((address >> 8) & 0xFF);
   interface->spiDriver->transfer(address & 0xFF);

   //Write data
   interface->spiDriver->transfer(data & 0xFF);
   interface->spiDriver->transfer((data >> 8) & 0xFF);
   interface->spiDriver->transfer((data >> 16) & 0xFF);
   interface->spiDriver->transfer((data >> 24) & 0xFF);

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}


/**
 * @brief Read system CSR register
 * @param[in] interface Underlying network interface
 * @param[in] address System register address
 * @return Register value
 **/

uint32_t lan9250ReadSysReg(NetInterface *interface, uint16_t address)
{
   uint32_t data;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(LAN9250_SPI_INSTR_READ);

   //Write address
   interface->spiDriver->transfer((address >> 8) & 0xFF);
   interface->spiDriver->transfer(address & 0xFF);

   //Read data
   data = interface->spiDriver->transfer(0x00);
   data |= interface->spiDriver->transfer(0x00) << 8;
   data |= interface->spiDriver->transfer(0x00) << 16;
   data |= interface->spiDriver->transfer(0x00) << 24;

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();

   //Return register value
   return data;
}


/**
 * @brief Dump system CSR registers for debugging purpose
 * @param[in] interface Underlying network interface
 **/

void lan9250DumpSysReg(NetInterface *interface)
{
   uint16_t i;

   //Loop through system registers
   for(i = 80; i < 512; i += 4)
   {
      //Display current system register
      TRACE_DEBUG("0x%03" PRIX16 ": 0x%08" PRIX32 "\r\n", i,
         lan9250ReadSysReg(interface, i));
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}


/**
 * @brief Write host MAC CSR register
 * @param[in] interface Underlying network interface
 * @param[in] address Host MAC register address
 * @param[in] data Register value
 **/

void lan9250WriteMacReg(NetInterface *interface, uint8_t address,
   uint32_t data)
{
   uint32_t value;

   //To perform a write to an individual host MAC register, the desired
   //data must first be written into the MAC_CSR_DATA register
   lan9250WriteSysReg(interface, LAN9250_MAC_CSR_DATA, data);

   //Set up a write operation
   value = LAN9250_MAC_CSR_CMD_BUSY | LAN9250_MAC_CSR_CMD_WRITE;
   //Set register address
   value |= address & LAN9250_MAC_CSR_CMD_ADDR;

   //The write cycle is initiated by performing a single write to the
   //MAC_CSR_CMD register
   lan9250WriteSysReg(interface, LAN9250_MAC_CSR_CMD, value);

   //The completion of the write cycle is indicated by the clearing of the
   //CSR_BUSY bit
   do
   {
      //Read MAC_CSR_CMD register
      value = lan9250ReadSysReg(interface, LAN9250_MAC_CSR_CMD);

      //Poll CSR_BUSY bit
   } while((value & LAN9250_MAC_CSR_CMD_BUSY) != 0);
}


/**
 * @brief Read host MAC CSR register
 * @param[in] interface Underlying network interface
 * @param[in] address Host MAC register address
 * @return Register value
 **/

uint32_t lan9250ReadMacReg(NetInterface *interface, uint8_t address)
{
   uint32_t value;

   //Set up a read operation
   value = LAN9250_MAC_CSR_CMD_BUSY | LAN9250_MAC_CSR_CMD_READ;
   //Set register address
   value |= address & LAN9250_MAC_CSR_CMD_ADDR;

   //To perform a read of an individual host MAC register, the read cycle
   //must be initiated by performing a single write to the MAC_CSR_CMD
   //register
   lan9250WriteSysReg(interface, LAN9250_MAC_CSR_CMD, value);

   //Valid data is available for reading when the CSR_BUSY bit is cleared
   do
   {
      //Read MAC_CSR_CMD register
      value = lan9250ReadSysReg(interface, LAN9250_MAC_CSR_CMD);

      //Poll CSR_BUSY bit
   } while((value & LAN9250_MAC_CSR_CMD_BUSY) != 0);

   //Read data from the MAC_CSR_DATA register
   return lan9250ReadSysReg(interface, LAN9250_MAC_CSR_DATA);
}


/**
 * @brief Dump host MAC CSR registers for debugging purpose
 * @param[in] interface Underlying network interface
 **/

void lan9250DumpMacReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through host MAC registers
   for(i = 0; i < 16; i++)
   {
      //Display current host MAC register
      TRACE_DEBUG("%02" PRIu8 ": 0x%08" PRIX32 "\r\n", i,
         lan9250ReadMacReg(interface, i));
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}


/**
 * @brief Write PHY register
 * @param[in] interface Underlying network interface
 * @param[in] address PHY register address
 * @param[in] data Register value
 **/

void lan9250WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data)
{
   uint32_t value;

   //The HMAC_MII_DATA register contains the data to be written
   lan9250WriteMacReg(interface, LAN9250_HMAC_MII_DATA, data);

   //Set up a write operation
   value = LAN9250_HMAC_MII_ACC_MIIBZY | LAN9250_HMAC_MII_ACC_MIIW_R |
      LAN9250_HMAC_MII_ACC_PHY_ADDR_DEFAULT;

   //Set register address
   value |= (address << 6) & LAN9250_HMAC_MII_ACC_MIIRINDA;

   //Initiate a write cycle
   lan9250WriteMacReg(interface, LAN9250_HMAC_MII_ACC, value);

   //During a MII register access, the MIIBZY bit will be set, signifying a
   //read or write access is in progress
   do
   {
      //Read HMAC_MII_ACC register
      value = lan9250ReadMacReg(interface, LAN9250_HMAC_MII_ACC);

      //The MIIBZY bit must be polled to determine when the MII register access
      //is complete
   } while((value & LAN9250_HMAC_MII_ACC_MIIBZY) != 0);
}


/**
 * @brief Read PHY register
 * @param[in] interface Underlying network interface
 * @param[in] address PHY register address
 * @return Register value
 **/

uint16_t lan9250ReadPhyReg(NetInterface *interface, uint8_t address)
{
   uint32_t value;

   //Set up a read operation
   value = LAN9250_HMAC_MII_ACC_MIIBZY | LAN9250_HMAC_MII_ACC_PHY_ADDR_DEFAULT;
   //Set register address
   value |= (address << 6) & LAN9250_HMAC_MII_ACC_MIIRINDA;

   //Initiate a read cycle
   lan9250WriteMacReg(interface, LAN9250_HMAC_MII_ACC, value);

   //During a MII register access, the MIIBZY bit will be set, signifying a
   //read or write access is in progress
   do
   {
      //Read HMAC_MII_ACC register
      value = lan9250ReadMacReg(interface, LAN9250_HMAC_MII_ACC);

      //The MIIBZY bit must be polled to determine when the MII register access
      //is complete
   } while((value & LAN9250_HMAC_MII_ACC_MIIBZY) != 0);

   //Read data from the HMAC_MII_DATA register
   return lan9250ReadMacReg(interface, LAN9250_HMAC_MII_DATA) &
      LAN9250_HMAC_MII_DATA_MII_DATA;
}


/**
 * @brief Dump PHY registers for debugging purpose
 * @param[in] interface Underlying network interface
 **/

void lan9250DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         lan9250ReadPhyReg(interface, i));
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}


/**
 * @brief Write MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @param[in] data MMD register value
 **/

void lan9250WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ACCESS,
      LAN9250_PHY_MMD_ACCESS_FUNC_ADDR |
      (devAddr & LAN9250_PHY_MMD_ACCESS_DEVAD));

   //Write MMD register address
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ADDR_DATA, regAddr);

   //Select data operation
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ACCESS,
      LAN9250_PHY_MMD_ACCESS_FUNC_DATA_NO_POST_INC |
      (devAddr & LAN9250_PHY_MMD_ACCESS_DEVAD));

   //Write the content of the MMD register
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ADDR_DATA, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t lan9250ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ACCESS,
      LAN9250_PHY_MMD_ACCESS_FUNC_ADDR |
      (devAddr & LAN9250_PHY_MMD_ACCESS_DEVAD));

   //Write MMD register address
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ADDR_DATA, regAddr);

   //Select data operation
   lan9250WritePhyReg(interface, LAN9250_PHY_MMD_ACCESS,
      LAN9250_PHY_MMD_ACCESS_FUNC_DATA_NO_POST_INC |
      (devAddr & LAN9250_PHY_MMD_ACCESS_DEVAD));

   //Read the content of the MMD register
   return lan9250ReadPhyReg(interface, LAN9250_PHY_MMD_ADDR_DATA);
}


/**
 * @brief Write TX FIFO
 * @param[in] interface Underlying network interface
 * @param[in] data Pointer to the data being written
 * @param[in] length Number of data to write
 **/

void lan9250WriteFifo(NetInterface *interface, const uint8_t *data,
   size_t length)
{
   size_t i;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(LAN9250_SPI_INSTR_WRITE);

   //Write address
   interface->spiDriver->transfer((LAN9250_TX_DATA_FIFO >> 8) & 0xFF);
   interface->spiDriver->transfer(LAN9250_TX_DATA_FIFO & 0xFF);

   //Write data
   for(i = 0; i < length; i++)
   {
      interface->spiDriver->transfer(data[i]);
   }

   //Maintain alignment to 4-byte boundaries
   for(; (i % 4) != 0; i++)
   {
      interface->spiDriver->transfer(0x00);
   }

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}


/**
 * @brief Read RX FIFO
 * @param[in] interface Underlying network interface
 * @param[out] data Buffer where to store the incoming data
 * @param[in] length Number of data to read
 **/

void lan9250ReadFifo(NetInterface *interface, uint8_t *data, size_t length)
{
   size_t i;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(LAN9250_SPI_INSTR_READ);

   //Write address
   interface->spiDriver->transfer((LAN9250_RX_DATA_FIFO >> 8) & 0xFF);
   interface->spiDriver->transfer(LAN9250_RX_DATA_FIFO & 0xFF);

   //Read data
   for(i = 0; i < length; i++)
   {
      data[i] = interface->spiDriver->transfer(0x00);
   }

   //Maintain alignment to 4-byte boundaries
   for(; (i % 4) != 0; i++)
   {
      interface->spiDriver->transfer(0x00);
   }

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}


/**
 * @brief CRC calculation
 * @param[in] data Pointer to the data over which to calculate the CRC
 * @param[in] length Number of bytes to process
 * @return Resulting CRC value
 **/

uint32_t lan9250CalcCrc(const void *data, size_t length)
{
   uint_t i;
   uint_t j;
   uint32_t crc;
   const uint8_t *p;

   //Point to the data over which to calculate the CRC
   p = (uint8_t *) data;
   //CRC preset value
   crc = 0xFFFFFFFF;

   //Loop through data
   for(i = 0; i < length; i++)
   {
      //The message is processed bit by bit
      for(j = 0; j < 8; j++)
      {
         //Update CRC value
         if((((crc >> 31) ^ (p[i] >> j)) & 0x01) != 0)
         {
            crc = (crc << 1) ^ 0x04C11DB7;
         }
         else
         {
            crc = crc << 1;
         }
      }
   }

   //Return CRC value
   return crc;
}
