/**
 * @file adin2111_driver.c
 * @brief ADIN2111 2-port 10Base-T1L Ethernet switch driver
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
#include "drivers/switch/adin2111_driver.h"
#include "debug.h"


/**
 * @brief ADIN2111 driver
 **/

const NicDriver adin2111Driver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   adin2111Init,
   adin2111Tick,
   adin2111EnableIrq,
   adin2111DisableIrq,
   adin2111EventHandler,
   adin2111SendPacket,
   adin2111UpdateMacAddrFilter,
   NULL,
   NULL,
   NULL,
   FALSE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief ADIN2111 controller initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t adin2111Init(NetInterface *interface)
{
   uint_t port;
   uint32_t value;

   //Debug message
   TRACE_INFO("Initializing ADIN2111 Ethernet controller...\r\n");

   //Initialize SPI interface
   interface->spiDriver->init();

   //Initialize external interrupt line driver
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->init();
   }

   //A full chip software reset can be initiated by writing 1 to the SWRESET
   //field of the RESET register
   adin2111WriteReg(interface, ADIN2111_RESET, ADIN2111_RESET_SWRESET);

   //Wait for the MAC to exit reset
   do
   {
      //To confirm that the MAC has exited reset, read the PHY identification
      //register
      value = adin2111ReadReg(interface, ADIN2111_PHYID);

      //If the reset value of the register can be read, the device has exited
      //reset and is ready for configuration
   } while(value != (ADIN2111_PHYID_OUI_DEFAULT | ADIN2111_PHYID_MODEL_DEFAULT |
      ADIN2111_PHYID_REVISION_DEFAULT));

   //Next, the host must read the STATUS0 register and confirm that the RESETC
   //field is 1
   do
   {
      //Read the status register 0
      value = adin2111ReadReg(interface, ADIN2111_STATUS0);

      //Check the value of the RESETC bit
   } while((value & ADIN2111_STATUS0_RESETC) == 0);

   //Write 1 to the RESETC field in the STATUS0 register to clear this field
   adin2111WriteReg(interface, ADIN2111_STATUS0, ADIN2111_STATUS0_RESETC);

   //Dump SPI registers for debugging purpose
   adin2111DumpReg(interface);

   //Loop through the ports
   for(port = ADIN2111_PORT1; port <= ADIN2111_PORT2; port++)
   {
      //Debug message
      TRACE_DEBUG("Port %u:\r\n", port);
      //Dump PHY registers for debugging purpose
      adin2111DumpPhyReg(interface, port);
   }

   //Configure MAC address filtering
   adin2111UpdateMacAddrFilter(interface);

   //Enable store and forward mode
   value = adin2111ReadReg(interface, ADIN2111_CONFIG0);
   value &= ~(ADIN2111_CONFIG0_TXCTE | ADIN2111_CONFIG0_RXCTE);
   adin2111WriteReg(interface, ADIN2111_CONFIG0, value);

   //Read MAC configuration register 2
   value = adin2111ReadReg(interface, ADIN2111_CONFIG2);
   //Enable CRC append in the MAC TX path
   value |= ADIN2111_CONFIG2_CRC_APPEND;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Port separation mode?
   if(interface->port != 0)
   {
      //Drop frames with unknown DA
      value &= ~(ADIN2111_CONFIG2_P1_FWD_UNK2P2 | ADIN2111_CONFIG2_P2_FWD_UNK2P1);
   }
   else
#endif
   {
      //Forward frames with unknown DA to the other port
      value |= ADIN2111_CONFIG2_P1_FWD_UNK2P2 | ADIN2111_CONFIG2_P2_FWD_UNK2P1;
   }

   //Update MAC configuration register 2
   adin2111WriteReg(interface, ADIN2111_CONFIG2, value);

   //Loop through the ports
   for(port = ADIN2111_PORT1; port <= ADIN2111_PORT2; port++)
   {
      //Disable system interrupts
      adin2111WriteMmdReg(interface, port, ADIN2111_CRSM_IRQ_MASK, 0);

      //Enable link status change interrupt
      adin2111WriteMmdReg(interface, port, ADIN2111_PHY_SUBSYS_IRQ_MASK,
         ADIN2111_PHY_SUBSYS_IRQ_MASK_LINK_STAT_CHNG_IRQ_EN);
   }

   //Write the IMASK0 register to enable interrupts as required
   adin2111WriteReg(interface, ADIN2111_IMASK0, ~ADIN2111_IMASK0_PHYINTM);

   //Write the IMASK1 register to enable interrupts as required
   adin2111WriteReg(interface, ADIN2111_IMASK1,
      ~(ADIN2111_IMASK1_P2_PHYINT_MASK | ADIN2111_IMASK1_P2_RX_RDY_MASK |
      ADIN2111_IMASK1_P1_RX_RDY_MASK | ADIN2111_IMASK1_TX_RDY_MASK));

   //When the MAC is configured, write 1 to the SYNC field in the CONFIG0
   //register to indicate that the MAC configuration is complete
   value = adin2111ReadReg(interface, ADIN2111_CONFIG0);
   value |= ADIN2111_CONFIG0_SYNC;
   adin2111WriteReg(interface, ADIN2111_CONFIG0, value);

   //Loop through the ports
   for(port = ADIN2111_PORT1; port <= ADIN2111_PORT2; port++)
   {
      //Configure LED0 and LED1 function
      adin2111WriteMmdReg(interface, port, ADIN2111_LED_CNTRL,
         ADIN2111_LED_CNTRL_LED0_EN |
         ADIN2111_LED_CNTRL_LED0_FUNCTION_LINKUP_TXRX_ACTIVITY |
         ADIN2111_LED_CNTRL_LED1_EN |
         ADIN2111_LED_CNTRL_LED1_FUNCTION_OFF);

      //Set LED0 and LED1 polarity
      adin2111WriteMmdReg(interface, port, ADIN2111_LED_POLARITY,
         ADIN2111_LED_POLARITY_LED0_POLARITY_ACTIVE_HIGH |
         ADIN2111_LED_POLARITY_LED1_POLARITY_ACTIVE_HIGH);

      //Clear the CRSM_SFT_PD bit to exit software power-down mode. At this
      //point, the MAC-PHY starts autonegotiation and attempts to bring up a
      //link after autonegotiation completes
      value = adin2111ReadMmdReg(interface, port, ADIN2111_CRSM_SFT_PD_CNTRL);
      value &= ~ADIN2111_CRSM_SFT_PD_CNTRL_CRSM_SFT_PD;
      adin2111WriteMmdReg(interface, port, ADIN2111_CRSM_SFT_PD_CNTRL, value);
   }

   //Perform custom configuration
   adin2111InitHook(interface);

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
 * @brief ADIN2111 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void adin2111InitHook(NetInterface *interface)
{
}


/**
 * @brief ADIN2111 timer handler
 * @param[in] interface Underlying network interface
 **/

void adin2111Tick(NetInterface *interface)
{
}


/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void adin2111EnableIrq(NetInterface *interface)
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

void adin2111DisableIrq(NetInterface *interface)
{
   //Disable interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief ADIN2111 interrupt service routine
 * @param[in] interface Underlying network interface
 * @return TRUE if a higher priority task must be woken. Else FALSE is returned
 **/

bool_t adin2111IrqHandler(NetInterface *interface)
{
   bool_t flag;
   size_t n;
   uint32_t mask0;
   uint32_t mask1;
   uint32_t status0;
   uint32_t status1;

   //This flag will be set if a higher priority task must be woken
   flag = FALSE;

   //Save interrupt mask register values
   mask0 = adin2111ReadReg(interface, ADIN2111_IMASK0);
   mask1 = adin2111ReadReg(interface, ADIN2111_IMASK1);

   //Disable interrupts to release the interrupt line
   adin2111WriteReg(interface, ADIN2111_IMASK0, 0xFFFFFFFF);
   adin2111WriteReg(interface, ADIN2111_IMASK1, 0xFFFFFFFF);

   //Read interrupt status registers
   status0 = adin2111ReadReg(interface, ADIN2111_STATUS0);
   status1 = adin2111ReadReg(interface, ADIN2111_STATUS1);
      
   //PHY interrupt on port 1?
   if((status0 & ADIN2111_STATUS0_PHYINT) != 0)
   {
      //Disable link status changed interrupt
      mask0 |= ADIN2111_IMASK0_PHYINTM;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //PHY interrupt on port 2?
   if((status1 & ADIN2111_STATUS1_P2_PHYINT) != 0)
   {
      //Disable link status changed interrupt
      mask1 |= ADIN2111_IMASK1_P2_PHYINT_MASK;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Packet received on port1?
   if((status1 & ADIN2111_STATUS1_P1_RX_RDY) != 0)
   {
      //Disable P1_RX_RDY interrupt
      mask1 |= ADIN2111_IMASK1_P1_RX_RDY_MASK;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Packet received on port2?
   if((status1 & ADIN2111_STATUS1_P2_RX_RDY) != 0)
   {
      //Disable P2_RX_RDY interrupt
      mask1 |= ADIN2111_IMASK1_P2_RX_RDY_MASK;

      //Set event flag
      interface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Packet transmission complete?
   if((status1 & ADIN2111_STATUS1_TX_RDY) != 0)
   {
      //Clear interrupt flag
      adin2111WriteReg(interface, ADIN2111_STATUS1, ADIN2111_STATUS1_TX_RDY);

      //The TX_SPACE register indicates the remaining space in the TX FIFO
      n = adin2111ReadReg(interface, ADIN2111_TX_SPACE) &
         ADIN2111_TX_SPACE_TX_SPACE;

      //Verify that there is space for a new frame
      if(n >= (ADIN2111_ETH_TX_BUFFER_SIZE + ADIN2111_TX_FRAME_OVERHEAD))
      {
         //Notify the TCP/IP stack that the transmitter is ready to send
         flag |= osSetEventFromIsr(&interface->nicTxEvent);
      }
   }

   //Re-enable interrupts once the interrupt has been serviced
   adin2111WriteReg(interface, ADIN2111_IMASK0, mask0);
   adin2111WriteReg(interface, ADIN2111_IMASK1, mask1);

   //A higher priority task must be woken?
   return flag;
}


/**
 * @brief ADIN2111 event handler
 * @param[in] interface Underlying network interface
 **/

void adin2111EventHandler(NetInterface *interface)
{
   uint32_t status0;
   uint32_t status1;
   uint16_t phyStatus;

   //When an interrupt occurs, the system can poll the MAC status registers
   //(STATUS0 and STATUS1) to determine the origin of the interrupt
   status0 = adin2111ReadReg(interface, ADIN2111_STATUS0);
   status1 = adin2111ReadReg(interface, ADIN2111_STATUS1);

   //PHY interrupt on port 1?
   if((status0 & ADIN2111_STATUS0_PHYINT) != 0)
   {
      //Host software must read the PHY_SUBSYS_IRQ_STATUS and CRSM_IRQ_STATUS
      //registers to determine the source of the interrupt
      phyStatus = adin2111ReadMmdReg(interface, ADIN2111_PORT1,
         ADIN2111_CRSM_IRQ_STATUS);

      phyStatus = adin2111ReadMmdReg(interface, ADIN2111_PORT1,
         ADIN2111_PHY_SUBSYS_IRQ_STATUS);

      //Link status change on port1?
      if((phyStatus & ADIN2111_PHY_SUBSYS_IRQ_STATUS_LINK_STAT_CHNG_LH) != 0)
      {
         //Handle link status change event
         adin2111LinkChangeEventHandler(interface);
      }
   }

   //PHY interrupt on port 2?
   if((status1 & ADIN2111_STATUS1_P2_PHYINT) != 0)
   {
      //Host software must read the PHY_SUBSYS_IRQ_STATUS and CRSM_IRQ_STATUS
      //registers to determine the source of the interrupt
      phyStatus = adin2111ReadMmdReg(interface, ADIN2111_PORT2,
         ADIN2111_CRSM_IRQ_STATUS);

      phyStatus = adin2111ReadMmdReg(interface, ADIN2111_PORT2,
         ADIN2111_PHY_SUBSYS_IRQ_STATUS);
      
      //Link status change on port2?
      if((phyStatus & ADIN2111_PHY_SUBSYS_IRQ_STATUS_LINK_STAT_CHNG_LH) != 0)
      {
         //Handle link status change event
         adin2111LinkChangeEventHandler(interface);
      }
   }

   //Packet received on port 1?
   if((status1 & ADIN2111_STATUS1_P1_RX_RDY) != 0)
   {
      //Process all pending packets
      do
      {
         //Read incoming packet
         adin2111ReceivePacket(interface, ADIN2111_PORT1);

         //Read STATUS1 again
         status1 = adin2111ReadReg(interface, ADIN2111_STATUS1);

         //If the P1_RX_RDY bit is set, another frame is available to read
      } while((status1 & ADIN2111_STATUS1_P1_RX_RDY) != 0);
   }

   //Packet received on port 2?
   if((status1 & ADIN2111_STATUS1_P2_RX_RDY) != 0)
   {
      //Process all pending packets
      do
      {
         //Read incoming packet
         adin2111ReceivePacket(interface, ADIN2111_PORT2);

         //Read STATUS1 again
         status1 = adin2111ReadReg(interface, ADIN2111_STATUS1);

         //If the P2_RX_RDY bit is set, another frame is available to read
      } while((status1 & ADIN2111_STATUS1_P2_RX_RDY) != 0);
   }

   //Write the IMASK0 register to re-enable interrupts
   adin2111WriteReg(interface, ADIN2111_IMASK0, ~ADIN2111_IMASK0_PHYINTM);

   //Write the IMASK1 register to re-enable interrupts
   adin2111WriteReg(interface, ADIN2111_IMASK1,
      ~(ADIN2111_IMASK1_P2_PHYINT_MASK | ADIN2111_IMASK1_P2_RX_RDY_MASK |
      ADIN2111_IMASK1_P1_RX_RDY_MASK | ADIN2111_IMASK1_TX_RDY_MASK));
}


/**
 * @brief ADIN2111 link status change event handler
 * @param[in] interface Underlying network interface
 **/

void adin2111LinkChangeEventHandler(NetInterface *interface)
{
   uint_t port;
   bool_t linkState;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Port separation mode?
   if(interface->port != 0)
   {
      uint_t i;
      NetInterface *virtualInterface;

      //Loop through network interfaces
      for(i = 0; i < NET_INTERFACE_COUNT; i++)
      {
         //Point to the current interface
         virtualInterface = &netInterface[i];

         //Check whether the current virtual interface is attached to the
         //physical interface
         if(virtualInterface == interface ||
            virtualInterface->parent == interface)
         {
            //Get the port number associated with the current interface
            port = virtualInterface->port;

            //Valid port?
            if(port >= ADIN2111_PORT1 && port <= ADIN2111_PORT2)
            {
               //Retrieve current link state
               linkState = adin2111GetLinkState(interface, port);

               //Link up event?
               if(linkState && !virtualInterface->linkState)
               {
                  //The switch is only able to operate in 10 Mbps mode
                  virtualInterface->linkSpeed = NIC_LINK_SPEED_10MBPS;
                  virtualInterface->duplexMode = NIC_FULL_DUPLEX_MODE;

                  //Update link state
                  virtualInterface->linkState = TRUE;

                  //Process link state change event
                  nicNotifyLinkChange(virtualInterface);
               }
               //Link down event
               else if(!linkState && virtualInterface->linkState)
               {
                  //Update link state
                  virtualInterface->linkState = FALSE;

                  //Process link state change event
                  nicNotifyLinkChange(virtualInterface);
               }
            }
         }
      }
   }
   else
#endif
   {
      //Initialize link state
      linkState = FALSE;

      //Loop through the ports
      for(port = ADIN2111_PORT1; port <= ADIN2111_PORT2; port++)
      {
         //Retrieve current link state
         if(adin2111GetLinkState(interface, port))
         {
            linkState = TRUE;
         }
      }

      //Link up event?
      if(linkState)
      {
         //The switch is only able to operate in 10 Mbps mode
         interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
         interface->duplexMode = NIC_FULL_DUPLEX_MODE;

         //Update link state
         interface->linkState = TRUE;
      }
      else
      {
         //Update link state
         interface->linkState = FALSE;
      }

      //Process link state change event
      nicNotifyLinkChange(interface);
   }
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

error_t adin2111SendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary)
{
   static uint8_t temp[ADIN2111_ETH_TX_BUFFER_SIZE];
   size_t n;
   size_t length;

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

   //Check the frame length
   if(length > ADIN2111_ETH_TX_BUFFER_SIZE)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //The TX_SPACE register indicates the remaining space in the TX FIFO
   n = adin2111ReadReg(interface, ADIN2111_TX_SPACE) &
      ADIN2111_TX_SPACE_TX_SPACE;

   //Ensure that there is sufficient space for the Ethernet frame plus 2-byte
   //header plus 2-byte size field
   if(n < (length + ADIN2111_TX_FRAME_OVERHEAD))
   {
      return ERROR_FAILURE;
   }

   //Copy user data
   netBufferRead(temp, buffer, offset, length);

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Check port number
   if(ancillary->port == ADIN2111_PORT1)
   {
      //TX_FSIZE is written with the original frame size + 2 bytes for the
      //frame header
      adin2111WriteReg(interface, ADIN2111_TX_FSIZE, length +
         ADIN2111_FRAME_HEADER_SIZE);

      //Write frame data (port 1)
      adin2111WriteFifo(interface, ADIN2111_FRAME_HEADER_PORT1, temp, length);
   }
   else if(ancillary->port == ADIN2111_PORT2)
   {
      //TX_FSIZE is written with the original frame size + 2 bytes for the
      //frame header
      adin2111WriteReg(interface, ADIN2111_TX_FSIZE, length +
         ADIN2111_FRAME_HEADER_SIZE);

      //Write frame data (port 2)
      adin2111WriteFifo(interface, ADIN2111_FRAME_HEADER_PORT2, temp, length);
   }
   else
#endif
   {
      //TX_FSIZE is written with the original frame size + 2 bytes for the
      //frame header
      adin2111WriteReg(interface, ADIN2111_TX_FSIZE, length +
         ADIN2111_FRAME_HEADER_SIZE);

      //Write frame data (port 1)
      adin2111WriteFifo(interface, ADIN2111_FRAME_HEADER_PORT1, temp, length);

      //TX_FSIZE is written with the original frame size + 2 bytes for the
      //frame header
      adin2111WriteReg(interface, ADIN2111_TX_FSIZE, length +
         ADIN2111_FRAME_HEADER_SIZE);

      //Write frame data (port 2)
      adin2111WriteFifo(interface, ADIN2111_FRAME_HEADER_PORT2, temp, length);
   }

   //The TX_SPACE register indicates the remaining space in the TX FIFO
   n = adin2111ReadReg(interface, ADIN2111_TX_SPACE) &
      ADIN2111_TX_SPACE_TX_SPACE;

   //Verify that there is space for a new frame
   if(n >= (ADIN2111_ETH_TX_BUFFER_SIZE + ADIN2111_TX_FRAME_OVERHEAD))
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Receive a packet
 * @param[in] port Port number
 * @param[in] interface Underlying network interface
 **/

void adin2111ReceivePacket(NetInterface *interface, uint8_t port)
{
   static uint8_t temp[ADIN2111_ETH_RX_BUFFER_SIZE];
   size_t length;
   uint16_t header;

   //Check port number
   if(port == ADIN2111_PORT1)
   {
      //Get the size of the frame at the head of the port 1 RX FIFO in bytes
      length = adin2111ReadReg(interface, ADIN2111_P1_RX_FSIZE) &
         ADIN2111_P1_RX_FSIZE_P1_RX_FRM_SIZE;
   }
   else
   {
      //Get the size of the frame at the head of the port 2 RX FIFO in bytes
      length = adin2111ReadReg(interface, ADIN2111_P2_RX_FSIZE) &
         ADIN2111_P2_RX_FSIZE_P2_RX_FRM_SIZE;
   }

   //Any packet pending in the receive buffer?
   if(length >= ADIN2111_FRAME_HEADER_SIZE)
   {
      NetRxAncillary ancillary;

      //The size of the frame includes the appended header
      length -= ADIN2111_FRAME_HEADER_SIZE;
      //Read frame data
      adin2111ReadFifo(interface, port, &header, temp, length);

      //Limit the length of the payload
      length = MIN(length, ADIN2111_ETH_RX_BUFFER_SIZE);
      //Additional options can be passed to the stack along with the packet
      ancillary = NET_DEFAULT_RX_ANCILLARY;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
      //Save the port number on which the frame was received
      ancillary.port = port;
#endif

      //Pass the packet to the upper layer
      nicProcessPacket(interface, temp, length, &ancillary);
   }
}


/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t adin2111UpdateMacAddrFilter(NetInterface *interface)
{
   uint_t i;
   uint_t j;
   uint32_t flags;
   MacFilterEntry *entry;

   //Debug message
   TRACE_DEBUG("Updating MAC filter...\r\n");

   //Set the upper 16 bits of the broadcast MAC address
   adin2111WriteReg(interface, ADIN2111_ADDR_FILT_UPRn(0),
      ADIN2111_ADDR_FILT_UPR_APPLY2PORT2 | ADIN2111_ADDR_FILT_UPR_APPLY2PORT1 |
      ADIN2111_ADDR_FILT_UPR_TO_OTHER_PORT | ADIN2111_ADDR_FILT_UPR_TO_HOST |
      ADIN2111_ADDR_FILT_UPR_MAC_ADDR_47_32);

   //Set the lower 32 bits of the broadcast MAC address
   adin2111WriteReg(interface, ADIN2111_ADDR_FILT_LWRn(0),
      ADIN2111_ADDR_FILT_LWR_MAC_ADDR_31_0);

   //Set the upper 16 bits of the station MAC address
   adin2111WriteReg(interface, ADIN2111_ADDR_FILT_UPRn(1),
      ADIN2111_ADDR_FILT_UPR_APPLY2PORT2 | ADIN2111_ADDR_FILT_UPR_APPLY2PORT1 |
      ADIN2111_ADDR_FILT_UPR_TO_HOST | (interface->macAddr.b[0] << 8) |
      interface->macAddr.b[1]);

   //Set the lower 32 bits of the station MAC address
   adin2111WriteReg(interface, ADIN2111_ADDR_FILT_LWRn(1),
      (interface->macAddr.b[2] << 24) | (interface->macAddr.b[3] << 16) |
      (interface->macAddr.b[4] << 8) | interface->macAddr.b[5]);

   //The MAC address filter contains the list of MAC addresses to accept
   //when receiving an Ethernet frame
   for(i = 0, j = 2; i < MAC_ADDR_FILTER_SIZE &&
      j < ADIN2111_ADDR_TABLE_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->macAddrFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //Specify forwarding rules
         flags = ADIN2111_ADDR_FILT_UPR_APPLY2PORT2 |
            ADIN2111_ADDR_FILT_UPR_APPLY2PORT1 | ADIN2111_ADDR_FILT_UPR_TO_HOST;

         //Multicast address?
         if(macIsMulticastAddr(&entry->addr))
         {
            flags |= ADIN2111_ADDR_FILT_UPR_TO_OTHER_PORT;
         }

         //Set the upper 16 bits of the current MAC address
         adin2111WriteReg(interface, ADIN2111_ADDR_FILT_UPRn(j),
            flags | (entry->addr.b[0] << 8) | entry->addr.b[1]);

         //Set the lower 32 bits of the current MAC address
         adin2111WriteReg(interface, ADIN2111_ADDR_FILT_LWRn(j),
            (entry->addr.b[2] << 24) | (entry->addr.b[3] << 16) |
            (entry->addr.b[4] << 8) | entry->addr.b[5]);

         //Increment index
         j++;
      }
   }

   //Clear unused table entries
   for(; j < ADIN2111_ADDR_TABLE_SIZE; j++)
   {
      //Clear current MAC address
      adin2111WriteReg(interface, ADIN2111_ADDR_FILT_UPRn(j), 0);
      adin2111WriteReg(interface, ADIN2111_ADDR_FILT_LWRn(j), 0);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get link state
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @return Link state
 **/

bool_t adin2111GetLinkState(NetInterface *interface, uint8_t port)
{
   uint16_t value;
   bool_t linkState;

   //Check port number
   if(port >= ADIN2111_PORT1 && port <= ADIN2111_PORT2)
   {
      //Any link failure condition is latched in the MI_STATUS register.
      //Reading the register twice will always return the actual link status
      value = adin2111ReadPhyReg(interface, port, ADIN2111_MI_STATUS);
      value = adin2111ReadPhyReg(interface, port, ADIN2111_MI_STATUS);

      //Retrieve current link state
      linkState = (value & ADIN2111_MI_STATUS_MI_LINK_STAT_LAT) ? TRUE : FALSE;
   }
   else
   {
      //The specified port number is not valid
      linkState = FALSE;
   }

   //Return link status
   return linkState;
}


/**
 * @brief Write SPI register
 * @param[in] interface Underlying network interface
 * @param[in] address Register address
 * @param[in] data System register value
 **/

void adin2111WriteReg(NetInterface *interface, uint16_t address,
   uint32_t data)
{
   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(ADIN2111_SPI_CMD_WRITE | (address >> 8));
   interface->spiDriver->transfer(address & 0xFF);

   //Write data
   interface->spiDriver->transfer((data >> 24) & 0xFF);
   interface->spiDriver->transfer((data >> 16) & 0xFF);
   interface->spiDriver->transfer((data >> 8) & 0xFF);
   interface->spiDriver->transfer(data & 0xFF);

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}


/**
 * @brief Read SPI register
 * @param[in] interface Underlying network interface
 * @param[in] address System register address
 * @return Register value
 **/

uint32_t adin2111ReadReg(NetInterface *interface, uint16_t address)
{
   uint32_t data;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(ADIN2111_SPI_CMD_READ | (address >> 8));
   interface->spiDriver->transfer(address & 0xFF);

   //Turn around
   interface->spiDriver->transfer(0x00);

   //Read data
   data = interface->spiDriver->transfer(0x00) << 24;
   data |= interface->spiDriver->transfer(0x00) << 16;
   data |= interface->spiDriver->transfer(0x00) << 8;
   data |= interface->spiDriver->transfer(0x00);

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();

   //Return register value
   return data;
}


/**
 * @brief Dump SPI registers for debugging purpose
 * @param[in] interface Underlying network interface
 **/

void adin2111DumpReg(NetInterface *interface)
{
   uint16_t i;

   //Loop through system registers
   for(i = 0; i < 256; i++)
   {
      //Display current SPI register
      TRACE_DEBUG("0x%02" PRIX16 ": 0x%08" PRIX32 "\r\n", i,
         adin2111ReadReg(interface, i));
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}


/**
 * @brief Write PHY register
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @param[in] address PHY register address
 * @param[in] data Register value
 **/

void adin2111WritePhyReg(NetInterface *interface, uint8_t port,
   uint8_t address, uint16_t data)
{
   uint32_t value;

   //Perform a Clause 22 write operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_22 | ADIN2111_MDIOACC_MDIO_OP_WRITE;
   //Set PHY address
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set register address
   value |= (address << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;
   //Set register value
   value |= data & ADIN2111_MDIOACC_MDIO_DATA;

   //Write MDIOACC0 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC0, value);

   //Poll MDIOACC0.TRDONE to determine that the write operation has completed
   do
   {
      //Read MDIOACC0 register
      value = adin2111ReadReg(interface, ADIN2111_MDIOACC0);

      //When the MDIO transaction completes, the TRDONE bit is set to 1
   } while((value & ADIN2111_MDIOACC_MDIO_TRDONE) == 0);
}


/**
 * @brief Read PHY register
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @param[in] address PHY register address
 * @return Register value
 **/

uint16_t adin2111ReadPhyReg(NetInterface *interface, uint8_t port,
   uint8_t address)
{
   uint32_t value;

   //Perform a Clause 22 read operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_22 | ADIN2111_MDIOACC_MDIO_OP_READ;
   //Set PHY address
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set register address
   value |= (address << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;

   //Write MDIOACC0 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC0, value);

   //Poll MDIOACC0.TRDONE to determine that the read operation has completed
   do
   {
      //Read MDIOACC0 register
      value = adin2111ReadReg(interface, ADIN2111_MDIOACC0);

      //When the MDIO transaction completes, the TRDONE bit is set to 1
   } while((value & ADIN2111_MDIOACC_MDIO_TRDONE) == 0);

   //MDIOACC0.MDIO_DATA reflects the content of register
   return value & ADIN2111_MDIOACC_MDIO_DATA;
}


/**
 * @brief Dump PHY registers for debugging purpose
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 **/

void adin2111DumpPhyReg(NetInterface *interface, uint8_t port)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         adin2111ReadPhyReg(interface, port, i));
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}


/**
 * @brief Write MMD register
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @param[in] data MMD register value
 **/

void adin2111WriteMmdReg(NetInterface *interface, uint8_t port,
   uint8_t devAddr, uint16_t regAddr, uint16_t data)
{
   uint32_t value;

   //Perform a Clause 45 address write operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_45 | ADIN2111_MDIOACC_MDIO_OP_ADDR;
   //MDIO_PRTAD is always written to 1
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set device address
   value |= (devAddr << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;
   //Set register address
   value |= regAddr & ADIN2111_MDIOACC_MDIO_DATA;

   //Write MDIOACC0 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC0, value);

   //Perform a Clause 45 write operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_45 | ADIN2111_MDIOACC_MDIO_OP_WRITE;
   //MDIO_PRTAD is always written to 1
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set device address
   value |= (devAddr << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;
   //Set register value
   value |= data & ADIN2111_MDIOACC_MDIO_DATA;

   //Write MDIOACC1 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC1, value);

   //Poll MDIOACC1.TRDONE to determine that the write operation has completed
   do
   {
      //Read MDIOACC1 register
      value = adin2111ReadReg(interface, ADIN2111_MDIOACC1);

      //When the MDIO transaction completes, the TRDONE bit is set to 1
   } while((value & ADIN2111_MDIOACC_MDIO_TRDONE) == 0);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t adin2111ReadMmdReg(NetInterface *interface, uint8_t port,
   uint8_t devAddr, uint16_t regAddr)
{
   uint32_t value;

   //Perform a Clause 45 address write operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_45 | ADIN2111_MDIOACC_MDIO_OP_ADDR;
   //MDIO_PRTAD is always written to 1
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set device address
   value |= (devAddr << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;
   //Set register address
   value |= regAddr & ADIN2111_MDIOACC_MDIO_DATA;

   //Write MDIOACC0 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC0, value);

   //Perform a Clause 45 read operation
   value = ADIN2111_MDIOACC_MDIO_ST_CLAUSE_45 | ADIN2111_MDIOACC_MDIO_OP_READ;
   //MDIO_PRTAD is always written to 1
   value |= (port << 21) & ADIN2111_MDIOACC_MDIO_PRTAD;
   //Set device address
   value |= (devAddr << 16) & ADIN2111_MDIOACC_MDIO_DEVAD;

   //Write MDIOACC1 register
   adin2111WriteReg(interface, ADIN2111_MDIOACC1, value);

   //Poll MDIOACC1.TRDONE to determine that the read operation has completed
   do
   {
      //Read MDIOACC1 register
      value = adin2111ReadReg(interface, ADIN2111_MDIOACC1);

      //When the MDIO transaction completes, the TRDONE bit is set to 1
   } while((value & ADIN2111_MDIOACC_MDIO_TRDONE) == 0);

   //MDIOACC1.MDIO_DATA reflects the content of register
   return value & ADIN2111_MDIOACC_MDIO_DATA;
}


/**
 * @brief Write TX FIFO
 * @param[in] interface Underlying network interface
 * @param[in] header Frame header
 * @param[in] data Pointer to the data being written
 * @param[in] length Number of data to write
 **/

void adin2111WriteFifo(NetInterface *interface, uint16_t header,
   const uint8_t *data, size_t length)
{
   size_t i;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Write command
   interface->spiDriver->transfer(ADIN2111_SPI_CMD_WRITE | (ADIN2111_TX >> 8));
   interface->spiDriver->transfer(ADIN2111_TX & 0xFF);

   //The 2-byte frame header is appended to all transmitted frames. This always
   //precedes the frame data
   interface->spiDriver->transfer((header >> 8) & 0xFF);
   interface->spiDriver->transfer(header & 0xFF);

   //Write frame data
   for(i = 0; i < length; i++)
   {
      interface->spiDriver->transfer(data[i]);
   }

   //The burst write data must always be in multiples of 4 bytes
   for(; ((i + ADIN2111_FRAME_HEADER_SIZE) % 4) != 0; i++)
   {
      interface->spiDriver->transfer(0x00);
   }

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}


/**
 * @brief Read RX FIFO
 * @param[in] interface Underlying network interface
 * @param[in] port Port number
 * @param[out] header Frame header
 * @param[out] data Buffer where to store the incoming data
 * @param[in] length Number of data to read
 **/

void adin2111ReadFifo(NetInterface *interface, uint8_t port,
   uint16_t *header, uint8_t *data, size_t length)
{
   size_t i;
   uint16_t address;

   //Pull the CS pin low
   interface->spiDriver->assertCs();

   //Select the relevant RX FIFO
   if(port == ADIN2111_PORT1)
   {
      address = ADIN2111_P1_RX;
   }
   else
   {
      address = ADIN2111_P2_RX;
   }

   //Write command
   interface->spiDriver->transfer(ADIN2111_SPI_CMD_READ | (address >> 8));
   interface->spiDriver->transfer(address & 0xFF);

   //Turn around
   interface->spiDriver->transfer(0x00);

   //The 2-byte frame header is appended to all received frames. This always
   //precedes the frame data
   *header = interface->spiDriver->transfer(0x00) << 16;
   *header |= interface->spiDriver->transfer(0x00);

   //Read frame data
   for(i = 0; i < length && i < ADIN2111_ETH_RX_BUFFER_SIZE; i++)
   {
      data[i] = interface->spiDriver->transfer(0x00);
   }

   //Discard extra bytes
   for(; i < length; i++)
   {
      interface->spiDriver->transfer(0x00);
   }

   //The burst read data must always be in multiples of 4 bytes
   for(; ((i + ADIN2111_FRAME_HEADER_SIZE) % 4) != 0; i++)
   {
      interface->spiDriver->transfer(0x00);
   }

   //Terminate the operation by raising the CS pin
   interface->spiDriver->deassertCs();
}
