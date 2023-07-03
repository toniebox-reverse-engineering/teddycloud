/**
 * @file adin1100_driver.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL NIC_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "drivers/phy/adin1100_driver.h"
#include "debug.h"


/**
 * @brief ADIN1100 Ethernet PHY driver
 **/

const PhyDriver adin1100PhyDriver =
{
   adin1100Init,
   adin1100Tick,
   adin1100EnableIrq,
   adin1100DisableIrq,
   adin1100EventHandler
};


/**
 * @brief ADIN1100 PHY transceiver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t adin1100Init(NetInterface *interface)
{
   uint16_t value;

   //Debug message
   TRACE_INFO("Initializing ADIN1100...\r\n");

   //Undefined PHY address?
   if(interface->phyAddr >= 32)
   {
      //Use the default address
      interface->phyAddr = ADIN1100_PHY_ADDR;
   }

   //Initialize serial management interface
   if(interface->smiDriver != NULL)
   {
      interface->smiDriver->init();
   }

   //Initialize external interrupt line driver
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->init();
   }

   //Reset PHY transceiver
   adin1100WritePhyReg(interface,  ADIN1100_MI_CONTROL,
      ADIN1100_MI_CONTROL_MI_SFT_RST);

   //Wait for the reset to complete
   while(adin1100ReadPhyReg(interface,  ADIN1100_MI_CONTROL) &
      ADIN1100_MI_CONTROL_MI_SFT_RST)
   {
   }

   //Dump PHY registers for debugging purpose
   adin1100DumpPhyReg(interface);

   //Enable LED1 output
   value = adin1100ReadMmdReg(interface, ADIN1100_DIGIO_PINMUX);
   value &= ~ADIN1100_DIGIO_PINMUX_DIGIO_LED1_PINMUX;
   value |= ADIN1100_DIGIO_PINMUX_DIGIO_LED1_PINMUX_LED_1;
   adin1100WriteMmdReg(interface, ADIN1100_DIGIO_PINMUX, value);

   //Configure LED0 and LED1 function
   adin1100WriteMmdReg(interface, ADIN1100_LED_CNTRL,
      ADIN1100_LED_CNTRL_LED0_EN |
      ADIN1100_LED_CNTRL_LED0_FUNCTION_LINKUP_TXRX_ACTIVITY |
      ADIN1100_LED_CNTRL_LED1_EN |
      ADIN1100_LED_CNTRL_LED1_FUNCTION_MASTER);

   //Set LED0 and LED1 polarity
   adin1100WriteMmdReg(interface, ADIN1100_LED_POLARITY,
      ADIN1100_LED_POLARITY_LED0_POLARITY_AUTOSENSE |
      ADIN1100_LED_POLARITY_LED1_POLARITY_AUTOSENSE);

   //Clear the CRSM_SFT_PD bit to exit software power-down mode. At this point,
   //the MAC-PHY starts autonegotiation and attempts to bring up a link after
   //autonegotiation completes
   value = adin1100ReadMmdReg(interface, ADIN1100_CRSM_SFT_PD_CNTRL);
   value &= ~ADIN1100_CRSM_SFT_PD_CNTRL_CRSM_SFT_PD;
   adin1100WriteMmdReg(interface, ADIN1100_CRSM_SFT_PD_CNTRL, value);

   //Perform custom configuration
   adin1100InitHook(interface);

   //Force the TCP/IP stack to poll the link state at startup
   interface->phyEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief ADIN1100 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void adin1100InitHook(NetInterface *interface)
{
}


/**
 * @brief ADIN1100 timer handler
 * @param[in] interface Underlying network interface
 **/

void adin1100Tick(NetInterface *interface)
{
   uint16_t value;
   bool_t linkState;

   //No external interrupt line driver?
   if(interface->extIntDriver == NULL)
   {
      //Read PHY status register
      value = adin1100ReadPhyReg(interface, ADIN1100_MI_STATUS);
      //Retrieve current link state
      linkState = (value & ADIN1100_MI_STATUS_MI_LINK_STAT_LAT) ? TRUE : FALSE;

      //Link up event?
      if(linkState && !interface->linkState)
      {
         //Set event flag
         interface->phyEvent = TRUE;
         //Notify the TCP/IP stack of the event
         osSetEvent(&netEvent);
      }
      //Link down event?
      else if(!linkState && interface->linkState)
      {
         //Set event flag
         interface->phyEvent = TRUE;
         //Notify the TCP/IP stack of the event
         osSetEvent(&netEvent);
      }
   }
}


/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void adin1100EnableIrq(NetInterface *interface)
{
   //Enable PHY transceiver interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->enableIrq();
   }
}


/**
 * @brief Disable interrupts
 * @param[in] interface Underlying network interface
 **/

void adin1100DisableIrq(NetInterface *interface)
{
   //Disable PHY transceiver interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief ADIN1100 event handler
 * @param[in] interface Underlying network interface
 **/

void adin1100EventHandler(NetInterface *interface)
{
   uint16_t value;

   //Read PHY status register
   value = adin1100ReadPhyReg(interface, ADIN1100_MI_STATUS);

   //Link is up?
   if((value & ADIN1100_MI_STATUS_MI_LINK_STAT_LAT) != 0)
   {
      //The PHY is only able to operate in 10 Mbps mode
      interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
      interface->duplexMode = NIC_FULL_DUPLEX_MODE;

      //Adjust MAC configuration parameters for proper operation
      interface->nicDriver->updateMacConfig(interface);

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


/**
 * @brief Write PHY register
 * @param[in] interface Underlying network interface
 * @param[in] address PHY register address
 * @param[in] data Register value
 **/

void adin1100WritePhyReg(NetInterface *interface, uint8_t address,
   uint16_t data)
{
   //Write the specified PHY register
   if(interface->smiDriver != NULL)
   {
      interface->smiDriver->writePhyReg(SMI_OPCODE_WRITE,
         interface->phyAddr, address, data);
   }
   else
   {
      interface->nicDriver->writePhyReg(SMI_OPCODE_WRITE,
         interface->phyAddr, address, data);
   }
}


/**
 * @brief Read PHY register
 * @param[in] interface Underlying network interface
 * @param[in] address PHY register address
 * @return Register value
 **/

uint16_t adin1100ReadPhyReg(NetInterface *interface, uint8_t address)
{
   uint16_t data;

   //Read the specified PHY register
   if(interface->smiDriver != NULL)
   {
      data = interface->smiDriver->readPhyReg(SMI_OPCODE_READ,
         interface->phyAddr, address);
   }
   else
   {
      data = interface->nicDriver->readPhyReg(SMI_OPCODE_READ,
         interface->phyAddr, address);
   }

   //Return the value of the PHY register
   return data;
}


/**
 * @brief Dump PHY registers for debugging purpose
 * @param[in] interface Underlying network interface
 **/

void adin1100DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         adin1100ReadPhyReg(interface, i));
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

void adin1100WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS_CNTRL,
      ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_ADDR |
      (devAddr & ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_DEVAD));

   //Write MMD register address
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS, regAddr);

   //Select data operation
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS_CNTRL,
      ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_DATA_NO_POST_INC |
      (devAddr & ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_DEVAD));

   //Write the content of the MMD register
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t adin1100ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS_CNTRL,
      ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_ADDR |
      (devAddr & ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_DEVAD));

   //Write MMD register address
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS, regAddr);

   //Select data operation
   adin1100WritePhyReg(interface, ADIN1100_MMD_ACCESS_CNTRL,
      ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_FUNCTION_DATA_NO_POST_INC |
      (devAddr & ADIN1100_MMD_ACCESS_CNTRL_MMD_ACR_DEVAD));

   //Read the content of the MMD register
   return adin1100ReadPhyReg(interface, ADIN1100_MMD_ACCESS);
}
