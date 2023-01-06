/**
 * @file pef7071_driver.c
 * @brief XWAY PHY11G (PEF7071) Gigabit Ethernet PHY driver
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
#include "drivers/phy/pef7071_driver.h"
#include "debug.h"


/**
 * @brief PEF7071 Ethernet PHY driver
 **/

const PhyDriver pef7071PhyDriver =
{
   pef7071Init,
   pef7071Tick,
   pef7071EnableIrq,
   pef7071DisableIrq,
   pef7071EventHandler
};


/**
 * @brief PEF7071 PHY transceiver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t pef7071Init(NetInterface *interface)
{
   //Debug message
   TRACE_INFO("Initializing PEF7071...\r\n");

   //Undefined PHY address?
   if(interface->phyAddr >= 32)
   {
      //Use the default address
      interface->phyAddr = PEF7071_PHY_ADDR;
   }

   //Initialize serial management interface
   if(interface->smiDriver != NULL)
   {
      interface->smiDriver->init();
   }

   //Reset PHY transceiver
   pef7071WritePhyReg(interface, PEF7071_CTRL, PEF7071_CTRL_RST);

   //Wait for the reset to complete
   while(pef7071ReadPhyReg(interface, PEF7071_CTRL) & PEF7071_CTRL_RST)
   {
   }

   //Dump PHY registers for debugging purpose
   pef7071DumpPhyReg(interface);

   //Select RMII mode
   pef7071WritePhyReg(interface, PEF7071_MIICTRL, PEF7071_MIICTRL_RXCOFF |
      PEF7071_MIICTRL_MODE_RMII);

   //The link speed is forced to 10/100 Mbit/s only
   pef7071WritePhyReg(interface, PEF7071_GCTRL, 0);

   //Restart auto-negotiation
   pef7071WritePhyReg(interface, PEF7071_CTRL, PEF7071_CTRL_ANEN |
      PEF7071_CTRL_ANRS);

   //Perform custom configuration
   pef7071InitHook(interface);

   //Force the TCP/IP stack to poll the link state at startup
   interface->phyEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief PEF7071 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void pef7071InitHook(NetInterface *interface)
{
}


/**
 * @brief PEF7071 timer handler
 * @param[in] interface Underlying network interface
 **/

void pef7071Tick(NetInterface *interface)
{
   uint16_t value;
   bool_t linkState;

   //Read status register
   value = pef7071ReadPhyReg(interface, PEF7071_STAT);
   //Retrieve current link state
   linkState = (value & PEF7071_STAT_LS) ? TRUE : FALSE;

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


/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void pef7071EnableIrq(NetInterface *interface)
{
}


/**
 * @brief Disable interrupts
 * @param[in] interface Underlying network interface
 **/

void pef7071DisableIrq(NetInterface *interface)
{
}


/**
 * @brief PEF7071 event handler
 * @param[in] interface Underlying network interface
 **/

void pef7071EventHandler(NetInterface *interface)
{
   uint16_t status;

   //Read status register
   status = pef7071ReadPhyReg(interface, PEF7071_STAT);

   //Link is up?
   if((status & PEF7071_STAT_LS) != 0)
   {
      //Read MII status register
      status = pef7071ReadPhyReg(interface, PEF7071_MIISTAT);

      //Check current speed
      switch(status & PEF7071_MIISTAT_SPEED)
      {
      //10BASE-T
      case PEF7071_MIISTAT_SPEED_TEN:
         interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
         break;
      //100BASE-TX
      case PEF7071_MIISTAT_SPEED_FAST:
         interface->linkSpeed = NIC_LINK_SPEED_100MBPS;
         break;
      //1000BASE-T
      case PEF7071_MIISTAT_SPEED_GIGA:
         interface->linkSpeed = NIC_LINK_SPEED_1GBPS;
         break;
      //Unknown speed
      default:
         //Debug message
         TRACE_WARNING("Invalid speed\r\n");
         break;
      }

      //Check current duplex mode
      if((status & PEF7071_MIISTAT_DPX) != 0)
      {
         interface->duplexMode = NIC_FULL_DUPLEX_MODE;
      }
      else
      {
         interface->duplexMode = NIC_HALF_DUPLEX_MODE;
      }

      //Update link state
      interface->linkState = TRUE;

      //Adjust MAC configuration parameters for proper operation
      interface->nicDriver->updateMacConfig(interface);
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

void pef7071WritePhyReg(NetInterface *interface, uint8_t address,
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

uint16_t pef7071ReadPhyReg(NetInterface *interface, uint8_t address)
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

void pef7071DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         pef7071ReadPhyReg(interface, i));
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

void pef7071WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   pef7071WritePhyReg(interface, PEF7071_MMDCTRL,
      PEF7071_MMDCTRL_ACTYPE_ADDR | (devAddr & PEF7071_MMDCTRL_DEVAD));

   //Write MMD register address
   pef7071WritePhyReg(interface, PEF7071_MMDDATA, regAddr);

   //Select data operation
   pef7071WritePhyReg(interface, PEF7071_MMDCTRL,
      PEF7071_MMDCTRL_ACTYPE_DATA | (devAddr & PEF7071_MMDCTRL_DEVAD));

   //Write the content of the MMD register
   pef7071WritePhyReg(interface, PEF7071_MMDDATA, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t pef7071ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   pef7071WritePhyReg(interface, PEF7071_MMDCTRL,
      PEF7071_MMDCTRL_ACTYPE_ADDR | (devAddr & PEF7071_MMDCTRL_DEVAD));

   //Write MMD register address
   pef7071WritePhyReg(interface, PEF7071_MMDDATA, regAddr);

   //Select data operation
   pef7071WritePhyReg(interface, PEF7071_MMDCTRL,
      PEF7071_MMDCTRL_ACTYPE_DATA | (devAddr & PEF7071_MMDCTRL_DEVAD));

   //Read the content of the MMD register
   return pef7071ReadPhyReg(interface, PEF7071_MMDDATA);
}
