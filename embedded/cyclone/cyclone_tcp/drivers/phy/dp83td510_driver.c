/**
 * @file dp83td510_driver.c
 * @brief DP83TD510 10Base-T1L Ethernet PHY driver
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
#include "drivers/phy/dp83td510_driver.h"
#include "debug.h"


/**
 * @brief DP83TD510 Ethernet PHY driver
 **/

const PhyDriver dp83td510PhyDriver =
{
   dp83td510Init,
   dp83td510Tick,
   dp83td510EnableIrq,
   dp83td510DisableIrq,
   dp83td510EventHandler
};


/**
 * @brief DP83TD510 PHY transceiver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t dp83td510Init(NetInterface *interface)
{
   //Debug message
   TRACE_INFO("Initializing DP83TD510...\r\n");

   //Undefined PHY address?
   if(interface->phyAddr >= 32)
   {
      //Use the default address
      interface->phyAddr = DP83TD510_PHY_ADDR;
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
   dp83td510WritePhyReg(interface, DP83TD510_MII_REG_0,
      DP83TD510_MII_REG_0_MII_RESET);

   //Wait for the reset to complete
   while(dp83td510ReadPhyReg(interface, DP83TD510_MII_REG_0) &
      DP83TD510_MII_REG_0_MII_RESET)
   {
   }

   //Errata
   dp83td510WriteMmdReg(interface, 0x1F, 0x0608, 0x003B);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0862, 0x39F8);
   dp83td510WriteMmdReg(interface, 0x1F, 0x081A, 0x67C0);
   dp83td510WriteMmdReg(interface, 0x1F, 0x081C, 0xFB62);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0830, 0x05A3);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0855, 0x1B55);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0831, 0x0403);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0856, 0x1800);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0857, 0x8FA0);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0871, 0x000C);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0883, 0x022E);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0402, 0x1800);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0878, 0x2248);
   dp83td510WriteMmdReg(interface, 0x1F, 0x010C, 0x0008);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0112, 0x1212);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0809, 0x5C80);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0803, 0x1529);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0804, 0x1A33);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0805, 0x1F3D);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0850, 0x045B);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0874, 0x6967);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0852, 0x7800);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0806, 0x1E1E);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0807, 0x2525);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0808, 0x2C2C);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0850, 0x0590);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0827, 0x4000);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0849, 0x0FE4);
   dp83td510WriteMmdReg(interface, 0x1F, 0x084B, 0x04B5);
   dp83td510WriteMmdReg(interface, 0x1F, 0x0018, 0x0043);

   //Restart auto-negotiation
   dp83td510WriteMmdReg(interface, DP83TD510_AN_CONTROL,
      DP83TD510_AN_CONTROL_MR_AN_ENABLE | DP83TD510_AN_CONTROL_MR_RESTART_AN);

   //Dump PHY registers for debugging purpose
   dp83td510DumpPhyReg(interface);

   //Perform custom configuration
   dp83td510InitHook(interface);

   //Force the TCP/IP stack to poll the link state at startup
   interface->phyEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief DP83TD510 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void dp83td510InitHook(NetInterface *interface)
{
}


/**
 * @brief DP83TD510 timer handler
 * @param[in] interface Underlying network interface
 **/

void dp83td510Tick(NetInterface *interface)
{
   uint16_t value;
   bool_t linkState;

   //No external interrupt line driver?
   if(interface->extIntDriver == NULL)
   {
      //Read PHY status register
      value = dp83td510ReadPhyReg(interface, DP83TD510_PHY_STS);
      //Retrieve current link state
      linkState = (value & DP83TD510_PHY_STS_LINK_STATUS) ? TRUE : FALSE;

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

void dp83td510EnableIrq(NetInterface *interface)
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

void dp83td510DisableIrq(NetInterface *interface)
{
   //Disable PHY transceiver interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief DP83TD510 event handler
 * @param[in] interface Underlying network interface
 **/

void dp83td510EventHandler(NetInterface *interface)
{
   uint16_t value;

   //Read PHY status register
   value = dp83td510ReadPhyReg(interface, DP83TD510_PHY_STS);

   //Link is up?
   if((value & DP83TD510_PHY_STS_LINK_STATUS) != 0)
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

void dp83td510WritePhyReg(NetInterface *interface, uint8_t address,
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

uint16_t dp83td510ReadPhyReg(NetInterface *interface, uint8_t address)
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

void dp83td510DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         dp83td510ReadPhyReg(interface, i));
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

void dp83td510WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   dp83td510WritePhyReg(interface, DP83TD510_REGCR,
      DP83TD510_REGCR_CMD_ADDR | (devAddr & DP83TD510_REGCR_DEVAD));

   //Write MMD register address
   dp83td510WritePhyReg(interface, DP83TD510_ADDAR, regAddr);

   //Select data operation
   dp83td510WritePhyReg(interface, DP83TD510_REGCR,
      DP83TD510_REGCR_CMD_DATA_NO_POST_INC | (devAddr & DP83TD510_REGCR_DEVAD));

   //Write the content of the MMD register
   dp83td510WritePhyReg(interface, DP83TD510_ADDAR, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t dp83td510ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   dp83td510WritePhyReg(interface, DP83TD510_REGCR,
      DP83TD510_REGCR_CMD_ADDR | (devAddr & DP83TD510_REGCR_DEVAD));

   //Write MMD register address
   dp83td510WritePhyReg(interface, DP83TD510_ADDAR, regAddr);

   //Select data operation
   dp83td510WritePhyReg(interface, DP83TD510_REGCR,
      DP83TD510_REGCR_CMD_DATA_NO_POST_INC | (devAddr & DP83TD510_REGCR_DEVAD));

   //Read the content of the MMD register
   return dp83td510ReadPhyReg(interface, DP83TD510_ADDAR);
}
