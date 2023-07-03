/**
 * @file dp83867_driver.c
 * @brief DP83867 Gigabit Ethernet PHY driver
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
#include "drivers/phy/dp83867_driver.h"
#include "debug.h"


/**
 * @brief DP83867 Ethernet PHY driver
 **/

const PhyDriver dp83867PhyDriver =
{
   dp83867Init,
   dp83867Tick,
   dp83867EnableIrq,
   dp83867DisableIrq,
   dp83867EventHandler
};


/**
 * @brief DP83867 PHY transceiver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t dp83867Init(NetInterface *interface)
{
   uint16_t temp;

   //Debug message
   TRACE_INFO("Initializing DP83867...\r\n");

   //Undefined PHY address?
   if(interface->phyAddr >= 32)
   {
      //Use the default address
      interface->phyAddr = DP83867_PHY_ADDR;
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
   dp83867WritePhyReg(interface, DP83867_BMCR, DP83867_BMCR_RESET);

   //Wait for the reset to complete
   while(dp83867ReadPhyReg(interface, DP83867_BMCR) & DP83867_BMCR_RESET)
   {
   }

   //Dump PHY registers for debugging purpose
   dp83867DumpPhyReg(interface);

   //Set RGMII TX and RX clock delays
   dp83867WriteMmdReg(interface, DP83867_RGMIIDCTL,
      DP83867_RGMIIDCTL_RGMII_TX_DELAY_CTRL_1_50NS |
      DP83867_RGMIIDCTL_RGMII_RX_DELAY_CTRL_2_00NS);

   //Enable shift mode
   temp = dp83867ReadMmdReg(interface, DP83867_RGMIICTL);
   temp |= DP83867_RGMIICTL_RGMII_TX_CLK_DELAY;
   temp |= DP83867_RGMIICTL_RGMII_RX_CLK_DELAY;
   dp83867WriteMmdReg(interface, DP83867_RGMIICTL, temp);

   //Set GPIO mux control
   dp83867WriteMmdReg(interface, DP83867_GPIO_MUX_CTRL,
      DP83867_GPIO_MUX_CTRL_GPIO_0_CTRL_LED_3 |
      DP83867_GPIO_MUX_CTRL_GPIO_1_CTRL_CONST_0);

   //Set LED mode
   dp83867WritePhyReg(interface, DP83867_LEDCR1,
      DP83867_LEDCR1_LED_0_SEL_LINK | DP83867_LEDCR1_LED_1_SEL_1000 |
      DP83867_LEDCR1_LED_2_SEL_ACT | DP83867_LEDCR1_LED_GPIO_SEL_10_100);

   //Configure INTN/PWDNN pin as an interrupt output
   dp83867WritePhyReg(interface, DP83867_CFG3, DP83867_CFG3_INT_OE);

   //The PHY will generate interrupts when link status changes are detected
   dp83867WritePhyReg(interface, DP83867_MICR,
      DP83867_MICR_LINK_STATUS_CHNG_INT_EN);

   //Perform custom configuration
   dp83867InitHook(interface);

   //Force the TCP/IP stack to poll the link state at startup
   interface->phyEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief DP83867 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void dp83867InitHook(NetInterface *interface)
{
}


/**
 * @brief DP83867 timer handler
 * @param[in] interface Underlying network interface
 **/

void dp83867Tick(NetInterface *interface)
{
   uint16_t value;
   bool_t linkState;

   //No external interrupt line driver?
   if(interface->extIntDriver == NULL)
   {
      //Read basic status register
      value = dp83867ReadPhyReg(interface, DP83867_BMSR);
      //Retrieve current link state
      linkState = (value & DP83867_BMSR_LINK_STATUS) ? TRUE : FALSE;

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

void dp83867EnableIrq(NetInterface *interface)
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

void dp83867DisableIrq(NetInterface *interface)
{
   //Disable PHY transceiver interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief DP83867 event handler
 * @param[in] interface Underlying network interface
 **/

void dp83867EventHandler(NetInterface *interface)
{
   uint16_t status;

   //Read status register to acknowledge the interrupt
   status = dp83867ReadPhyReg(interface, DP83867_MISR);

   //Link status change?
   if((status & DP83867_MISR_LINK_STATUS_CHNG_INT) != 0)
   {
      //Read PHY status register
      status = dp83867ReadPhyReg(interface, DP83867_PHYSTS);

      //Link is up?
      if((status & DP83867_PHYSTS_LINK_STATUS) != 0)
      {
         //Check current speed
         switch(status & DP83867_PHYSTS_SPEED_SEL)
         {
         //10BASE-T
         case DP83867_PHYSTS_SPEED_SEL_10MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
            break;
         //100BASE-TX
         case DP83867_PHYSTS_SPEED_SEL_100MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_100MBPS;
            break;
         //1000BASE-T
         case DP83867_PHYSTS_SPEED_SEL_1000MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_1GBPS;
            break;
         //Unknown speed
         default:
            //Debug message
            TRACE_WARNING("Invalid speed\r\n");
            break;
         }

         //Check duplex mode
         if((status & DP83867_PHYSTS_DUPLEX_MODE) != 0)
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
}


/**
 * @brief Write PHY register
 * @param[in] interface Underlying network interface
 * @param[in] address PHY register address
 * @param[in] data Register value
 **/

void dp83867WritePhyReg(NetInterface *interface, uint8_t address,
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

uint16_t dp83867ReadPhyReg(NetInterface *interface, uint8_t address)
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

void dp83867DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         dp83867ReadPhyReg(interface, i));
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

void dp83867WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   dp83867WritePhyReg(interface, DP83867_REGCR,
      DP83867_REGCR_FUNC_ADDR | (devAddr & DP83867_REGCR_DEVAD));

   //Write MMD register address
   dp83867WritePhyReg(interface, DP83867_ADDAR, regAddr);

   //Select data operation
   dp83867WritePhyReg(interface, DP83867_REGCR,
      DP83867_REGCR_FUNC_DATA_NO_POST_INC | (devAddr & DP83867_REGCR_DEVAD));

   //Write the content of the MMD register
   dp83867WritePhyReg(interface, DP83867_ADDAR, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t dp83867ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   dp83867WritePhyReg(interface, DP83867_REGCR,
      DP83867_REGCR_FUNC_ADDR | (devAddr & DP83867_REGCR_DEVAD));

   //Write MMD register address
   dp83867WritePhyReg(interface, DP83867_ADDAR, regAddr);

   //Select data operation
   dp83867WritePhyReg(interface, DP83867_REGCR,
      DP83867_REGCR_FUNC_DATA_NO_POST_INC | (devAddr & DP83867_REGCR_DEVAD));

   //Read the content of the MMD register
   return dp83867ReadPhyReg(interface, DP83867_ADDAR);
}
