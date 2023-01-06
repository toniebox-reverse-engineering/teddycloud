/**
 * @file dp83869_driver.c
 * @brief DP83869 Gigabit Ethernet PHY driver
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
#include "drivers/phy/dp83869_driver.h"
#include "debug.h"


/**
 * @brief DP83869 Ethernet PHY driver
 **/

const PhyDriver dp83869PhyDriver =
{
   dp83869Init,
   dp83869Tick,
   dp83869EnableIrq,
   dp83869DisableIrq,
   dp83869EventHandler
};


/**
 * @brief DP83869 PHY transceiver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t dp83869Init(NetInterface *interface)
{
   uint16_t temp;

   //Debug message
   TRACE_INFO("Initializing DP83869...\r\n");

   //Undefined PHY address?
   if(interface->phyAddr >= 32)
   {
      //Use the default address
      interface->phyAddr = DP83869_PHY_ADDR;
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
   dp83869WritePhyReg(interface, DP83869_BMCR, DP83869_BMCR_RESET);

   //Wait for the reset to complete
   while(dp83869ReadPhyReg(interface, DP83869_BMCR) & DP83869_BMCR_RESET)
   {
   }

   //Dump PHY registers for debugging purpose
   dp83869DumpPhyReg(interface);

   //Set RGMII TX and RX clock delays
   dp83869WriteMmdReg(interface, DP83869_ANA_RGMII_DLL_CTRL,
      DP83869_ANA_RGMII_DLL_CTRL_DLL_TX_DELAY_CTRL_SL_1_50NS |
      DP83869_ANA_RGMII_DLL_CTRL_DLL_RX_DELAY_CTRL_SL_2_00NS);

   //Enable shift mode
   temp = dp83869ReadMmdReg(interface, DP83869_RGMII_CTRL);
   temp |= DP83869_RGMII_CTRL_RGMII_TX_CLK_DELAY;
   temp |= DP83869_RGMII_CTRL_RGMII_RX_CLK_DELAY;
   dp83869WriteMmdReg(interface, DP83869_RGMII_CTRL, temp);

   //Set GPIO mux control
   dp83869WriteMmdReg(interface, DP83869_GPIO_MUX_CTRL,
      DP83869_GPIO_MUX_CTRL_LED_2_GPIO_0_CTRL_LED_2 |
      DP83869_GPIO_MUX_CTRL_JTAG_TDO_GPIO_1_CTRL_LED_3);

   //Set LED mode
   dp83869WritePhyReg(interface, DP83869_LEDS_CFG1,
      DP83869_LEDS_CFG1_LED_0_SEL_LINK | DP83869_LEDS_CFG1_LED_1_SEL_1000 |
      DP83869_LEDS_CFG1_LED_2_SEL_ACT | DP83869_LEDS_CFG1_LED_GPIO_SEL_10_100);

   //Configure INTN/PWDNN pin as an interrupt output
   dp83869WritePhyReg(interface, DP83869_GEN_CFG4, DP83869_GEN_CFG4_INT_OE);

   //The PHY will generate interrupts when link status changes are detected
   dp83869WritePhyReg(interface, DP83869_INTERRUPT_MASK,
      DP83869_INTERRUPT_MASK_LINK_STATUS_CHNG_INT_EN);

   //Perform custom configuration
   dp83869InitHook(interface);

   //Force the TCP/IP stack to poll the link state at startup
   interface->phyEvent = TRUE;
   //Notify the TCP/IP stack of the event
   osSetEvent(&netEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief DP83869 custom configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void dp83869InitHook(NetInterface *interface)
{
}


/**
 * @brief DP83869 timer handler
 * @param[in] interface Underlying network interface
 **/

void dp83869Tick(NetInterface *interface)
{
   uint16_t value;
   bool_t linkState;

   //No external interrupt line driver?
   if(interface->extIntDriver == NULL)
   {
      //Read basic status register
      value = dp83869ReadPhyReg(interface, DP83869_BMSR);
      //Retrieve current link state
      linkState = (value & DP83869_BMSR_LINK_STS1) ? TRUE : FALSE;

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

void dp83869EnableIrq(NetInterface *interface)
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

void dp83869DisableIrq(NetInterface *interface)
{
   //Disable PHY transceiver interrupts
   if(interface->extIntDriver != NULL)
   {
      interface->extIntDriver->disableIrq();
   }
}


/**
 * @brief DP83869 event handler
 * @param[in] interface Underlying network interface
 **/

void dp83869EventHandler(NetInterface *interface)
{
   uint16_t status;

   //Read status register to acknowledge the interrupt
   status = dp83869ReadPhyReg(interface, DP83869_INTERRUPT_STATUS);

   //Link status change?
   if((status & DP83869_INTERRUPT_STATUS_LINK_STATUS_CHNG) != 0)
   {
      //Read PHY status register
      status = dp83869ReadPhyReg(interface, DP83869_PHY_STATUS);

      //Link is up?
      if((status & DP83869_PHY_STATUS_LINK_STATUS_2) != 0)
      {
         //Check current speed
         switch(status & DP83869_PHY_STATUS_SPEED_SEL)
         {
         //10BASE-T
         case DP83869_PHY_STATUS_SPEED_SEL_10MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_10MBPS;
            break;
         //100BASE-TX
         case DP83869_PHY_STATUS_SPEED_SEL_100MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_100MBPS;
            break;
         //1000BASE-T
         case DP83869_PHY_STATUS_SPEED_SEL_1000MBPS:
            interface->linkSpeed = NIC_LINK_SPEED_1GBPS;
            break;
         //Unknown speed
         default:
            //Debug message
            TRACE_WARNING("Invalid speed\r\n");
            break;
         }

         //Check duplex mode
         if((status & DP83869_PHY_STATUS_DUPLEX_MODE_ENV) != 0)
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

void dp83869WritePhyReg(NetInterface *interface, uint8_t address,
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

uint16_t dp83869ReadPhyReg(NetInterface *interface, uint8_t address)
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

void dp83869DumpPhyReg(NetInterface *interface)
{
   uint8_t i;

   //Loop through PHY registers
   for(i = 0; i < 32; i++)
   {
      //Display current PHY register
      TRACE_DEBUG("%02" PRIu8 ": 0x%04" PRIX16 "\r\n", i,
         dp83869ReadPhyReg(interface, i));
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

void dp83869WriteMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr, uint16_t data)
{
   //Select register operation
   dp83869WritePhyReg(interface, DP83869_REGCR,
      DP83869_REGCR_FUNC_ADDR | (devAddr & DP83869_REGCR_DEVAD));

   //Write MMD register address
   dp83869WritePhyReg(interface, DP83869_ADDAR, regAddr);

   //Select data operation
   dp83869WritePhyReg(interface, DP83869_REGCR,
      DP83869_REGCR_FUNC_DATA_NO_POST_INC | (devAddr & DP83869_REGCR_DEVAD));

   //Write the content of the MMD register
   dp83869WritePhyReg(interface, DP83869_ADDAR, data);
}


/**
 * @brief Read MMD register
 * @param[in] interface Underlying network interface
 * @param[in] devAddr Device address
 * @param[in] regAddr Register address
 * @return MMD register value
 **/

uint16_t dp83869ReadMmdReg(NetInterface *interface, uint8_t devAddr,
   uint16_t regAddr)
{
   //Select register operation
   dp83869WritePhyReg(interface, DP83869_REGCR,
      DP83869_REGCR_FUNC_ADDR | (devAddr & DP83869_REGCR_DEVAD));

   //Write MMD register address
   dp83869WritePhyReg(interface, DP83869_ADDAR, regAddr);

   //Select data operation
   dp83869WritePhyReg(interface, DP83869_REGCR,
      DP83869_REGCR_FUNC_DATA_NO_POST_INC | (devAddr & DP83869_REGCR_DEVAD));

   //Read the content of the MMD register
   return dp83869ReadPhyReg(interface, DP83869_ADDAR);
}
