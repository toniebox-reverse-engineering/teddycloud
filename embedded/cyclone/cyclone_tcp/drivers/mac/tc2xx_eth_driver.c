/**
 * @file tc2xx_eth_driver.c
 * @brief Infineon AURIX TriCore TC2xx Ethernet MAC driver
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
#include <machine/intrinsics.h>
#include <machine/wdtcon.h>
#include "tc_inc_path.h"
#include TC_INCLUDE(TCPATH/Ifx_reg.h)
#include TC_INCLUDE(TCPATH/IfxCpu_bf.h)
#include "interrupts.h"
#include "core/net.h"
#include "drivers/mac/tc2xx_eth_driver.h"
#include "debug.h"

//Underlying network interface
static NetInterface *nicDriverInterface;

//Tasking compiler?
#if defined(__TASKING__)

//Transmit buffer
static uint8_t txBuffer[TC2XX_ETH_TX_BUFFER_COUNT][TC2XX_ETH_TX_BUFFER_SIZE]
   __align(4);
//Receive buffer
static uint8_t rxBuffer[TC2XX_ETH_RX_BUFFER_COUNT][TC2XX_ETH_RX_BUFFER_SIZE]
   __align(4);
//Transmit DMA descriptors
static Tc2xxTxDmaDesc txDmaDesc[TC2XX_ETH_TX_BUFFER_COUNT]
   __align(4);
//Receive DMA descriptors
static Tc2xxRxDmaDesc rxDmaDesc[TC2XX_ETH_RX_BUFFER_COUNT]
  __align(4);

//GCC compiler?
#else

//Transmit buffer
static uint8_t txBuffer[TC2XX_ETH_TX_BUFFER_COUNT][TC2XX_ETH_TX_BUFFER_SIZE]
   __attribute__((aligned(4)));
//Receive buffer
static uint8_t rxBuffer[TC2XX_ETH_RX_BUFFER_COUNT][TC2XX_ETH_RX_BUFFER_SIZE]
   __attribute__((aligned(4)));
//Transmit DMA descriptors
static Tc2xxTxDmaDesc txDmaDesc[TC2XX_ETH_TX_BUFFER_COUNT]
   __attribute__((aligned(4)));
//Receive DMA descriptors
static Tc2xxRxDmaDesc rxDmaDesc[TC2XX_ETH_RX_BUFFER_COUNT]
   __attribute__((aligned(4)));

#endif

//Current transmit descriptor
static uint_t txIndex;
//Current receive descriptor
static uint_t rxIndex;


/**
 * @brief TC2xx Ethernet MAC driver
 **/

const NicDriver tc2xxEthDriver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   tc2xxEthInit,
   tc2xxEthTick,
   tc2xxEthEnableIrq,
   tc2xxEthDisableIrq,
   tc2xxEthEventHandler,
   tc2xxEthSendPacket,
   tc2xxEthUpdateMacAddrFilter,
   tc2xxEthUpdateMacConfig,
   tc2xxEthWritePhyReg,
   tc2xxEthReadPhyReg,
   TRUE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief TC2xx Ethernet MAC initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc2xxEthInit(NetInterface *interface)
{
   error_t error;
   uint_t i;

   //Debug message
   TRACE_INFO("Initializing TC2xx Ethernet MAC...\r\n");

   //Save underlying network interface
   nicDriverInterface = interface;

   //Unlock sequence
   unlock_wdtcon();
   //Enable Ethernet module
   MODULE_ETH.CLC.U = 0;
   //Lock sequence
   lock_wdtcon();

   //GPIO configuration
   tc2xxEthInitGpio(interface);

   //Unlock sequence
   unlock_wdtcon();
   //Perform kernel reset
   MODULE_ETH.KRST0.B.RST = 1;
   MODULE_ETH.KRST1.B.RST = 1;
   //Lock sequence
   lock_wdtcon();

   //Wait for the reset to complete
   while(MODULE_ETH.KRST0.B.RSTSTAT == 0)
   {
   }

   //Unlock sequence
   unlock_wdtcon();
   //Clear kernel reset status
   MODULE_ETH.KRSTCLR.B.CLR = 1;
   //Lock sequence
   lock_wdtcon();

   //Perform a software reset
   MODULE_ETH.BUS_MODE.B.SWR = 1;
   //Wait for the reset to complete
   while(MODULE_ETH.BUS_MODE.B.SWR)
   {
   }

   //Adjust MDC clock range depending on CSR clock frequency
   MODULE_ETH.GMII_ADDRESS.B.CR = 4;

   //Valid Ethernet PHY or switch driver?
   if(interface->phyDriver != NULL)
   {
      //Ethernet PHY initialization
      error = interface->phyDriver->init(interface);
   }
   else if(interface->switchDriver != NULL)
   {
      //Ethernet switch initialization
      error = interface->switchDriver->init(interface);
   }
   else
   {
      //The interface is not properly configured
      error = ERROR_FAILURE;
   }

   //Any error to report?
   if(error)
   {
      return error;
   }

   //Use default MAC configuration
   MODULE_ETH.MAC_CONFIGURATION.U = 0;
   MODULE_ETH.MAC_CONFIGURATION.B.PS = 1;
   MODULE_ETH.MAC_CONFIGURATION.B.DO = 1;

   //Set the MAC address of the station
   MODULE_ETH.MAC_ADDRESS_G0[0].LOW.U = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   MODULE_ETH.MAC_ADDRESS_G0[0].HIGH.U = interface->macAddr.w[2];

   //The MAC supports 15 additional addresses for unicast perfect filtering
   for(i = 1; i < 16; i++)
   {
      MODULE_ETH.MAC_ADDRESS_G0[i].LOW.U = 0;
      MODULE_ETH.MAC_ADDRESS_G0[i].HIGH.U = 0;
   }

   //Initialize hash table
   MODULE_ETH.HASH_TABLE_LOW.U = 0;
   MODULE_ETH.HASH_TABLE_HIGH.U = 0;

   //Configure the receive filter
   MODULE_ETH.MAC_FRAME_FILTER.U = 0;
   MODULE_ETH.MAC_FRAME_FILTER.B.HPF = 1;
   MODULE_ETH.MAC_FRAME_FILTER.B.HMC = 1;

   //Disable flow control
   MODULE_ETH.FLOW_CONTROL.U = 0;

   //Enable store and forward mode
   MODULE_ETH.OPERATION_MODE.U = 0;
   MODULE_ETH.OPERATION_MODE.B.RSF = 1;
   MODULE_ETH.OPERATION_MODE.B.TSF = 1;

   //Configure DMA bus mode
   MODULE_ETH.BUS_MODE.U = 0;
   MODULE_ETH.BUS_MODE.B.PRWG = 0;
   MODULE_ETH.BUS_MODE.B.TXPR = 0;
   MODULE_ETH.BUS_MODE.B.MB = 0;
   MODULE_ETH.BUS_MODE.B.AAL = 1;
   MODULE_ETH.BUS_MODE.B.PBLx8 = 0;
   MODULE_ETH.BUS_MODE.B.USP = 1;
   MODULE_ETH.BUS_MODE.B.RPBL = 1;
   MODULE_ETH.BUS_MODE.B.FB = 0;
   MODULE_ETH.BUS_MODE.B.PR = 0;
   MODULE_ETH.BUS_MODE.B.PBL = 1;
   MODULE_ETH.BUS_MODE.B.ATDS = 1;
   MODULE_ETH.BUS_MODE.B.DSL = 0;
   MODULE_ETH.BUS_MODE.B.DA = 0;

   //Initialize DMA descriptor lists
   tc2xxEthInitDmaDesc(interface);

   //Disable all MMC counters
   MODULE_ETH.MMC_CONTROL.B.CNTFREEZ = 1;

   //Disable MAC interrupts
   MODULE_ETH.INTERRUPT_MASK.B.LPIIM = 1;
   MODULE_ETH.INTERRUPT_MASK.B.TSIM = 1;
   MODULE_ETH.INTERRUPT_MASK.B.PMTIM = 1;
   MODULE_ETH.INTERRUPT_MASK.B.PCSANCIM = 1;
   MODULE_ETH.INTERRUPT_MASK.B.PCSLCHGIM = 1;
   MODULE_ETH.INTERRUPT_MASK.B.RGSMIIIM = 1;

   //Enable the desired DMA interrupts
   MODULE_ETH.INTERRUPT_ENABLE.B.TIE = 1;
   MODULE_ETH.INTERRUPT_ENABLE.B.RIE = 1;
   MODULE_ETH.INTERRUPT_ENABLE.B.NIE = 1;

   //Register interrupt handler
   InterruptInstall(SRC_ID_ETH, tc2xxEthIrqHandler, TC2XX_ETH_IRQ_PRIORITY, 0);

   //Enable MAC transmission and reception
   MODULE_ETH.MAC_CONFIGURATION.B.TE = 1;
   MODULE_ETH.MAC_CONFIGURATION.B.RE = 1;

   //Enable DMA transmission and reception
   MODULE_ETH.OPERATION_MODE.B.ST = 1;
   MODULE_ETH.OPERATION_MODE.B.SR = 1;

   //Accept any packets from the upper layer
   osSetEvent(&interface->nicTxEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief GPIO configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void tc2xxEthInitGpio(NetInterface *interface)
{
//AURIX TC265 Starter Kit?
#if defined(USE_KIT_AURIX_TC265_TRB)
   //Configure ETHTXD1 (P11.2)
   MODULE_P11.IOCR0.B.PC2 = 22;

   //Configure ETHTXD0 (P11.3)
   MODULE_P11.IOCR0.B.PC3 = 22;

   //Configure ETHTXEN (P11.6)
   MODULE_P11.IOCR4.B.PC6 = 22;

   //Configure ETHRXD1 (P11.9)
   MODULE_P11.IOCR8.B.PC9 = 0;
   MODULE_ETH.GPCTL.B.ALTI7 = 0;

   //Configure ETHRXD0 (P11.10)
   MODULE_P11.IOCR8.B.PC10 = 0;
   MODULE_ETH.GPCTL.B.ALTI6 = 0;

   //Configure ETHCRSDVA (P11.11)
   MODULE_P11.IOCR8.B.PC11 = 0;
   MODULE_ETH.GPCTL.B.ALTI4 = 0;

   //Configure ETHRXCLKA (P11.12)
   MODULE_P11.IOCR12.B.PC12 = 0;
   MODULE_ETH.GPCTL.B.ALTI1 = 0;

   //Configure ETHMDC (P21.0)
   MODULE_P21.IOCR0.B.PC0 = 22;

   //Configure ETHMDIOB (P21.1)
   MODULE_P21.IOCR0.B.PC1 = 22;
   MODULE_ETH.GPCTL.B.ALTI0 = 1;

   //Unlock sequence
   unlock_safety_wdtcon();

   //Select Ethernet output signals through fast RMII mode
   MODULE_P11.PCSR.B.SEL2 = 1;
   MODULE_P11.PCSR.B.SEL3 = 1;
   MODULE_P11.PCSR.B.SEL6 = 1;

   //Lock sequence
   lock_safety_wdtcon();

   //Unlock sequence
   unlock_wdtcon();

   //Set speed grade
   MODULE_P11.PDR0.B.PD2 = 0;
   MODULE_P11.PDR0.B.PL2 = 0;
   MODULE_P11.PDR0.B.PD3 = 0;
   MODULE_P11.PDR0.B.PL3 = 0;
   MODULE_P11.PDR0.B.PD6 = 0;
   MODULE_P11.PDR0.B.PL6 = 0;

   MODULE_P11.PDR1.B.PD9 = 0;
   MODULE_P11.PDR1.B.PL9 = 0;
   MODULE_P11.PDR1.B.PD10 = 0;
   MODULE_P11.PDR1.B.PL10 = 0;
   MODULE_P11.PDR1.B.PD11 = 0;
   MODULE_P11.PDR1.B.PL11 = 0;
   MODULE_P11.PDR1.B.PD12 = 0;
   MODULE_P11.PDR1.B.PL12 = 0;

   MODULE_P21.PDR0.B.PD0 = 0;
   MODULE_P21.PDR0.B.PL0 = 0;
   MODULE_P21.PDR0.B.PD1 = 3;
   MODULE_P21.PDR0.B.PL1 = 0;

   //Lock sequence
   lock_wdtcon();

   //Select RMII operation mode
   MODULE_ETH.GPCTL.B.EPR = 1;

//AURIX TC277 TFT Application Kit or AURIX TC297 TFT Application Kit?
#elif defined(USE_KIT_AURIX_TC277_TFT) || defined(USE_KIT_AURIX_TC297_TFT)
   //Configure ETHTXD1 (P11.2)
   MODULE_P11.IOCR0.B.PC2 = 22;

   //Configure ETHTXD0 (P11.3)
   MODULE_P11.IOCR0.B.PC3 = 22;

   //Configure ETHTXEN (P11.6)
   MODULE_P11.IOCR4.B.PC6 = 22;

   //Configure ETHRXD1 (P11.9)
   MODULE_P11.IOCR8.B.PC9 = 0;
   MODULE_ETH.GPCTL.B.ALTI7 = 0;

   //Configure ETHRXD0 (P11.10)
   MODULE_P11.IOCR8.B.PC10 = 0;
   MODULE_ETH.GPCTL.B.ALTI6 = 0;

   //Configure ETHCRSDVA (P11.11)
   MODULE_P11.IOCR8.B.PC11 = 0;
   MODULE_ETH.GPCTL.B.ALTI4 = 0;

   //Configure ETHRXCLKA (P11.12)
   MODULE_P11.IOCR12.B.PC12 = 0;
   MODULE_ETH.GPCTL.B.ALTI1 = 0;

   //Configure ETHMDC (P21.2)
   MODULE_P21.IOCR0.B.PC2 = 21;

   //Configure ETHMDIOD (P21.3)
   MODULE_P21.IOCR0.B.PC3 = 0;
   MODULE_ETH.GPCTL.B.ALTI0 = 3;

   //Unlock sequence
   unlock_safety_wdtcon();

   //Select Ethernet output signals through fast RMII mode
   MODULE_P11.PCSR.B.SEL2 = 1;
   MODULE_P11.PCSR.B.SEL3 = 1;
   MODULE_P11.PCSR.B.SEL6 = 1;

   //Lock sequence
   lock_safety_wdtcon();

   //Unlock sequence
   unlock_wdtcon();

   //Set speed grade
   MODULE_P11.PDR0.B.PD2 = 0;
   MODULE_P11.PDR0.B.PL2 = 0;
   MODULE_P11.PDR0.B.PD3 = 0;
   MODULE_P11.PDR0.B.PL3 = 0;
   MODULE_P11.PDR0.B.PD6 = 0;
   MODULE_P11.PDR0.B.PL6 = 0;

   MODULE_P11.PDR1.B.PD9 = 0;
   MODULE_P11.PDR1.B.PL9 = 0;
   MODULE_P11.PDR1.B.PD10 = 0;
   MODULE_P11.PDR1.B.PL10 = 0;
   MODULE_P11.PDR1.B.PD11 = 0;
   MODULE_P11.PDR1.B.PL11 = 0;
   MODULE_P11.PDR1.B.PD12 = 0;
   MODULE_P11.PDR1.B.PL12 = 0;

   MODULE_P21.PDR0.B.PD2 = 0;
   MODULE_P21.PDR0.B.PL2 = 0;
   MODULE_P21.PDR0.B.PD3 = 0;
   MODULE_P21.PDR0.B.PL3 = 0;

   //Lock sequence
   lock_wdtcon();

   //Select RMII operation mode
   MODULE_ETH.GPCTL.B.EPR = 1;
#endif
}


/**
 * @brief Initialize DMA descriptor lists
 * @param[in] interface Underlying network interface
 **/

void tc2xxEthInitDmaDesc(NetInterface *interface)
{
   uint_t i;

   //Initialize TX DMA descriptor list
   for(i = 0; i < TC2XX_ETH_TX_BUFFER_COUNT; i++)
   {
      //Use chain structure rather than ring structure
      txDmaDesc[i].tdes0 = ETH_TDES0_IC | ETH_TDES0_TCH;
      //Initialize transmit buffer size
      txDmaDesc[i].tdes1 = 0;
      //Transmit buffer address
      txDmaDesc[i].tdes2 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(txBuffer[i]);
      //Next descriptor address
      txDmaDesc[i].tdes3 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&txDmaDesc[i + 1]);
      //Reserved fields
      txDmaDesc[i].tdes4 = 0;
      txDmaDesc[i].tdes5 = 0;
      //Transmit frame time stamp
      txDmaDesc[i].tdes6 = 0;
      txDmaDesc[i].tdes7 = 0;
   }

   //The last descriptor is chained to the first entry
   txDmaDesc[i - 1].tdes3 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&txDmaDesc[0]);
   //Point to the very first descriptor
   txIndex = 0;

   //Initialize RX DMA descriptor list
   for(i = 0; i < TC2XX_ETH_RX_BUFFER_COUNT; i++)
   {
      //The descriptor is initially owned by the DMA
      rxDmaDesc[i].rdes0 = ETH_RDES0_OWN;
      //Use chain structure rather than ring structure
      rxDmaDesc[i].rdes1 = ETH_RDES1_RCH | (TC2XX_ETH_RX_BUFFER_SIZE & ETH_RDES1_RBS1);
      //Receive buffer address
      rxDmaDesc[i].rdes2 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(rxBuffer[i]);
      //Next descriptor address
      rxDmaDesc[i].rdes3 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&rxDmaDesc[i + 1]);
      //Extended status
      rxDmaDesc[i].rdes4 = 0;
      //Reserved field
      rxDmaDesc[i].rdes5 = 0;
      //Receive frame time stamp
      rxDmaDesc[i].rdes6 = 0;
      rxDmaDesc[i].rdes7 = 0;
   }

   //The last descriptor is chained to the first entry
   rxDmaDesc[i - 1].rdes3 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&rxDmaDesc[0]);
   //Point to the very first descriptor
   rxIndex = 0;

   //Start location of the TX descriptor list
   MODULE_ETH.TRANSMIT_DESCRIPTOR_LIST_ADDRESS.U = (uint32_t) ETH_GLOBAL_DSPR_ADDR(txDmaDesc);
   //Start location of the RX descriptor list
   MODULE_ETH.RECEIVE_DESCRIPTOR_LIST_ADDRESS.U = (uint32_t) ETH_GLOBAL_DSPR_ADDR(rxDmaDesc);
}


/**
 * @brief TC2xx Ethernet MAC timer handler
 *
 * This routine is periodically called by the TCP/IP stack to handle periodic
 * operations such as polling the link state
 *
 * @param[in] interface Underlying network interface
 **/

void tc2xxEthTick(NetInterface *interface)
{
   //Valid Ethernet PHY or switch driver?
   if(interface->phyDriver != NULL)
   {
      //Handle periodic operations
      interface->phyDriver->tick(interface);
   }
   else if(interface->switchDriver != NULL)
   {
      //Handle periodic operations
      interface->switchDriver->tick(interface);
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void tc2xxEthEnableIrq(NetInterface *interface)
{
   //Enable Ethernet MAC interrupts
   InterruptEnable(SRC_ID_ETH);

   //Valid Ethernet PHY or switch driver?
   if(interface->phyDriver != NULL)
   {
      //Enable Ethernet PHY interrupts
      interface->phyDriver->enableIrq(interface);
   }
   else if(interface->switchDriver != NULL)
   {
      //Enable Ethernet switch interrupts
      interface->switchDriver->enableIrq(interface);
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Disable interrupts
 * @param[in] interface Underlying network interface
 **/

void tc2xxEthDisableIrq(NetInterface *interface)
{
   //Enable Ethernet MAC interrupts
   InterruptDisable(SRC_ID_ETH);

   //Valid Ethernet PHY or switch driver?
   if(interface->phyDriver != NULL)
   {
      //Disable Ethernet PHY interrupts
      interface->phyDriver->disableIrq(interface);
   }
   else if(interface->switchDriver != NULL)
   {
      //Disable Ethernet switch interrupts
      interface->switchDriver->disableIrq(interface);
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief TC2xx Ethernet MAC interrupt service routine
 * @param arg Unused parameter
 **/

void tc2xxEthIrqHandler(int_t arg)
{
   bool_t flag;
   uint32_t status;

   //Interrupt service routine prologue
   osEnterIsr();

   //This flag will be set if a higher priority task must be woken
   flag = FALSE;

   //Read DMA status register
   status = MODULE_ETH.STATUS.U;

   //Packet transmitted?
   if((status & ETH_STATUS_TI) != 0)
   {
      //Clear TI interrupt flag
      MODULE_ETH.STATUS.U = ETH_STATUS_TI;

      //Check whether the TX buffer is available for writing
      if((txDmaDesc[txIndex].tdes0 & ETH_TDES0_OWN) == 0)
      {
         //Notify the TCP/IP stack that the transmitter is ready to send
         flag |= osSetEventFromIsr(&nicDriverInterface->nicTxEvent);
      }
   }

   //Packet received?
   if((status & ETH_STATUS_RI) != 0)
   {
      //Clear RI interrupt flag
      MODULE_ETH.STATUS.U = ETH_STATUS_RI;

      //Set event flag
      nicDriverInterface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Clear NIS interrupt flag
   MODULE_ETH.STATUS.U = ETH_STATUS_NIS;

   //Interrupt service routine epilogue
   osExitIsr(flag);
}


/**
 * @brief TC2xx Ethernet MAC event handler
 * @param[in] interface Underlying network interface
 **/

void tc2xxEthEventHandler(NetInterface *interface)
{
   error_t error;

   //Process all pending packets
   do
   {
      //Read incoming packet
      error = tc2xxEthReceivePacket(interface);

      //No more data in the receive buffer?
   } while(error != ERROR_BUFFER_EMPTY);
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

error_t tc2xxEthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary)
{
   size_t length;

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

   //Check the frame length
   if(length > TC2XX_ETH_TX_BUFFER_SIZE)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Make sure the current buffer is available for writing
   if((txDmaDesc[txIndex].tdes0 & ETH_TDES0_OWN) != 0)
   {
      return ERROR_FAILURE;
   }

   //Copy user data to the transmit buffer
   netBufferRead(txBuffer[txIndex], buffer, offset, length);

   //Write the number of bytes to send
   txDmaDesc[txIndex].tdes1 = length & ETH_TDES1_TBS1;
   //Set LS and FS flags as the data fits in a single buffer
   txDmaDesc[txIndex].tdes0 |= ETH_TDES0_LS | ETH_TDES0_FS;
   //Give the ownership of the descriptor to the DMA
   txDmaDesc[txIndex].tdes0 |= ETH_TDES0_OWN;

   //Clear TU flag to resume processing
   MODULE_ETH.STATUS.U = ETH_STATUS_TU;
   //Instruct the DMA to poll the transmit descriptor list
   MODULE_ETH.TRANSMIT_POLL_DEMAND.U = 0;

   //Increment index and wrap around if necessary
   if(txIndex < (TC2XX_ETH_TX_BUFFER_COUNT - 1))
   {
      txIndex++;
   }
   else
   {
      txIndex = 0;
   }

   //Check whether the next buffer is available for writing
   if((txDmaDesc[txIndex].tdes0 & ETH_TDES0_OWN) == 0)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
   }

   //Data successfully written
   return NO_ERROR;
}


/**
 * @brief Receive a packet
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc2xxEthReceivePacket(NetInterface *interface)
{
   error_t error;
   size_t n;
   NetRxAncillary ancillary;

   //Current buffer available for reading?
   if((rxDmaDesc[rxIndex].rdes0 & ETH_RDES0_OWN) == 0)
   {
      //FS and LS flags should be set
      if((rxDmaDesc[rxIndex].rdes0 & ETH_RDES0_FS) != 0 &&
         (rxDmaDesc[rxIndex].rdes0 & ETH_RDES0_LS) != 0)
      {
         //Make sure no error occurred
         if((rxDmaDesc[rxIndex].rdes0 & ETH_RDES0_ES) == 0)
         {
            //Retrieve the length of the frame
            n = (rxDmaDesc[rxIndex].rdes0 & ETH_RDES0_FL) >> 16;
            //Limit the number of data to read
            n = MIN(n, TC2XX_ETH_RX_BUFFER_SIZE);

            //Additional options can be passed to the stack along with the packet
            ancillary = NET_DEFAULT_RX_ANCILLARY;

            //Pass the packet to the upper layer
            nicProcessPacket(interface, rxBuffer[rxIndex], n, &ancillary);

            //Valid packet received
            error = NO_ERROR;
         }
         else
         {
            //The received packet contains an error
            error = ERROR_INVALID_PACKET;
         }
      }
      else
      {
         //The packet is not valid
         error = ERROR_INVALID_PACKET;
      }

      //Give the ownership of the descriptor back to the DMA
      rxDmaDesc[rxIndex].rdes0 = ETH_RDES0_OWN;

      //Increment index and wrap around if necessary
      if(rxIndex < (TC2XX_ETH_RX_BUFFER_COUNT - 1))
      {
         rxIndex++;
      }
      else
      {
         rxIndex = 0;
      }
   }
   else
   {
      //No more data in the receive buffer
      error = ERROR_BUFFER_EMPTY;
   }

   //Clear RU flag to resume processing
   MODULE_ETH.STATUS.U = ETH_STATUS_RU;
   //Instruct the DMA to poll the receive descriptor list
   MODULE_ETH.RECEIVE_POLL_DEMAND.U = 0;

   //Return status code
   return error;
}


/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc2xxEthUpdateMacAddrFilter(NetInterface *interface)
{
   uint_t i;
   uint_t j;
   uint_t k;
   uint32_t crc;
   uint32_t hashTable[2];
   MacAddr unicastMacAddr[15];
   MacFilterEntry *entry;

   //Debug message
   TRACE_DEBUG("Updating MAC filter...\r\n");

   //Set the MAC address of the station
   MODULE_ETH.MAC_ADDRESS_G0[0].LOW.U = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   MODULE_ETH.MAC_ADDRESS_G0[0].HIGH.U = interface->macAddr.w[2];

   //The MAC supports 15 additional addresses for unicast perfect filtering
   for(i = 0; i < 15; i++)
   {
      unicastMacAddr[i] = MAC_UNSPECIFIED_ADDR;
   }

   //The hash table is used for multicast address filtering
   hashTable[0] = 0;
   hashTable[1] = 0;

   //The MAC address filter contains the list of MAC addresses to accept
   //when receiving an Ethernet frame
   for(i = 0, j = 0; i < MAC_ADDR_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->macAddrFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //Multicast address?
         if(macIsMulticastAddr(&entry->addr))
         {
            //Compute CRC over the current MAC address
            crc = tc2xxEthCalcCrc(&entry->addr, sizeof(MacAddr));

            //The upper 6 bits in the CRC register are used to index the
            //contents of the hash table
            k = (crc >> 26) & 0x3F;

            //Update hash table contents
            hashTable[k / 32] |= (1 << (k % 32));
         }
         else
         {
            //Up to 15 additional MAC addresses can be specified
            if(j < 15)
            {
               //Save the unicast address
               unicastMacAddr[j++] = entry->addr;
            }
         }
      }
   }

   //Configure the unicast address filter
   for(i = 0; i < 15; i++)
   {
      //Set current entry
      MODULE_ETH.MAC_ADDRESS_G0[i + 1].LOW.U = unicastMacAddr[0].w[0] | (unicastMacAddr[0].w[1] << 16);
      MODULE_ETH.MAC_ADDRESS_G0[i + 1].HIGH.U = unicastMacAddr[0].w[2];

      //When the AE bit is set, the entry is used for perfect filtering
      if(i < j)
      {
         MODULE_ETH.MAC_ADDRESS_G0[i + 1].HIGH.B.AE = 1;
      }
   }

   //Configure the multicast hash table
   MODULE_ETH.HASH_TABLE_LOW.U = hashTable[0];
   MODULE_ETH.HASH_TABLE_HIGH.U = hashTable[1];

   //Debug message
   TRACE_DEBUG("  HASH_TABLE_LOW = %08" PRIX32 "\r\n", MODULE_ETH.HASH_TABLE_LOW.U);
   TRACE_DEBUG("  HASH_TABLE_HIGH = %08" PRIX32 "\r\n", MODULE_ETH.HASH_TABLE_HIGH.U);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Adjust MAC configuration parameters for proper operation
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc2xxEthUpdateMacConfig(NetInterface *interface)
{
   Ifx_ETH_MAC_CONFIGURATION config;

   //Read current MAC configuration
   config.U = MODULE_ETH.MAC_CONFIGURATION.U;

   //10BASE-T or 100BASE-TX operation mode?
   if(interface->linkSpeed == NIC_LINK_SPEED_100MBPS)
   {
      config.B.FES = 1;
   }
   else
   {
      config.B.FES = 0;
   }

   //Half-duplex or full-duplex mode?
   if(interface->duplexMode == NIC_FULL_DUPLEX_MODE)
   {
      config.B.DM = 1;
   }
   else
   {
      config.B.DM = 0;
   }

   //Update MAC configuration register
   MODULE_ETH.MAC_CONFIGURATION.U = config.U;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write PHY register
 * @param[in] opcode Access type (2 bits)
 * @param[in] phyAddr PHY address (5 bits)
 * @param[in] regAddr Register address (5 bits)
 * @param[in] data Register value
 **/

void tc2xxEthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data)
{
   //Valid opcode?
   if(opcode == SMI_OPCODE_WRITE)
   {
      //Set up a write operation
      MODULE_ETH.GMII_ADDRESS.B.GW = 1;
      //PHY address
      MODULE_ETH.GMII_ADDRESS.B.PA = phyAddr;
      //Register address
      MODULE_ETH.GMII_ADDRESS.B.GR = regAddr;

      //Data to be written in the PHY register
      MODULE_ETH.GMII_DATA.B.GD = data;

      //Start a write operation
      MODULE_ETH.GMII_ADDRESS.B.GB = 1;
      //Wait for the write to complete
      while(MODULE_ETH.GMII_ADDRESS.B.GB)
      {
      }
   }
   else
   {
      //The MAC peripheral only supports standard Clause 22 opcodes
   }
}


/**
 * @brief Read PHY register
 * @param[in] opcode Access type (2 bits)
 * @param[in] phyAddr PHY address (5 bits)
 * @param[in] regAddr Register address (5 bits)
 * @return Register value
 **/

uint16_t tc2xxEthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr)
{
   uint16_t data;

   //Valid opcode?
   if(opcode == SMI_OPCODE_READ)
   {
      //Set up a read operation
      MODULE_ETH.GMII_ADDRESS.B.GW = 0;
      //PHY address
      MODULE_ETH.GMII_ADDRESS.B.PA = phyAddr;
      //Register address
      MODULE_ETH.GMII_ADDRESS.B.GR = regAddr;

      //Start a read operation
      MODULE_ETH.GMII_ADDRESS.B.GB = 1;
      //Wait for the read to complete
      while(MODULE_ETH.GMII_ADDRESS.B.GB)
      {
      }

      //Get register value
      data = MODULE_ETH.GMII_DATA.B.GD;
   }
   else
   {
      //The MAC peripheral only supports standard Clause 22 opcodes
      data = 0;
   }

   //Return the value of the PHY register
   return data;
}


/**
 * @brief CRC calculation
 * @param[in] data Pointer to the data over which to calculate the CRC
 * @param[in] length Number of bytes to process
 * @return Resulting CRC value
 **/

uint32_t tc2xxEthCalcCrc(const void *data, size_t length)
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
   return ~crc;
}
