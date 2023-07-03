/**
 * @file tc3xx_eth_driver.c
 * @brief Infineon AURIX TriCore TC3xx Ethernet MAC driver
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
#include "drivers/mac/tc3xx_eth_driver.h"
#include "debug.h"

//Underlying network interface
static NetInterface *nicDriverInterface;

//Tasking compiler?
#if defined(__TASKING__)

//Transmit buffer
static uint8_t txBuffer[TC3XX_ETH_TX_BUFFER_COUNT][TC3XX_ETH_TX_BUFFER_SIZE]
   __align(4);
//Receive buffer
static uint8_t rxBuffer[TC3XX_ETH_RX_BUFFER_COUNT][TC3XX_ETH_RX_BUFFER_SIZE]
   __align(4);
//Transmit DMA descriptors
static Tc3xxTxDmaDesc txDmaDesc[TC3XX_ETH_TX_BUFFER_COUNT]
   __align(4);
//Receive DMA descriptors
static Tc3xxRxDmaDesc rxDmaDesc[TC3XX_ETH_RX_BUFFER_COUNT]
  __align(4);

//GCC compiler?
#else

//Transmit buffer
static uint8_t txBuffer[TC3XX_ETH_TX_BUFFER_COUNT][TC3XX_ETH_TX_BUFFER_SIZE]
   __attribute__((aligned(4)));
//Receive buffer
static uint8_t rxBuffer[TC3XX_ETH_RX_BUFFER_COUNT][TC3XX_ETH_RX_BUFFER_SIZE]
   __attribute__((aligned(4)));
//Transmit DMA descriptors
static Tc3xxTxDmaDesc txDmaDesc[TC3XX_ETH_TX_BUFFER_COUNT]
   __attribute__((aligned(4)));
//Receive DMA descriptors
static Tc3xxRxDmaDesc rxDmaDesc[TC3XX_ETH_RX_BUFFER_COUNT]
   __attribute__((aligned(4)));

#endif

//Current transmit descriptor
static uint_t txIndex;
//Current receive descriptor
static uint_t rxIndex;


/**
 * @brief TC3xx Ethernet MAC driver
 **/

const NicDriver tc3xxEthDriver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   tc3xxEthInit,
   tc3xxEthTick,
   tc3xxEthEnableIrq,
   tc3xxEthDisableIrq,
   tc3xxEthEventHandler,
   tc3xxEthSendPacket,
   tc3xxEthUpdateMacAddrFilter,
   tc3xxEthUpdateMacConfig,
   tc3xxEthWritePhyReg,
   tc3xxEthReadPhyReg,
   TRUE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief TC3xx Ethernet MAC initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc3xxEthInit(NetInterface *interface)
{
   error_t error;
   Ifx_SCU_CCUCON5 ccucon5;

   //Debug message
   TRACE_INFO("Initializing TC3xx Ethernet MAC...\r\n");

   //Save underlying network interface
   nicDriverInterface = interface;

   //The lock bit indicates if the CCUCON5 register can be updated with a new
   //value
   while (SCU_CCUCON5.B.LCK != 0)
   {
   }

   //Unlock sequence
   unlock_safety_wdtcon();

   //Set GETH frequency divider
   ccucon5.U = SCU_CCUCON5.U;
   ccucon5.B.GETHDIV = 2;
   ccucon5.B.UP = 1;
   SCU_CCUCON5.U = ccucon5.U;

   //Lock sequence
   lock_safety_wdtcon();

   //The lock bit is released when the update is complete
   while (SCU_CCUCON5.B.LCK != 0)
   {
   }

   //Unlock sequence
   unlock_wdtcon();
   //Enable Ethernet module
   MODULE_GETH.CLC.B.DISR = 0;
   //Lock sequence
   lock_wdtcon();

   //GPIO configuration
   tc3xxEthInitGpio(interface);

   //Unlock sequence
   unlock_wdtcon();
   //Perform kernel reset
   MODULE_GETH.KRST0.B.RST = 1;
   MODULE_GETH.KRST1.B.RST = 1;
   //Lock sequence
   lock_wdtcon();

   //Wait for the reset to complete
   while(MODULE_GETH.KRST0.B.RSTSTAT == 0)
   {
   }

   //Unlock sequence
   unlock_wdtcon();
   //Clear kernel reset status
   MODULE_GETH.KRSTCLR.B.CLR = 1;
   //Lock sequence
   lock_wdtcon();

   //Perform a software reset
   MODULE_GETH.DMA_MODE.B.SWR = 1;
   //Wait for the reset to complete
   while(MODULE_GETH.DMA_MODE.B.SWR)
   {
   }

   //Adjust MDC clock range depending on CSR clock frequency
   MODULE_GETH.MAC_MDIO_ADDRESS.B.CR = 5;

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
   MODULE_GETH.MAC_CONFIGURATION.U = 0;
   MODULE_GETH.MAC_CONFIGURATION.B.PS = 1;
   MODULE_GETH.MAC_CONFIGURATION.B.DO = 1;

   //Set the MAC address of the station
   MODULE_GETH.MAC_ADDRESS_LOW0.U = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   MODULE_GETH.MAC_ADDRESS_HIGH0.U = interface->macAddr.w[2];

   //Configure the receive filter
   MODULE_GETH.MAC_PACKET_FILTER.U = 0;

   //Disable flow control
   MODULE_GETH.MAC_Q0_TX_FLOW_CTRL.U = 0;
   MODULE_GETH.MAC_RX_FLOW_CTRL.U = 0;

   //Enable the first RX queue
   MODULE_GETH.MAC_RXQ_CTRL0.B.RXQ0EN = 1;

   //Configure DMA operating mode
   MODULE_GETH.DMA_MODE.B.INTM = 0;
   MODULE_GETH.DMA_MODE.B.PR = 0;

   //Configure system bus mode
   MODULE_GETH.DMA_SYSBUS_MODE.B.AAL = 1;

   //The DMA takes the descriptor table as contiguous
   MODULE_GETH.DMA_CH[0].CONTROL.B.DSL = 0;
   //Configure TX features
   MODULE_GETH.DMA_CH[0].TX_CONTROL.B.TXPBL = 1;

   //Configure RX features
   MODULE_GETH.DMA_CH[0].RX_CONTROL.B.RXPBL = 1;
   MODULE_GETH.DMA_CH[0].RX_CONTROL.B.RBSZ_13_Y = TC3XX_ETH_RX_BUFFER_SIZE / 4;

   //Enable store and forward mode for transmission
   MODULE_GETH.MTL_TXQ0.OPERATION_MODE.B.TQS = 7;
   MODULE_GETH.MTL_TXQ0.OPERATION_MODE.B.TXQEN = 2;
   MODULE_GETH.MTL_TXQ0.OPERATION_MODE.B.TSF = 1;

   //Enable store and forward mode for reception
   MODULE_GETH.MTL_RXQ0.OPERATION_MODE.B.RQS = 7;
   MODULE_GETH.MTL_RXQ0.OPERATION_MODE.B.RSF = 1;

   //Initialize DMA descriptor lists
   tc3xxEthInitDmaDesc(interface);

   //Disable all MMC counters
   MODULE_GETH.MMC_CONTROL.B.CNTFREEZ = 1;

   //Disable MAC interrupts
   MODULE_GETH.MAC_INTERRUPT_ENABLE.U = 0;

   //Enable the desired DMA interrupts
   MODULE_GETH.DMA_CH[0].INTERRUPT_ENABLE.B.TIE = 1;
   MODULE_GETH.DMA_CH[0].INTERRUPT_ENABLE.B.RIE = 1;
   MODULE_GETH.DMA_CH[0].INTERRUPT_ENABLE.B.NIE = 1;

   //Register interrupt handler
   InterruptInstall(SRC_ID_GETH0, tc3xxEthIrqHandler, TC3XX_ETH_IRQ_PRIORITY, 0);

   //Enable MAC transmission and reception
   MODULE_GETH.MAC_CONFIGURATION.B.TE = 1;
   MODULE_GETH.MAC_CONFIGURATION.B.RE = 1;

   //Enable DMA transmission and reception
   MODULE_GETH.DMA_CH[0].TX_CONTROL.B.ST = 1;
   MODULE_GETH.DMA_CH[0].RX_CONTROL.B.SR = 1;

   //Accept any packets from the upper layer
   osSetEvent(&interface->nicTxEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief GPIO configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void tc3xxEthInitGpio(NetInterface *interface)
{
//AURIX TC397 TFT Application Kit?
#if defined(USE_KIT_A2G_TC397_TFT)
   //Configure GETH_TXD3 (P11.0)
   MODULE_P11.IOCR0.B.PC0 = 22;

   //Configure GETH_TXD2 (P11.1)
   MODULE_P11.IOCR0.B.PC1 = 22;

   //Configure GETH_TXD1 (P11.2)
   MODULE_P11.IOCR0.B.PC2 = 22;

   //Configure GETH_TXD0 (P11.3)
   MODULE_P11.IOCR0.B.PC3 = 22;

   //Configure GETH_TXCLK (P11.4)
   MODULE_P11.IOCR4.B.PC4 = 23;

   //Configure GETH_GREFCLK (P11.5)
   MODULE_P11.IOCR4.B.PC5 = 0;

   //Configure GETH_TCTL (P11.6)
   MODULE_P11.IOCR4.B.PC6 = 22;

   //Configure GETH_RXD3A (P11.7)
   MODULE_P11.IOCR4.B.PC7 = 0;
   MODULE_GETH.GPCTL.B.ALTI9 = 0;

   //Configure GETH_RXD2A (P11.8)
   MODULE_P11.IOCR8.B.PC8 = 0;
   MODULE_GETH.GPCTL.B.ALTI8 = 0;

   //Configure GETH_RXD1A (P11.9)
   MODULE_P11.IOCR8.B.PC9 = 0;
   MODULE_GETH.GPCTL.B.ALTI7 = 0;

   //Configure GETH_RXD0A (P11.10)
   MODULE_P11.IOCR8.B.PC10 = 0;
   MODULE_GETH.GPCTL.B.ALTI6 = 0;

   //Configure GETH_RCTLA (P11.11)
   MODULE_P11.IOCR8.B.PC11 = 0;
   MODULE_GETH.GPCTL.B.ALTI4 = 0;

   //Configure GETH_RXCLKA (P11.12)
   MODULE_P11.IOCR12.B.PC12 = 0;
   MODULE_GETH.GPCTL.B.ALTI1 = 0;

   //Configure GETH_MDC (P12.0)
   MODULE_P12.IOCR0.B.PC0 = 22;

   //Configure GETH_MDIOC (P12.1)
   MODULE_P12.IOCR0.B.PC1 = 0;
   MODULE_GETH.GPCTL.B.ALTI0 = 2;

   //Unlock sequence
   unlock_safety_wdtcon();

   //Set bit SELx for TXD[3:0] TXCLK and TCTL signals
   MODULE_P11.PCSR.B.SEL0 = 1;
   MODULE_P11.PCSR.B.SEL1 = 1;
   MODULE_P11.PCSR.B.SEL2 = 1;
   MODULE_P11.PCSR.B.SEL3 = 1;
   MODULE_P11.PCSR.B.SEL4 = 1;
   MODULE_P11.PCSR.B.SEL6 = 1;

   //Lock sequence
   lock_safety_wdtcon();

   //Unlock sequence
   unlock_wdtcon();

   //Set speed grade
   MODULE_P11.PDR0.B.PD0 = 3;
   MODULE_P11.PDR0.B.PL0 = 0;
   MODULE_P11.PDR0.B.PD1 = 3;
   MODULE_P11.PDR0.B.PL1 = 0;
   MODULE_P11.PDR0.B.PD2 = 3;
   MODULE_P11.PDR0.B.PL2 = 0;
   MODULE_P11.PDR0.B.PD3 = 3;
   MODULE_P11.PDR0.B.PL3 = 0;
   MODULE_P11.PDR0.B.PD4 = 3;
   MODULE_P11.PDR0.B.PL4 = 0;
   MODULE_P11.PDR0.B.PD5 = 3;
   MODULE_P11.PDR0.B.PL5 = 0;
   MODULE_P11.PDR0.B.PD6 = 3;
   MODULE_P11.PDR0.B.PL6 = 0;
   MODULE_P11.PDR0.B.PD7 = 3;
   MODULE_P11.PDR0.B.PL7 = 0;
   MODULE_P11.PDR1.B.PD8 = 3;
   MODULE_P11.PDR1.B.PL8 = 0;
   MODULE_P11.PDR1.B.PD9 = 3;
   MODULE_P11.PDR1.B.PL9 = 0;
   MODULE_P11.PDR1.B.PD10 = 3;
   MODULE_P11.PDR1.B.PL10 = 0;
   MODULE_P11.PDR1.B.PD11 = 3;
   MODULE_P11.PDR1.B.PL11 = 0;
   MODULE_P11.PDR1.B.PD12 = 3;
   MODULE_P11.PDR1.B.PL12 = 0;

   MODULE_P12.PDR0.B.PD0 = 3;
   MODULE_P12.PDR0.B.PL0 = 0;
   MODULE_P12.PDR0.B.PD1 = 3;
   MODULE_P12.PDR0.B.PL1 = 0;

   //Lock sequence
   lock_wdtcon();

   //Select RGMII operation mode
   MODULE_GETH.GPCTL.B.EPR = 1;

   //Set delay for RGMII TX and RX clocks
   MODULE_GETH.SKEWCTL.B.TXCFG = 5;
   MODULE_GETH.SKEWCTL.B.RXCFG = 5;
#endif
}


/**
 * @brief Initialize DMA descriptor lists
 * @param[in] interface Underlying network interface
 **/

void tc3xxEthInitDmaDesc(NetInterface *interface)
{
   uint_t i;

   //Initialize TX DMA descriptor list
   for(i = 0; i < TC3XX_ETH_TX_BUFFER_COUNT; i++)
   {
      //The descriptor is initially owned by the application
      txDmaDesc[i].tdes0 = 0;
      txDmaDesc[i].tdes1 = 0;
      txDmaDesc[i].tdes2 = 0;
      txDmaDesc[i].tdes3 = 0;
   }

   //Initialize TX descriptor index
   txIndex = 0;

   //Initialize RX DMA descriptor list
   for(i = 0; i < TC3XX_ETH_RX_BUFFER_COUNT; i++)
   {
      //The descriptor is initially owned by the DMA
      rxDmaDesc[i].rdes0 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(rxBuffer[i]);
      rxDmaDesc[i].rdes1 = 0;
      rxDmaDesc[i].rdes2 = 0;
      rxDmaDesc[i].rdes3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
   }

   //Initialize RX descriptor index
   rxIndex = 0;

   //Start location of the TX descriptor list
   MODULE_GETH.DMA_CH[0].TXDESC_LIST_ADDRESS.U = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&txDmaDesc[0]);
   //Length of the transmit descriptor ring
   MODULE_GETH.DMA_CH[0].TXDESC_RING_LENGTH.U = TC3XX_ETH_TX_BUFFER_COUNT - 1;

   //Start location of the RX descriptor list
   MODULE_GETH.DMA_CH[0].RXDESC_LIST_ADDRESS.U = (uint32_t) ETH_GLOBAL_DSPR_ADDR(&rxDmaDesc[0]);
   //Length of the receive descriptor ring
   MODULE_GETH.DMA_CH[0].RXDESC_RING_LENGTH.U = TC3XX_ETH_RX_BUFFER_COUNT - 1;
}


/**
 * @brief TC3xx Ethernet MAC timer handler
 *
 * This routine is periodically called by the TCP/IP stack to handle periodic
 * operations such as polling the link state
 *
 * @param[in] interface Underlying network interface
 **/

void tc3xxEthTick(NetInterface *interface)
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

void tc3xxEthEnableIrq(NetInterface *interface)
{
   //Enable Ethernet MAC interrupts
   InterruptEnable(SRC_ID_GETH0);

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

void tc3xxEthDisableIrq(NetInterface *interface)
{
   //Enable Ethernet MAC interrupts
   InterruptDisable(SRC_ID_GETH0);

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
 * @brief TC3xx Ethernet MAC interrupt service routine
 * @param arg Unused parameter
 **/

void tc3xxEthIrqHandler(int_t arg)
{
   bool_t flag;
   uint32_t status;

   //Interrupt service routine prologue
   osEnterIsr();

   //This flag will be set if a higher priority task must be woken
   flag = FALSE;

   //Read DMA status register
   status = MODULE_GETH.DMA_CH[0].STATUS.U;

   //Packet transmitted?
   if((status & ETH_DMA_CH_STATUS_TI) != 0)
   {
      //Clear TI interrupt flag
      MODULE_GETH.DMA_CH[0].STATUS.U = ETH_DMA_CH_STATUS_TI;

      //Check whether the TX buffer is available for writing
      if((txDmaDesc[txIndex].tdes3 & ETH_TDES3_OWN) == 0)
      {
         //Notify the TCP/IP stack that the transmitter is ready to send
         flag |= osSetEventFromIsr(&nicDriverInterface->nicTxEvent);
      }
   }

   //Packet received?
   if((status & ETH_DMA_CH_STATUS_RI) != 0)
   {
      //Disable RIE interrupt
      MODULE_GETH.DMA_CH[0].INTERRUPT_ENABLE.B.RIE = 0;

      //Set event flag
      nicDriverInterface->nicEvent = TRUE;
      //Notify the TCP/IP stack of the event
      flag |= osSetEventFromIsr(&netEvent);
   }

   //Clear NIS interrupt flag
   MODULE_GETH.DMA_CH[0].STATUS.U = ETH_DMA_CH_STATUS_NIS;

   //Interrupt service routine epilogue
   osExitIsr(flag);
}


/**
 * @brief TC3xx Ethernet MAC event handler
 * @param[in] interface Underlying network interface
 **/

void tc3xxEthEventHandler(NetInterface *interface)
{
   error_t error;

   //Packet received?
   if((MODULE_GETH.DMA_CH[0].STATUS.U & ETH_DMA_CH_STATUS_RI) != 0)
   {
      //Clear interrupt flag
      MODULE_GETH.DMA_CH[0].STATUS.U = ETH_DMA_CH_STATUS_RI;

      //Process all pending packets
      do
      {
         //Read incoming packet
         error = tc3xxEthReceivePacket(interface);

         //No more data in the receive buffer?
      } while(error != ERROR_BUFFER_EMPTY);
   }

   //Re-enable DMA interrupts
   MODULE_GETH.DMA_CH[0].INTERRUPT_ENABLE.U = ETH_DMA_CH_INTERRUPT_ENABLE_NIE |
      ETH_DMA_CH_INTERRUPT_ENABLE_RIE | ETH_DMA_CH_INTERRUPT_ENABLE_TIE;
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

error_t tc3xxEthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary)
{
   size_t length;

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

   //Check the frame length
   if(length > TC3XX_ETH_TX_BUFFER_SIZE)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Make sure the current buffer is available for writing
   if((txDmaDesc[txIndex].tdes3 & ETH_TDES3_OWN) != 0)
   {
      return ERROR_FAILURE;
   }

   //Copy user data to the transmit buffer
   netBufferRead(txBuffer[txIndex], buffer, offset, length);

   //Set the start address of the buffer
   txDmaDesc[txIndex].tdes0 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(txBuffer[txIndex]);
   //Write the number of bytes to send
   txDmaDesc[txIndex].tdes2 = ETH_TDES2_IOC | (length & ETH_TDES2_B1L);
   //Give the ownership of the descriptor to the DMA
   txDmaDesc[txIndex].tdes3 = ETH_TDES3_OWN | ETH_TDES3_FD | ETH_TDES3_LD;

   //Clear TBU flag to resume processing
   MODULE_GETH.DMA_CH[0].STATUS.U = ETH_DMA_CH_STATUS_TBU;
   //Instruct the DMA to poll the transmit descriptor list
   MODULE_GETH.DMA_CH[0].TXDESC_TAIL_POINTER.U = 0;

   //Increment index and wrap around if necessary
   if(txIndex < (TC3XX_ETH_TX_BUFFER_COUNT - 1))
   {
      txIndex++;
   }
   else
   {
      txIndex = 0;
   }

   //Check whether the next buffer is available for writing
   if((txDmaDesc[txIndex].tdes3 & ETH_TDES3_OWN) == 0)
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

error_t tc3xxEthReceivePacket(NetInterface *interface)
{
   error_t error;
   size_t n;
   NetRxAncillary ancillary;

   //Current buffer available for reading?
   if((rxDmaDesc[rxIndex].rdes3 & ETH_RDES3_OWN) == 0)
   {
      //FD and LD flags should be set
      if((rxDmaDesc[rxIndex].rdes3 & ETH_RDES3_FD) != 0 &&
         (rxDmaDesc[rxIndex].rdes3 & ETH_RDES3_LD) != 0)
      {
         //Make sure no error occurred
         if((rxDmaDesc[rxIndex].rdes3 & ETH_RDES3_ES) == 0)
         {
            //Retrieve the length of the frame
            n = rxDmaDesc[rxIndex].rdes3 & ETH_RDES3_PL;
            //Limit the number of data to read
            n = MIN(n, TC3XX_ETH_RX_BUFFER_SIZE);

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

      //Set the start address of the buffer
      rxDmaDesc[rxIndex].rdes0 = (uint32_t) ETH_GLOBAL_DSPR_ADDR(rxBuffer[rxIndex]);
      //Give the ownership of the descriptor back to the DMA
      rxDmaDesc[rxIndex].rdes3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;

      //Increment index and wrap around if necessary
      if(rxIndex < (TC3XX_ETH_RX_BUFFER_COUNT - 1))
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

   //Clear RBU flag to resume processing
   MODULE_GETH.DMA_CH[0].STATUS.U = ETH_DMA_CH_STATUS_RBU;
   //Instruct the DMA to poll the receive descriptor list
   MODULE_GETH.DMA_CH[0].RXDESC_TAIL_POINTER.U = 0;

   //Return status code
   return error;
}


/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc3xxEthUpdateMacAddrFilter(NetInterface *interface)
{
   uint_t i;
   bool_t acceptMulticast;

   //Debug message
   TRACE_DEBUG("Updating MAC filter...\r\n");

   //Set the MAC address of the station
   MODULE_GETH.MAC_ADDRESS_LOW0.U = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   MODULE_GETH.MAC_ADDRESS_HIGH0.U = interface->macAddr.w[2];

   //This flag will be set if multicast addresses should be accepted
   acceptMulticast = FALSE;

   //The MAC address filter contains the list of MAC addresses to accept
   //when receiving an Ethernet frame
   for(i = 0; i < MAC_ADDR_FILTER_SIZE; i++)
   {
      //Valid entry?
      if(interface->macAddrFilter[i].refCount > 0)
      {
         //Accept multicast addresses
         acceptMulticast = TRUE;
         //We are done
         break;
      }
   }

   //Enable or disable the reception of multicast frames
   if(acceptMulticast)
   {
      MODULE_GETH.MAC_PACKET_FILTER.B.PM = 1;
   }
   else
   {
      MODULE_GETH.MAC_PACKET_FILTER.B.PM = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Adjust MAC configuration parameters for proper operation
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t tc3xxEthUpdateMacConfig(NetInterface *interface)
{
   Ifx_GETH_MAC_CONFIGURATION config;

   //Read current MAC configuration
   config.U = MODULE_GETH.MAC_CONFIGURATION.U;

   //1000BASE-T operation mode?
   if(interface->linkSpeed == NIC_LINK_SPEED_1GBPS)
   {
      config.B.PS = 0;
      config.B.FES = 0;
   }
   //100BASE-TX operation mode?
   else if(interface->linkSpeed == NIC_LINK_SPEED_100MBPS)
   {
      config.B.PS = 1;
      config.B.FES = 1;
   }
   //10BASE-T operation mode?
   else
   {
      config.B.PS = 1;
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
   MODULE_GETH.MAC_CONFIGURATION.U = config.U;

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

void tc3xxEthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data)
{
   //Valid opcode?
   if(opcode == SMI_OPCODE_WRITE)
   {
      //Set up a write operation
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GOC_0 = 1;
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GOC_1 = 0;

      //PHY address
      MODULE_GETH.MAC_MDIO_ADDRESS.B.PA = phyAddr;
      //Register address
      MODULE_GETH.MAC_MDIO_ADDRESS.B.RDA = regAddr;

      //Data to be written in the PHY register
      MODULE_GETH.MAC_MDIO_DATA.B.GD = data;

      //Start a write operation
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GB = 1;
      //Wait for the write to complete
      while(MODULE_GETH.MAC_MDIO_ADDRESS.B.GB)
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

uint16_t tc3xxEthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr)
{
   uint16_t data;

   //Valid opcode?
   if(opcode == SMI_OPCODE_READ)
   {
      //Set up a read operation
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GOC_0 = 1;
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GOC_1 = 1;

      //PHY address
      MODULE_GETH.MAC_MDIO_ADDRESS.B.PA = phyAddr;
      //Register address
      MODULE_GETH.MAC_MDIO_ADDRESS.B.RDA = regAddr;

      //Start a read operation
      MODULE_GETH.MAC_MDIO_ADDRESS.B.GB = 1;
      //Wait for the read to complete
      while(MODULE_GETH.MAC_MDIO_ADDRESS.B.GB)
      {
      }

      //Get register value
      data = MODULE_GETH.MAC_MDIO_DATA.B.GD;
   }
   else
   {
      //The MAC peripheral only supports standard Clause 22 opcodes
      data = 0;
   }

   //Return the value of the PHY register
   return data;
}
