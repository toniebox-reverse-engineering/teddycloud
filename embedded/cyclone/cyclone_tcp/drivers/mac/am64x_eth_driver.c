/**
 * @file am64x_eth_driver.c
 * @brief AM64x Ethernet MAC driver
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
#include <hw_include/csl_cpswitch.h>
#include <kernel/dpl/AddrTranslateP.h>
#include <drivers/pinmux.h>
#include <drivers/udma/udma_priv.h>
#include <networking/enet/utils/include/enet_apputils.h>
#include <networking/enet/utils/include/enet_appmemutils.h>
#include <networking/enet/utils/include/enet_appmemutils_cfg.h>
#include "core/net.h"
#include "drivers/mac/am64x_eth_driver.h"
#include "debug.h"

//MDIO input clock frequency
#define MDIO_INPUT_CLK 250000000
//MDIO output clock frequency
#define MDIO_OUTPUT_CLK 1000000

//Underlying network interface (port 1)
static NetInterface *nicDriverInterface1 = NULL;
//Underlying network interface (port 2)
static NetInterface *nicDriverInterface2 = NULL;

//TX DMA handle
static EnetDma_TxChHandle txChHandle = NULL;
//RX DMA handle
static EnetDma_RxChHandle rxChHandle = NULL;

//TX packet queue
static EnetDma_PktQ txFreePacketQueue;
//RX packet queue
static EnetDma_PktQ rxFreePacketQueue;


/**
 * @brief AM64x Ethernet MAC driver (port1)
 **/

const NicDriver am64xEthPort1Driver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   am64xEthInitPort1,
   am64xEthTick,
   am64xEthEnableIrq,
   am64xEthDisableIrq,
   am64xEthEventHandler,
   am64xEthSendPacket,
   am64xEthUpdateMacAddrFilter,
   am64xEthUpdateMacConfig,
   am64xEthWritePhyReg,
   am64xEthReadPhyReg,
   FALSE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief AM64x Ethernet MAC driver (port2)
 **/

const NicDriver am64xEthPort2Driver =
{
   NIC_TYPE_ETHERNET,
   ETH_MTU,
   am64xEthInitPort2,
   am64xEthTick,
   am64xEthEnableIrq,
   am64xEthDisableIrq,
   am64xEthEventHandler,
   am64xEthSendPacket,
   am64xEthUpdateMacAddrFilter,
   am64xEthUpdateMacConfig,
   am64xEthWritePhyReg,
   am64xEthReadPhyReg,
   FALSE,
   TRUE,
   TRUE,
   FALSE
};


/**
 * @brief AM64x Ethernet MAC initialization (port 1)
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t am64xEthInitPort1(NetInterface *interface)
{
   error_t error;
   uint32_t temp;
   volatile CSL_Xge_cpswRegs *ctrlRegs;
   volatile CSL_AleRegs *aleRegs;
   volatile CSL_main_ctrl_mmr_cfg0Regs *mmrRegs;

   //Debug message
   TRACE_INFO("Initializing AM64x Ethernet MAC (port 1)...\r\n");

   //Initialize CPSW instance
   am64xEthInitInstance(interface);

   //Save underlying network interface
   nicDriverInterface1 = interface;

   //PHY transceiver initialization
   error = interface->phyDriver->init(interface);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Unspecified MAC address?
   if(macCompAddr(&interface->macAddr, &MAC_UNSPECIFIED_ADDR))
   {
      //Point to the CTRL_MMR0 registers
      mmrRegs = (volatile CSL_main_ctrl_mmr_cfg0Regs *) CSL_CTRL_MMR0_CFG0_BASE;

      //Use the factory preprogrammed MAC address
      interface->macAddr.b[0] = (mmrRegs->MAC_ID1 >> 8) & 0xFF;
      interface->macAddr.b[1] = mmrRegs->MAC_ID1 & 0xFF;
      interface->macAddr.b[2] = (mmrRegs->MAC_ID0 >> 24) & 0xFF;
      interface->macAddr.b[3] = (mmrRegs->MAC_ID0 >> 16) & 0xFF;
      interface->macAddr.b[4] = (mmrRegs->MAC_ID0 >> 8) & 0xFF;
      interface->macAddr.b[5] = mmrRegs->MAC_ID0 & 0xFF;

      //Generate the 64-bit interface identifier
      macAddrToEui64(&interface->macAddr, &interface->eui64);
   }

   //Point to the CPSW0_CONTROL registers
   ctrlRegs = (volatile CSL_Xge_cpswRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_NU_OFFSET);
   //Point to the CPSW0_ALE registers
   aleRegs = (volatile CSL_AleRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_ALE_OFFSET);

   //Set CMD_IDLE bit to 1 in the port control register
   ctrlRegs->ENETPORT[0].PN_MAC_CONTROL_REG |= CSL_XGE_CPSW_PN_MAC_CONTROL_REG_CMD_IDLE_MASK;

   //Wait for IDLE bit to be set to 1 in the port status register
   while((ctrlRegs->ENETPORT[0].PN_MAC_STATUS_REG & CSL_XGE_CPSW_PN_MAC_STATUS_REG_IDLE_MASK) == 0)
   {
   }

   //Set SOFT_RESET bit to 1 in the port software reset register
   ctrlRegs->ENETPORT[0].PN_MAC_SOFT_RESET_REG |= CSL_XGE_CPSW_PN_MAC_SOFT_RESET_REG_SOFT_RESET_MASK;

   //Wait for SOFT_RESET bit to be cleared to confirm reset completion
   while((ctrlRegs->ENETPORT[0].PN_MAC_SOFT_RESET_REG &
      CSL_XGE_CPSW_PN_MAC_SOFT_RESET_REG_SOFT_RESET_MASK) != 0)
   {
   }

   //Set port state (forwarding)
   temp = aleRegs->I0_ALE_PORTCTL0[1] & ~CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_MASK;
   aleRegs->I0_ALE_PORTCTL0[1] = temp | (3 << CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_SHIFT);

   //Set the MAC address of the station
   ctrlRegs->ENETPORT[0].PN_SA_H_REG = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   ctrlRegs->ENETPORT[0].PN_SA_L_REG = interface->macAddr.w[2];

   //Configure VLAN identifier and VLAN priority
   ctrlRegs->ENETPORT[0].PN_PORT_VLAN_REG = (0 << CSL_XGE_CPSW_PN_PORT_VLAN_REG_PORT_PRI_SHIFT) |
      (CPSW_PORT1 << CSL_XGE_CPSW_PN_PORT_VLAN_REG_PORT_VID_SHIFT);

   //Add a VLAN entry in the ALE table
   am64xEthAddVlanEntry(CPSW_PORT1, CPSW_PORT1);

   //Add a VLAN/unicast address entry in the ALE table
   am64xEthAddVlanAddrEntry(CPSW_PORT1, CPSW_PORT1, &interface->macAddr);

   //Enable CPSW statistics
   ctrlRegs->STAT_PORT_EN_REG |= CSL_XGE_CPSW_STAT_PORT_EN_REG_P1_STAT_EN_MASK;

   //Enable TX and RX
   ctrlRegs->ENETPORT[0].PN_MAC_CONTROL_REG = CSL_XGE_CPSW_PN_MAC_CONTROL_REG_GMII_EN_MASK;

   //Accept any packets from the upper layer
   osSetEvent(&interface->nicTxEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief AM64x Ethernet MAC initialization (port 2)
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t am64xEthInitPort2(NetInterface *interface)
{
   error_t error;
   uint32_t temp;
   volatile CSL_Xge_cpswRegs *ctrlRegs;
   volatile CSL_AleRegs *aleRegs;

   //Debug message
   TRACE_INFO("Initializing AM64x Ethernet MAC (port 2)...\r\n");

   //Initialize CPSW instance
   am64xEthInitInstance(interface);

   //Save underlying network interface
   nicDriverInterface2 = interface;

   //PHY transceiver initialization
   error = interface->phyDriver->init(interface);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Point to the CPSW0_CONTROL registers
   ctrlRegs = (volatile CSL_Xge_cpswRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_NU_OFFSET);
   //Point to the CPSW0_ALE registers
   aleRegs = (volatile CSL_AleRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_ALE_OFFSET);

   //Set CMD_IDLE bit to 1 in the port control register
   ctrlRegs->ENETPORT[1].PN_MAC_CONTROL_REG |= CSL_XGE_CPSW_PN_MAC_CONTROL_REG_CMD_IDLE_MASK;

   //Wait for IDLE bit to be set to 1 in the port status register
   while((ctrlRegs->ENETPORT[1].PN_MAC_STATUS_REG & CSL_XGE_CPSW_PN_MAC_STATUS_REG_IDLE_MASK) == 0)
   {
   }

   //Set SOFT_RESET bit to 1 in the port software reset register
   ctrlRegs->ENETPORT[1].PN_MAC_SOFT_RESET_REG |= CSL_XGE_CPSW_PN_MAC_SOFT_RESET_REG_SOFT_RESET_MASK;

   //Wait for SOFT_RESET bit to be cleared to confirm reset completion
   while((ctrlRegs->ENETPORT[1].PN_MAC_SOFT_RESET_REG &
      CSL_XGE_CPSW_PN_MAC_SOFT_RESET_REG_SOFT_RESET_MASK) != 0)
   {
   }

   //Set port state (forwarding)
   temp = aleRegs->I0_ALE_PORTCTL0[2] & ~CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_MASK;
   aleRegs->I0_ALE_PORTCTL0[2] = temp | (3 << CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_SHIFT);

   //Set the MAC address of the station
   ctrlRegs->ENETPORT[1].PN_SA_H_REG = interface->macAddr.w[0] | (interface->macAddr.w[1] << 16);
   ctrlRegs->ENETPORT[1].PN_SA_L_REG = interface->macAddr.w[2];

   //Configure VLAN identifier and VLAN priority
   ctrlRegs->ENETPORT[1].PN_PORT_VLAN_REG = (0 << CSL_XGE_CPSW_PN_PORT_VLAN_REG_PORT_PRI_SHIFT) |
      (CPSW_PORT2 << CSL_XGE_CPSW_PN_PORT_VLAN_REG_PORT_VID_SHIFT);

   //Add a VLAN entry in the ALE table
   am64xEthAddVlanEntry(CPSW_PORT2, CPSW_PORT2);

   //Add a VLAN/unicast address entry in the ALE table
   am64xEthAddVlanAddrEntry(CPSW_PORT2, CPSW_PORT2, &interface->macAddr);

   //Enable CPSW statistics
   ctrlRegs->STAT_PORT_EN_REG |= CSL_XGE_CPSW_STAT_PORT_EN_REG_P2_STAT_EN_MASK;

   //Enable TX and RX
   ctrlRegs->ENETPORT[1].PN_MAC_CONTROL_REG = CSL_XGE_CPSW_PN_MAC_CONTROL_REG_GMII_EN_MASK;

   //Accept any packets from the upper layer
   osSetEvent(&interface->nicTxEvent);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Initialize CPSW instance
 * @param[in] interface Underlying network interface
 **/

void am64xEthInitInstance(NetInterface *interface)
{
   int32_t status;
   uint32_t i;
   uint32_t temp;
   uint32_t coreId;
   uint32_t coreKey;
   Cpsw_Cfg cpswConfig;
   EnetOsal_Cfg osalConfig;
   EnetUtils_Cfg utilsConfig;
   EnetUdma_Cfg dmaConfig;
   EnetUdma_OpenTxChPrms txChCfg;
   EnetUdma_OpenRxFlowPrms rxChCfg;
   Enet_IoctlPrms ioctlParams;
   EnetPer_AttachCoreOutArgs attachCoreOutArgs;
   Enet_Handle enetHandle;
   Udma_DrvHandle udmaHandle;
   EnetDma_Pkt *packetInfo;
   volatile CSL_Xge_cpswRegs *ctrlRegs;
   volatile CSL_AleRegs *aleRegs;
   volatile CSL_MdioRegs *mdioRegs;
   uint8_t macAddr[ENET_MAC_ADDR_LEN];

   //Initialization sequence is performed once
   if(nicDriverInterface1 == NULL && nicDriverInterface2 == NULL)
   {
      uint32_t txChNum = 0;
      uint32_t rxFlowIdx = 0;
      uint32_t rxStartFlowIdx = 0;

      //Retrieve core ID
      coreId = EnetSoc_getCoreId();

      //Select the interface mode (MII/RMII/RGMII) and configure pin muxing
      am64xEthInitGpio(interface);

      //Initialize configuration structures
      memset(&cpswConfig, 0, sizeof(Cpsw_Cfg));
      memset(&dmaConfig, 0, sizeof(EnetUdma_Cfg));

      //Initialize OS abstraction layer
      Enet_initOsalCfg(&osalConfig);
      Enet_initUtilsCfg(&utilsConfig);
      Enet_init(&osalConfig, &utilsConfig);

      //Debug message
      TRACE_INFO("  Initializing memory...\r\n");

      //Initialize memory
      status = EnetMem_init();
      //Check status code
      if(status != ENET_SOK)
      {
         //Debug message
         TRACE_ERROR("Failed to initialize memory (status = %d)\r\n", status);
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Initialize packet queue for free TX packets
      EnetQueue_initQ(&txFreePacketQueue);

      //Debug message
      TRACE_INFO("  Initializing UDMA driver...\r\n");

      //Open UDMA driver
      udmaHandle = EnetAppUtils_udmaOpen(ENET_CPSW_3G, NULL);
      //Invalid handle?
      if(udmaHandle == NULL)
      {
         //Debug message
         TRACE_ERROR("Failed to open UDMA driver\r\n");
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Debug message
      TRACE_INFO("  Initializing CPSW clocks...\r\n");
      //Enable CPSW peripheral clocks
      EnetAppUtils_enableClocks(ENET_CPSW_3G, 0);

      //Initialize DMA configuration
      dmaConfig.rxChInitPrms.dmaPriority = UDMA_DEFAULT_RX_CH_DMA_PRIORITY;
      dmaConfig.hUdmaDrv = udmaHandle;

      //Set CPSW parameters
      Enet_initCfg(ENET_CPSW_3G, 0, &cpswConfig, sizeof(Cpsw_Cfg));
      cpswConfig.vlanCfg.vlanAware = false;
      cpswConfig.hostPortCfg.removeCrc = false;
      cpswConfig.hostPortCfg.padShortPacket = true;
      cpswConfig.hostPortCfg.passCrcErrors = false;
      cpswConfig.dmaCfg = &dmaConfig;

      //Debug message
      TRACE_INFO("  Initializing RM configuration...\r\n");
      //Initialize RM configuration
      EnetAppUtils_initResourceConfig(ENET_CPSW_3G, coreId, &cpswConfig.resCfg);

      //Debug message
      TRACE_INFO("  Initializing CPSW peripheral...\r\n");

      //Open CPSW peripheral
      enetHandle = Enet_open(ENET_CPSW_3G, 0, &cpswConfig, sizeof(Cpsw_Cfg));
      //Invalid handle?
      if(enetHandle == NULL)
      {
         //Debug message
         TRACE_ERROR("Failed to open CPSW peripheral\r\n");
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Debug message
      TRACE_INFO("  Attaching core with RM...\r\n");

      //Set IOCTL parameters
      ENET_IOCTL_SET_INOUT_ARGS(&ioctlParams, &coreId, &attachCoreOutArgs);

      //Attach the core with RM
      status = Enet_ioctl(enetHandle, coreId, ENET_PER_IOCTL_ATTACH_CORE,
         &ioctlParams);
      //Check status code
      if(status != ENET_SOK)
      {
         //Debug message
         TRACE_ERROR("Failed to attach core with RM (status = %d)\r\n", status);
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Save core key
      coreKey = attachCoreOutArgs.coreKey;

      //Set DMA TX channel parameters
      EnetDma_initTxChParams(&txChCfg);
      txChCfg.hUdmaDrv = udmaHandle;
      txChCfg.notifyCb = NULL;
      txChCfg.cbArg = NULL;
      txChCfg.useGlobalEvt = true;

      //Use default common parameters
      EnetAppUtils_setCommonTxChPrms(&txChCfg);

      //Debug message
      TRACE_INFO("  Opening DMA TX channel...\r\n");

      //Open the DMA TX channel
      EnetAppUtils_openTxCh(enetHandle, coreKey, coreId, &txChNum,
         &txChHandle, &txChCfg);
      //Invalid handle?
      if(txChHandle == NULL)
      {
         //Debug message
         TRACE_ERROR("Failed to open DMA TX channel\r\n");
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Allocate TX packet queue
      for(i = 0; i < ENET_MEM_NUM_TX_PKTS; i++)
      {
         //Allocate a new packet
         packetInfo = EnetMem_allocEthPkt(NULL, ENET_MEM_LARGE_POOL_PKT_SIZE,
            ENETDMA_CACHELINE_ALIGNMENT);

         //Sanity check
         EnetAppUtils_assert(packetInfo != NULL);

         //Add the packet to the queue
         EnetQueue_enq(&txFreePacketQueue, &packetInfo->node);
      }

      //Debug message
      TRACE_INFO("  TX queue initialized with %u packets\r\n",
         EnetQueue_getQCount(&txFreePacketQueue));

      //Set DMA TX channel parameters
      EnetDma_initRxChParams(&rxChCfg);
      rxChCfg.hUdmaDrv = udmaHandle;
      rxChCfg.notifyCb = am64xEthRxIrqHandler;
      rxChCfg.cbArg = NULL;
      rxChCfg.useGlobalEvt = true;
      rxChCfg.flowPrms.sizeThreshEn = 0;

      //Use default common parameters
      EnetAppUtils_setCommonRxFlowPrms(&rxChCfg);

      //Open the DMA RX channel
      EnetAppUtils_openRxFlowForChIdx(ENET_CPSW_3G, enetHandle, coreKey,
         coreId, true, 0, &rxStartFlowIdx, &rxFlowIdx, macAddr, &rxChHandle,
         &rxChCfg);
      //Invalid handle?
      if(rxChHandle == NULL)
      {
         //Debug message
         TRACE_ERROR("Failed to open DMA RX channel\r\n");
         //Fatal error
         EnetAppUtils_assert(false);
      }

      //Initialize RX packet queue
      EnetQueue_initQ(&rxFreePacketQueue);

      //Allocate RX packet queue
      for(i = 0; i < ENET_MEM_NUM_RX_PKTS; i++)
      {
         //Allocate a new packet
         packetInfo = EnetMem_allocEthPkt(NULL, ENET_MEM_LARGE_POOL_PKT_SIZE,
            ENETDMA_CACHELINE_ALIGNMENT);

         //Sanity check
         EnetAppUtils_assert(packetInfo != NULL);

         //Add the packet to the queue
         EnetQueue_enq(&rxFreePacketQueue, &packetInfo->node);
      }

      //Debug message
      TRACE_INFO("  RX queue initialized with %u packets\r\n",
         EnetQueue_getQCount(&rxFreePacketQueue));

      //Submit all packets
      EnetDma_submitRxPktQ(rxChHandle, &rxFreePacketQueue);

      //Point to the CPSW0_CONTROL registers
      ctrlRegs = (volatile CSL_Xge_cpswRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_NU_OFFSET);
      //Point to the CPSW0_ALE registers
      aleRegs = (volatile CSL_AleRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_ALE_OFFSET);
      //Point to the CPSW0_MDIO registers
      mdioRegs = (volatile CSL_MdioRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_MDIO_OFFSET);

      //Enable ALE and clear ALE address table
      aleRegs->ALE_CONTROL = CSL_ALE_ALE_CONTROL_ENABLE_ALE_MASK |
         CSL_ALE_ALE_CONTROL_CLEAR_TABLE_MASK;

      //For dual MAC mode, configure VLAN aware mode
      aleRegs->ALE_CONTROL |= CSL_ALE_ALE_CONTROL_ALE_VLAN_AWARE_MASK;

      //Set host port state (forwarding)
      temp = aleRegs->I0_ALE_PORTCTL0[0] & ~CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_MASK;
      aleRegs->I0_ALE_PORTCTL0[0] = temp | (3 << CSL_ALE_I0_ALE_PORTCTL0_I0_REG_P0_PORTSTATE_SHIFT);

      //Configure host port
      ctrlRegs->P0_CONTROL_REG = 0;

      //Set the maximum frame length
      temp = ctrlRegs->P0_RX_MAXLEN_REG & ~CSL_XGE_CPSW_P0_RX_MAXLEN_REG_RX_MAXLEN_MASK;
      ctrlRegs->P0_RX_MAXLEN_REG = temp | (ETH_MAX_FRAME_SIZE << CSL_XGE_CPSW_P0_RX_MAXLEN_REG_RX_MAXLEN_SHIFT);

      //Enable host port
      ctrlRegs->CONTROL_REG = CSL_XGE_CPSW_CONTROL_REG_P0_RX_PAD_MASK |
         CSL_XGE_CPSW_CONTROL_REG_P0_ENABLE_MASK;

      //Enable CPSW statistics
      ctrlRegs->STAT_PORT_EN_REG |= CSL_XGE_CPSW_STAT_PORT_EN_REG_P0_STAT_EN_MASK;

      //Calculate the MDC clock divider to be used
      temp = (MDIO_INPUT_CLK / MDIO_OUTPUT_CLK) - 1;

      //Initialize MDIO interface
      mdioRegs->CONTROL_REG = CSL_MDIO_CONTROL_REG_ENABLE_MASK |
         CSL_MDIO_CONTROL_REG_FAULT_DETECT_ENABLE_MASK |
         (temp & CSL_MDIO_CONTROL_REG_CLKDIV_MASK);
   }
}


/**
 * @brief GPIO configuration
 * @param[in] interface Underlying network interface
 **/

__weak_func void am64xEthInitGpio(NetInterface *interface)
{
//TMDS64GPEVM evaluation board?
#if defined(USE_TMDS64GPEVM)
   //MDIO/MDC pins
   const Pinmux_PerCfg_t mdioPins[] =
   {
      //MDIO0_MDC (ball R2)
      {PIN_PRG0_PRU1_GPO19, PIN_MODE(4) | PIN_PULL_DISABLE},
      //MDIO0_MDIO (ball P5)
      {PIN_PRG0_PRU1_GPO18, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},

      //RGMII1_TXC (ball U14)
      {PIN_PRG1_PRU0_GPO10, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_TX_CTL (ball U15)
      {PIN_PRG1_PRU0_GPO9, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_TD0 (ball V15)
      {PIN_PRG1_PRU1_GPO7, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_TD1 (ball V14)
      {PIN_PRG1_PRU1_GPO9, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_TD2 (ball W14)
      {PIN_PRG1_PRU1_GPO10, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_TD3 (ball AA14)
      {PIN_PRG1_PRU1_GPO17, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII1_RXC (ball AA5)
      {PIN_PRG0_PRU0_GPO10, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII1_RX_CTL (ball W6)
      {PIN_PRG0_PRU0_GPO9, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII1_RD0 (ball W5)
      {PIN_PRG0_PRU1_GPO7, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII1_RD1 (ball Y5)
      {PIN_PRG0_PRU1_GPO9, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII1_RD2 (ball V6)
      {PIN_PRG0_PRU1_GPO10, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII1_RD3 (ball V5)
      {PIN_PRG0_PRU1_GPO17, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},

      //RGMII2_TXC (ball Y10)
      {PIN_PRG1_PRU1_GPO16, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_TX_CTL (ball Y11)
      {PIN_PRG1_PRU1_GPO15, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_TD0 (ball AA10)
      {PIN_PRG1_PRU1_GPO11, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_TD1 (ball V10)
      {PIN_PRG1_PRU1_GPO12, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_TD2 (ball U10)
      {PIN_PRG1_PRU1_GPO13, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_TD3 (ball AA11)
      {PIN_PRG1_PRU1_GPO14, PIN_MODE(4) | PIN_PULL_DISABLE},
      //RGMII2_RXC (ball U11)
      {PIN_PRG1_PRU1_GPO6, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII2_RX_CTL (ball W12)
      {PIN_PRG1_PRU1_GPO4, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII2_RD0 (ball W11)
      {PIN_PRG1_PRU1_GPO0, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII2_RD1 (ball V11)
      {PIN_PRG1_PRU1_GPO1, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII2_RD2 (ball AA12)
      {PIN_PRG1_PRU1_GPO2, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},
      //RGMII2_RD3 (ball Y12)
      {PIN_PRG1_PRU1_GPO3, PIN_MODE(4) | PIN_INPUT_ENABLE | PIN_PULL_DISABLE},

      //End marker
      {PINMUX_END, PINMUX_END}
   };

   //Configure MDIO/MDC pins
   Pinmux_config(mdioPins, PINMUX_DOMAIN_ID_MAIN);
#endif
}


/**
 * @brief AM64x Ethernet MAC timer handler
 *
 * This routine is periodically called by the TCP/IP stack to handle periodic
 * operations such as polling the link state
 *
 * @param[in] interface Underlying network interface
 **/

void am64xEthTick(NetInterface *interface)
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

void am64xEthEnableIrq(NetInterface *interface)
{
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

void am64xEthDisableIrq(NetInterface *interface)
{
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
 * @brief AM64x Ethernet MAC receive interrupt
 * @param[in] arg Unused parameter
 **/

void am64xEthRxIrqHandler(void *arg)
{
   bool_t flag;

   //Interrupt service routine prologue
   osEnterIsr();

   //Set event flag
   nicDriverInterface1->nicEvent = TRUE;
   //Notify the TCP/IP stack of the event
   flag = osSetEventFromIsr(&netEvent);

   //Interrupt service routine epilogue
   osExitIsr(flag);
}


/**
 * @brief AM64x Ethernet MAC event handler
 * @param[in] interface Underlying network interface
 **/

void am64xEthEventHandler(NetInterface *interface)
{
   static uint8_t temp[ENET_MEM_LARGE_POOL_PKT_SIZE];
   size_t n;
   int32_t status;
   EnetDma_PktQ readyPacketQueue;
   EnetDma_PktQ freePacketQueue;
   EnetDma_Pkt *packetInfo;
   NetRxAncillary ancillary;

   //Initialize packet queues
   EnetQueue_initQ(&readyPacketQueue);
   EnetQueue_initQ(&freePacketQueue);

   //Retrieve received packets
   status = EnetDma_retrieveRxPktQ(rxChHandle, &readyPacketQueue);

   //Return status code
   if(status == ENET_SOK)
   {
      //Get the first received packet
      packetInfo = (EnetDma_Pkt *) EnetQueue_deq(&readyPacketQueue);

      //Consume the received packets and send them back
      while(packetInfo != NULL)
      {
         //Check the port on which the packet was received
         if(packetInfo->rxPortNum == ENET_MAC_PORT_1)
         {
            //Port 1
            interface = nicDriverInterface1;
         }
         else if(packetInfo->rxPortNum == ENET_MAC_PORT_2)
         {
            //Port 2
            interface = nicDriverInterface2;
         }
         else
         {
            //Invalid port
            interface = NULL;
         }

         //Retrieve the length of the frame
         n = packetInfo->userBufLen;

         //Sanity check
         if(interface != NULL)
         {
            //Copy data from the receive buffer
            osMemcpy(temp, packetInfo->bufPtr, (n + 3) & ~3UL);

            //Additional options can be passed to the stack along with the packet
            ancillary = NET_DEFAULT_RX_ANCILLARY;

            //Pass the packet to the upper layer
            nicProcessPacket(interface, temp, n, &ancillary);
         }

         //Restore buffer length
         packetInfo->userBufLen = ENET_MEM_LARGE_POOL_PKT_SIZE;

         //Release the received packet
         EnetQueue_enq(&freePacketQueue, &packetInfo->node);

         //Get the next received packet
         packetInfo = (EnetDma_Pkt *) EnetQueue_deq(&readyPacketQueue);
      }

      //Send the processed packets back to the RX queue
      EnetDma_submitRxPktQ(rxChHandle, &freePacketQueue);
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

error_t am64xEthSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary)
{
   size_t length;
   int32_t status;
   EnetDma_PktQ freePacketQueue;
   EnetDma_PktQ submitPacketQueue;
   EnetDma_Pkt *packetInfo;

   //Initialize packet queues
   EnetQueue_initQ(&freePacketQueue);
   EnetQueue_initQ(&submitPacketQueue);

   //Retrieve free TX packets
   status = EnetDma_retrieveTxPktQ(txChHandle, &freePacketQueue);

   //Return status code
   if(status == ENET_SOK)
   {
      //Get the first free packet
      packetInfo = (EnetDma_Pkt *) EnetQueue_deq(&freePacketQueue);

      //Move free packets to the queue
      while(packetInfo != NULL)
      {
         EnetQueue_enq(&txFreePacketQueue, &packetInfo->node);
         packetInfo = (EnetDma_Pkt *) EnetQueue_deq(&freePacketQueue);
      }
   }

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

   //Check the frame length
   if(length > ENET_MEM_LARGE_POOL_PKT_SIZE)
   {
      //The transmitter can accept another packet
      osSetEvent(&interface->nicTxEvent);
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Dequeue a free packet from the queue
   packetInfo = (EnetDma_Pkt *) EnetQueue_deq(&txFreePacketQueue);

   //Any packet available?
   if(packetInfo != NULL)
   {
      //Copy user data to the transmit buffer
      netBufferRead(packetInfo->bufPtr, buffer, offset, length);

      //Prepare an new packet
      packetInfo->userBufLen = length;
      packetInfo->appPriv = NULL;
      packetInfo->tsInfo.enableHostTxTs = false;

      //Select the relevant port number
      if(interface == nicDriverInterface1)
      {
         //Port 1
         packetInfo->txPortNum = ENET_MAC_PORT_1;
      }
      else
      {
         //Port 2
         packetInfo->txPortNum = ENET_MAC_PORT_2;
      }

      //Enqueue the packet for transmission
      EnetQueue_enq(&submitPacketQueue, &packetInfo->node);
   }

   //Transmit all queued packets
   status = EnetDma_submitTxPktQ(txChHandle, &submitPacketQueue);

   //The transmitter can accept another packet
   osSetEvent(&interface->nicTxEvent);

   //Return status code
   if(status == ENET_SOK)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_FAILURE;
   }
}


/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t am64xEthUpdateMacAddrFilter(NetInterface *interface)
{
   uint_t i;
   uint_t port;
   MacFilterEntry *entry;

   //Debug message
   TRACE_DEBUG("Updating AM64x ALE table...\r\n");

   //Select the relevant port number
   if(interface == nicDriverInterface1)
   {
      port = CPSW_PORT1;
   }
   else if(interface == nicDriverInterface2)
   {
      port = CPSW_PORT2;
   }
   else
   {
      port = CPSW_PORT0;
   }

   //The MAC address filter contains the list of MAC addresses to accept when
   //receiving an Ethernet frame
   for(i = 0; i < MAC_ADDR_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->macAddrFilter[i];

      //Check whether the ALE table should be updated for the current multicast
      //address
      if(!macCompAddr(&entry->addr, &MAC_UNSPECIFIED_ADDR))
      {
         if(entry->addFlag)
         {
            //Add VLAN/multicast address entry to the ALE table
            am64xEthAddVlanAddrEntry(port, port, &entry->addr);
         }
         else if(entry->deleteFlag)
         {
            //Remove VLAN/multicast address entry from the ALE table
            am64xEthDeleteVlanAddrEntry(port, port, &entry->addr);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Adjust MAC configuration parameters for proper operation
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t am64xEthUpdateMacConfig(NetInterface *interface)
{
   uint32_t config = 0;
   volatile CSL_Xge_cpswRegs *ctrlRegs;

   //Point to the CPSW0_CONTROL registers
   ctrlRegs = (volatile CSL_Xge_cpswRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_NU_OFFSET);

   //Read MAC control register
   if(interface == nicDriverInterface1)
   {
      config = ctrlRegs->ENETPORT[0].PN_MAC_CONTROL_REG;
   }
   else if(interface == nicDriverInterface2)
   {
      config = ctrlRegs->ENETPORT[1].PN_MAC_CONTROL_REG;
   }

   //1000BASE-T operation mode?
   if(interface->linkSpeed == NIC_LINK_SPEED_1GBPS)
   {
      config |= CSL_XGE_CPSW_PN_MAC_CONTROL_REG_GIG_MASK;
      config &= ~CSL_XGE_CPSW_PN_MAC_CONTROL_REG_IFCTL_A_MASK;
   }
   //100BASE-TX operation mode?
   else if(interface->linkSpeed == NIC_LINK_SPEED_100MBPS)
   {
      config &= ~CSL_XGE_CPSW_PN_MAC_CONTROL_REG_GIG_MASK;
      config |= CSL_XGE_CPSW_PN_MAC_CONTROL_REG_IFCTL_A_MASK;
   }
   //10BASE-T operation mode?
   else
   {
      config &= ~CSL_XGE_CPSW_PN_MAC_CONTROL_REG_GIG_MASK;
      config &= ~CSL_XGE_CPSW_PN_MAC_CONTROL_REG_IFCTL_A_MASK;
   }

   //Half-duplex or full-duplex mode?
   if(interface->duplexMode == NIC_FULL_DUPLEX_MODE)
   {
      config |= CSL_XGE_CPSW_PN_MAC_CONTROL_REG_FULLDUPLEX_MASK;
   }
   else
   {
      config &= ~CSL_XGE_CPSW_PN_MAC_CONTROL_REG_FULLDUPLEX_MASK;
   }

   //Update MAC control register
   if(interface == nicDriverInterface1)
   {
      ctrlRegs->ENETPORT[0].PN_MAC_CONTROL_REG = config;
   }
   else if(interface == nicDriverInterface2)
   {
      ctrlRegs->ENETPORT[1].PN_MAC_CONTROL_REG = config;
   }

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

void am64xEthWritePhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr, uint16_t data)
{
   uint32_t temp;
   volatile CSL_MdioRegs *mdioRegs;

   //Point to the CPSW0_MDIO registers
   mdioRegs = (volatile CSL_MdioRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_MDIO_OFFSET);

   //Valid opcode?
   if(opcode == SMI_OPCODE_WRITE)
   {
      //Set up a write operation
      temp = CSL_MDIO_USER_GROUP_USER_ACCESS_REG_GO_MASK |
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_WRITE_MASK;

      //PHY address
      temp |= (phyAddr << CSL_MDIO_USER_GROUP_USER_ACCESS_REG_PHYADR_SHIFT) &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_PHYADR_MASK;

      //Register address
      temp |= (regAddr << CSL_MDIO_USER_GROUP_USER_ACCESS_REG_REGADR_SHIFT) &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_REGADR_MASK;

      //Register value
      temp |= data & CSL_MDIO_USER_GROUP_USER_ACCESS_REG_DATA_MASK;

      //Start a write operation
      mdioRegs->USER_GROUP[0].USER_ACCESS_REG = temp;

      //Wait for the write to complete
      while((mdioRegs->USER_GROUP[0].USER_ACCESS_REG &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_GO_MASK) != 0)
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

uint16_t am64xEthReadPhyReg(uint8_t opcode, uint8_t phyAddr,
   uint8_t regAddr)
{
   uint16_t data;
   uint32_t temp;
   volatile CSL_MdioRegs *mdioRegs;

   //Point to the CPSW0_MDIO registers
   mdioRegs = (volatile CSL_MdioRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_MDIO_OFFSET);

   //Valid opcode?
   if(opcode == SMI_OPCODE_READ)
   {
      //Set up a read operation
      temp = CSL_MDIO_USER_GROUP_USER_ACCESS_REG_GO_MASK;

      //PHY address
      temp |= (phyAddr << CSL_MDIO_USER_GROUP_USER_ACCESS_REG_PHYADR_SHIFT) &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_PHYADR_MASK;

      //Register address
      temp |= (regAddr << CSL_MDIO_USER_GROUP_USER_ACCESS_REG_REGADR_SHIFT) &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_REGADR_MASK;

      //Start a read operation
      mdioRegs->USER_GROUP[0].USER_ACCESS_REG = temp;

      //Wait for the read to complete
      while((mdioRegs->USER_GROUP[0].USER_ACCESS_REG &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_GO_MASK) != 0)
      {
      }

      //Get register value
      data = mdioRegs->USER_GROUP[0].USER_ACCESS_REG &
         CSL_MDIO_USER_GROUP_USER_ACCESS_REG_DATA_MASK;
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
 * @brief Write an ALE table entry
 * @param[in] index Entry index
 * @param[in] entry Pointer to the ALE table entry
 **/

void am64xEthWriteEntry(uint_t index, const Am64xAleEntry *entry)
{
   volatile CSL_AleRegs *aleRegs;

   //Point to the CPSW0_ALE registers
   aleRegs = (volatile CSL_AleRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_ALE_OFFSET);

   //Copy the content of the entry to be written
   aleRegs->ALE_TBLW2 = entry->word2;
   aleRegs->ALE_TBLW1 = entry->word1;
   aleRegs->ALE_TBLW0 = entry->word0;

   //Write the ALE entry at the specified index
   aleRegs->ALE_TBLCTL = CSL_ALE_ALE_TBLCTL_TABLEWR_MASK | index;
}


/**
 * @brief Read an ALE table entry
 * @param[in] index Entry index
 * @param[out] entry Pointer to the ALE table entry
 **/

void am64xEthReadEntry(uint_t index, Am64xAleEntry *entry)
{
   volatile CSL_AleRegs *aleRegs;

   //Point to the CPSW0_ALE registers
   aleRegs = (volatile CSL_AleRegs *) (CSL_CPSW0_NUSS_BASE + CPSW_ALE_OFFSET);

   //Read the ALE entry at the specified index
   aleRegs->ALE_TBLCTL = index;

   //Copy the content of the entry
   entry->word2 = aleRegs->ALE_TBLW2;
   entry->word1 = aleRegs->ALE_TBLW1;
   entry->word0 = aleRegs->ALE_TBLW0;
}


/**
 * @brief Find a free entry in the ALE table
 * @return Index of the first free entry
 **/

uint_t am64xEthFindFreeEntry(void)
{
   uint_t index;
   uint32_t type;
   Am64xAleEntry entry;

   //Loop through the ALE table entries
   for(index = 0; index < CPSW_ALE_MAX_ENTRIES; index++)
   {
      //Read the current entry
      am64xEthReadEntry(index, &entry);

      //Retrieve the type of the ALE entry
      type = entry.word1 & CPSW_ALE_WORD1_ENTRY_TYPE_MASK;

      //Free entry?
      if(type == CPSW_ALE_WORD1_ENTRY_TYPE_FREE)
      {
         //Exit immediately
         break;
      }
   }

   //Return the index of the entry
   return index;
}


/**
 * @brief Search the ALE table for the specified VLAN entry
 * @param[in] vlanId VLAN identifier
 * @return Index of the matching entry
 **/

uint_t am64xEthFindVlanEntry(uint_t vlanId)
{
   uint_t index;
   uint32_t value;
   Am64xAleEntry entry;

   //Loop through the ALE table entries
   for(index = 0; index < CPSW_ALE_MAX_ENTRIES; index++)
   {
      //Read the current entry
      am64xEthReadEntry(index, &entry);

      //Retrieve the type of the ALE entry
      value = entry.word1 & CPSW_ALE_WORD1_ENTRY_TYPE_MASK;

      //Check the type of the ALE entry
      if(value == CPSW_ALE_WORD1_ENTRY_TYPE_VLAN_ADDR)
      {
         //Get the VLAN identifier
         value = entry.word1 & CPSW_ALE_WORD1_VLAN_ID_MASK;

         //Compare the VLAN identifier
         if(value == CPSW_ALE_WORD1_VLAN_ID(vlanId))
         {
            //Matching ALE entry found
            break;
         }
      }
   }

   //Return the index of the entry
   return index;
}


/**
 * @brief Search the ALE table for the specified VLAN/address entry
 * @param[in] vlanId VLAN identifier
 * @param[in] macAddr MAC address
 * @return Index of the matching entry
 **/

uint_t am64xEthFindVlanAddrEntry(uint_t vlanId, MacAddr *macAddr)
{
   uint_t index;
   uint32_t value;
   Am64xAleEntry entry;

   //Loop through the ALE table entries
   for(index = 0; index < CPSW_ALE_MAX_ENTRIES; index++)
   {
      //Read the current entry
      am64xEthReadEntry(index, &entry);

      //Retrieve the type of the ALE entry
      value = entry.word1 & CPSW_ALE_WORD1_ENTRY_TYPE_MASK;

      //Check the type of the ALE entry
      if(value == CPSW_ALE_WORD1_ENTRY_TYPE_VLAN_ADDR)
      {
         //Get the VLAN identifier
         value = entry.word1 & CPSW_ALE_WORD1_VLAN_ID_MASK;

         //Compare the VLAN identifier
         if(value == CPSW_ALE_WORD1_VLAN_ID(vlanId))
         {
            //Compare the MAC address
            if(macAddr->b[0] == (uint8_t) (entry.word1 >> 8) &&
               macAddr->b[1] == (uint8_t) (entry.word1 >> 0) &&
               macAddr->b[2] == (uint8_t) (entry.word0 >> 24) &&
               macAddr->b[3] == (uint8_t) (entry.word0 >> 16) &&
               macAddr->b[4] == (uint8_t) (entry.word0 >> 8) &&
               macAddr->b[5] == (uint8_t) (entry.word0 >> 0))
            {
               //Matching ALE entry found
               break;
            }
         }
      }
   }

   //Return the index of the entry
   return index;
}


/**
 * @brief Add a VLAN entry in the ALE table
 * @param[in] port Port number
 * @param[in] vlanId VLAN identifier
 * @return Error code
 **/

error_t am64xEthAddVlanEntry(uint_t port, uint_t vlanId)
{
   error_t error;
   uint_t index;
   Am64xAleEntry entry;

   //Ensure that there are no duplicate address entries in the ALE table
   index = am64xEthFindVlanEntry(vlanId);

   //No matching entry found?
   if(index >= CPSW_ALE_MAX_ENTRIES)
   {
      //Find a free entry in the ALE table
      index = am64xEthFindFreeEntry();
   }

   //Sanity check
   if(index < CPSW_ALE_MAX_ENTRIES)
   {
      //Set up a VLAN table entry
      entry.word2 = 0;
      entry.word1 = CPSW_ALE_WORD1_ENTRY_TYPE_VLAN;
      entry.word0 = 0;

      //Set VLAN identifier
      entry.word1 |= CPSW_ALE_WORD1_VLAN_ID(vlanId);

      //Force the packet VLAN tag to be removed on egress
      entry.word0 |= CPSW_ALE_WORD0_FORCE_UNTAG_EGRESS(1 << port) |
         CPSW_ALE_WORD0_FORCE_UNTAG_EGRESS(1 << CPSW_PORT0);

      //Set VLAN member list
      entry.word0 |= CPSW_ALE_WORD0_VLAN_MEMBER_LIST(1 << port) |
         CPSW_ALE_WORD0_VLAN_MEMBER_LIST(1 << CPSW_PORT0);

      //Add a new entry to the ALE table
      am64xEthWriteEntry(index, &entry);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The ALE table is full
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Add a VLAN/address entry in the ALE table
 * @param[in] port Port number
 * @param[in] vlanId VLAN identifier
 * @param[in] macAddr MAC address
 * @return Error code
 **/

error_t am64xEthAddVlanAddrEntry(uint_t port, uint_t vlanId, MacAddr *macAddr)
{
   error_t error;
   uint_t index;
   Am64xAleEntry entry;

   //Ensure that there are no duplicate address entries in the ALE table
   index = am64xEthFindVlanAddrEntry(vlanId, macAddr);

   //No matching entry found?
   if(index >= CPSW_ALE_MAX_ENTRIES)
   {
      //Find a free entry in the ALE table
      index = am64xEthFindFreeEntry();
   }

   //Sanity check
   if(index < CPSW_ALE_MAX_ENTRIES)
   {
      //Set up a VLAN/address table entry
      entry.word2 = 0;
      entry.word1 = CPSW_ALE_WORD1_ENTRY_TYPE_VLAN_ADDR;
      entry.word0 = 0;

      //Multicast address?
      if(macIsMulticastAddr(macAddr))
      {
         //Set port mask
         entry.word2 |= CPSW_ALE_WORD2_SUPER |
            CPSW_ALE_WORD2_PORT_MASK(1 << port) |
            CPSW_ALE_WORD2_PORT_MASK(1 << CPSW_CH0);

         //Set multicast forward state
         entry.word1 |= CPSW_ALE_WORD1_MCAST_FWD_STATE(0);
      }

      //Set VLAN identifier
      entry.word1 |= CPSW_ALE_WORD1_VLAN_ID(vlanId);

      //Copy the upper 16 bits of the unicast address
      entry.word1 |= (macAddr->b[0] << 8) | macAddr->b[1];

      //Copy the lower 32 bits of the unicast address
      entry.word0 |= (macAddr->b[2] << 24) | (macAddr->b[3] << 16) |
         (macAddr->b[4] << 8) | macAddr->b[5];

      //Add a new entry to the ALE table
      am64xEthWriteEntry(index, &entry);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The ALE table is full
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Remove a VLAN/address entry from the ALE table
 * @param[in] port Port number
 * @param[in] vlanId VLAN identifier
 * @param[in] macAddr MAC address
 * @return Error code
 **/

error_t am64xEthDeleteVlanAddrEntry(uint_t port, uint_t vlanId, MacAddr *macAddr)
{
   error_t error;
   uint_t index;
   Am64xAleEntry entry;

   //Search the ALE table for the specified VLAN/address entry
   index = am64xEthFindVlanAddrEntry(vlanId, macAddr);

   //Matching ALE entry found?
   if(index < CPSW_ALE_MAX_ENTRIES)
   {
      //Clear the contents of the entry
      entry.word2 = 0;
      entry.word1 = 0;
      entry.word0 = 0;

      //Update the ALE table
      am64xEthWriteEntry(index, &entry);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Entry not found
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
}
