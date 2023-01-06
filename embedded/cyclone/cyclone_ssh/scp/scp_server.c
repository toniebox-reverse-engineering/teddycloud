/**
 * @file scp_server.c
 * @brief SCP server
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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
#define TRACE_LEVEL SCP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "scp/scp_server.h"
#include "scp/scp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains SCP server settings
 **/

void scpServerGetDefaultSettings(ScpServerSettings *settings)
{
   //SSH server context
   settings->sshServerContext = NULL;

   //SCP sessions
   settings->numSessions = 0;
   settings->sessions = NULL;

   //Root directory
   settings->rootDir = NULL;

   //User verification callback function
   settings->checkUserCallback = NULL;
   //Callback used to retrieve file permissions
   settings->getFilePermCallback = NULL;
}


/**
 * @brief Initialize SCP server context
 * @param[in] context Pointer to the SCP server context
 * @param[in] settings SCP server specific settings
 * @return Error code
 **/

error_t scpServerInit(ScpServerContext *context,
   const ScpServerSettings *settings)
{
   error_t error;
   uint_t i;

   //Debug message
   TRACE_INFO("Initializing SCP server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid SCP sessions?
   if(settings->sessions == NULL || settings->numSessions < 1 ||
      settings->numSessions > SCP_SERVER_MAX_SESSIONS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid root directory?
   if(settings->rootDir == NULL ||
      osStrlen(settings->rootDir) > SCP_SERVER_MAX_ROOT_DIR_LEN)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Initialize status code
   error = NO_ERROR;

   //Clear SCP server context
   osMemset(context, 0, sizeof(ScpServerContext));

   //Save user settings
   context->sshServerContext = settings->sshServerContext;
   context->numSessions = settings->numSessions;
   context->sessions = settings->sessions;
   context->checkUserCallback = settings->checkUserCallback;
   context->getFilePermCallback = settings->getFilePermCallback;

   //Set root directory
   osStrcpy(context->rootDir, settings->rootDir);

   //Clean the root directory path
   pathCanonicalize(context->rootDir);
   pathRemoveSlash(context->rootDir);

   //Loop through SCP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Initialize the structure representing the SCP session
      osMemset(&context->sessions[i], 0, sizeof(ScpServerSession));
   }

   //Create an event object to poll the state of channels
   if(!osCreateEvent(&context->event))
   {
      //Report an error
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(error)
   {
      //Clean up side effects
      scpServerDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Start SCP server
 * @param[in] context Pointer to the SCP server context
 * @return Error code
 **/

error_t scpServerStart(ScpServerContext *context)
{
   error_t error;

   //Make sure the SCP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting SCP server...\r\n");

   //Make sure the SCP server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Register channel request processing callback
   error = sshServerRegisterChannelRequestCallback(context->sshServerContext,
      scpServerChannelRequestCallback, context);

   //Check status code
   if(!error)
   {
      //Start the SCP server
      context->stop = FALSE;
      context->running = TRUE;

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("SCP Server",
         (OsTaskCode) scpServerTask, context, &context->taskTcb,
         context->taskStack, SCP_SERVER_STACK_SIZE, SCP_SERVER_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("SCP Server", (OsTaskCode) scpServerTask,
         context, SCP_SERVER_STACK_SIZE, SCP_SERVER_PRIORITY);
#endif

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         error = ERROR_OUT_OF_RESOURCES;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Unregister channel request processing callback
      sshServerUnregisterChannelRequestCallback(context->sshServerContext,
         scpServerChannelRequestCallback);
   }

   //Return status code
   return error;
}


/**
 * @brief Stop SCP server
 * @param[in] context Pointer to the SCP server context
 * @return Error code
 **/

error_t scpServerStop(ScpServerContext *context)
{
   uint_t i;

   //Make sure the SCP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping SCP server...\r\n");

   //Check whether the SCP server is running
   if(context->running)
   {
      //Unregister channel request processing callback
      sshServerUnregisterChannelRequestCallback(context->sshServerContext,
         scpServerChannelRequestCallback);

      //Stop the SCP server
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

      //Loop through SCP sessions
      for(i = 0; i < context->numSessions; i++)
      {
         //Active session?
         if(context->sessions[i].state != SCP_SERVER_SESSION_STATE_CLOSED)
         {
            //Close SCP session
            scpServerCloseSession(&context->sessions[i]);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set user's root directory
 * @param[in] session Handle referencing an SCP session
 * @param[in] rootDir NULL-terminated string specifying the root directory
 * @return Error code
 **/

error_t scpServerSetRootDir(ScpServerSession *session, const char_t *rootDir)
{
   ScpServerContext *context;

   //Check parameters
   if(session == NULL || rootDir == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the SCP server context
   context = session->context;

   //Set user's root directory
   pathCopy(session->rootDir, context->rootDir, SCP_SERVER_MAX_ROOT_DIR_LEN);
   pathCombine(session->rootDir, rootDir, SCP_SERVER_MAX_ROOT_DIR_LEN);

   //Clean the resulting path
   pathCanonicalize(session->rootDir);
   pathRemoveSlash(session->rootDir);

   //Set default user's home directory
   pathCopy(session->homeDir, session->rootDir, SCP_SERVER_MAX_HOME_DIR_LEN);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set user's home directory
 * @param[in] session Handle referencing an SCP session
 * @param[in] homeDir NULL-terminated string specifying the home directory
 * @return Error code
 **/

error_t scpServerSetHomeDir(ScpServerSession *session, const char_t *homeDir)
{
   ScpServerContext *context;

   //Check parameters
   if(session == NULL || homeDir == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the SCP server context
   context = session->context;

   //Set user's home directory
   pathCopy(session->homeDir, context->rootDir, SCP_SERVER_MAX_HOME_DIR_LEN);
   pathCombine(session->homeDir, homeDir, SCP_SERVER_MAX_HOME_DIR_LEN);

   //Clean the resulting path
   pathCanonicalize(session->homeDir);
   pathRemoveSlash(session->homeDir);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief SCP server task
 * @param[in] param Pointer to the SCP server context
 **/

void scpServerTask(void *param)
{
   error_t error;
   uint_t i;
   systime_t timeout;
   ScpServerContext *context;
   ScpServerSession *session;

   //Point to the SCP server context
   context = (ScpServerContext *) param;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Set polling timeout
      timeout = SCP_SERVER_TICK_INTERVAL;

      //Clear event descriptor set
      osMemset(context->eventDesc, 0, sizeof(context->eventDesc));

      //Loop through SCP sessions
      for(i = 0; i < context->numSessions; i++)
      {
         //Point to the structure describing the current session
         session = &context->sessions[i];

         //Active session?
         if(session->state != SCP_SERVER_SESSION_STATE_CLOSED)
         {
            //Register session events
            scpServerRegisterSessionEvents(session, &context->eventDesc[i]);

            //Check whether the channel is ready for I/O operation
            if(context->eventDesc[i].eventFlags != 0)
            {
               //No need to poll the underlying channel for incoming traffic
               timeout = 0;
            }
         }
      }

      //Wait for one of the set of channels to become ready to perform I/O
      error = sshPollChannels(context->eventDesc, context->numSessions,
         &context->event, timeout);

      //Check status code
      if(error == NO_ERROR || error == ERROR_TIMEOUT)
      {
         //Stop request?
         if(context->stop)
         {
            //Stop SCP server operation
            context->running = FALSE;
            //Task epilogue
            osExitTask();
            //Kill ourselves
            osDeleteTask(OS_SELF_TASK_ID);
         }

         //Loop through SCP sessions
         for(i = 0; i < context->numSessions; i++)
         {
            //Point to the structure describing the current session
            session = &context->sessions[i];

            //Active session?
            if(session->state != SCP_SERVER_SESSION_STATE_CLOSED)
            {
               //Check whether the channel is ready to perform I/O
               if(context->eventDesc[i].eventFlags != 0)
               {
                  //Session event handler
                  scpServerProcessSessionEvents(session);
               }
            }
         }
      }

      //Handle periodic operations
      scpServerTick(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release SCP server context
 * @param[in] context Pointer to the SCP server context
 **/

void scpServerDeinit(ScpServerContext *context)
{
   //Make sure the SCP server context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear SCP server context
      osMemset(context, 0, sizeof(ScpServerContext));
   }
}

#endif
