/**
 * @file sftp_server.c
 * @brief SFTP server
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
#define TRACE_LEVEL SFTP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "sftp/sftp_server.h"
#include "sftp/sftp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains SFTP server settings
 **/

void sftpServerGetDefaultSettings(SftpServerSettings *settings)
{
   //SSH server context
   settings->sshServerContext = NULL;

   //SFTP sessions
   settings->numSessions = 0;
   settings->sessions = NULL;

   //File objects
   settings->numFileObjects = 0;
   settings->fileObjects = NULL;

   //Root directory
   settings->rootDir = NULL;

   //User verification callback function
   settings->checkUserCallback = NULL;
   //Callback used to retrieve file permissions
   settings->getFilePermCallback = NULL;
}


/**
 * @brief Initialize SFTP server context
 * @param[in] context Pointer to the SFTP server context
 * @param[in] settings SFTP server specific settings
 * @return Error code
 **/

error_t sftpServerInit(SftpServerContext *context,
   const SftpServerSettings *settings)
{
   error_t error;
   uint_t i;

   //Debug message
   TRACE_INFO("Initializing SFTP server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid SFTP sessions?
   if(settings->sessions == NULL || settings->numSessions < 1 ||
      settings->numSessions > SFTP_SERVER_MAX_SESSIONS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid file objects?
   if(settings->fileObjects == NULL || settings->numFileObjects < 1)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid root directory?
   if(settings->rootDir == NULL ||
      osStrlen(settings->rootDir) > SFTP_SERVER_MAX_ROOT_DIR_LEN)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Initialize status code
   error = NO_ERROR;

   //Clear SFTP server context
   osMemset(context, 0, sizeof(SftpServerContext));

   //Save user settings
   context->sshServerContext = settings->sshServerContext;
   context->numSessions = settings->numSessions;
   context->sessions = settings->sessions;
   context->numFileObjects = settings->numFileObjects;
   context->fileObjects = settings->fileObjects;
   context->checkUserCallback = settings->checkUserCallback;
   context->getFilePermCallback = settings->getFilePermCallback;

   //Set root directory
   osStrcpy(context->rootDir, settings->rootDir);

   //Clean the root directory path
   pathCanonicalize(context->rootDir);
   pathRemoveSlash(context->rootDir);

   //Loop through SFTP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Initialize the structure representing the SFTP session
      osMemset(&context->sessions[i], 0, sizeof(SftpServerSession));
   }

   //Loop through file objects
   for(i = 0; i < context->numFileObjects; i++)
   {
      //Initialize the structure representing a file object
      osMemset(&context->fileObjects[i], 0, sizeof(SftpFileObject));
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
      sftpServerDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Start SFTP server
 * @param[in] context Pointer to the SFTP server context
 * @return Error code
 **/

error_t sftpServerStart(SftpServerContext *context)
{
   error_t error;

   //Make sure the SFTP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting SFTP server...\r\n");

   //Make sure the SFTP server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Register channel request processing callback
   error = sshServerRegisterChannelRequestCallback(context->sshServerContext,
      sftpServerChannelRequestCallback, context);

   //Check status code
   if(!error)
   {
      //Start the SFTP server
      context->stop = FALSE;
      context->running = TRUE;

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("SFTP Server",
         (OsTaskCode) sftpServerTask, context, &context->taskTcb,
         context->taskStack, SFTP_SERVER_STACK_SIZE, SFTP_SERVER_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("SFTP Server",
         (OsTaskCode) sftpServerTask, context, SFTP_SERVER_STACK_SIZE,
         SFTP_SERVER_PRIORITY);
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
         sftpServerChannelRequestCallback);
   }

   //Return status code
   return error;
}


/**
 * @brief Stop SFTP server
 * @param[in] context Pointer to the SFTP server context
 * @return Error code
 **/

error_t sftpServerStop(SftpServerContext *context)
{
   uint_t i;

   //Make sure the SFTP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping SFTP server...\r\n");

   //Check whether the SFTP server is running
   if(context->running)
   {
      //Unregister channel request processing callback
      sshServerUnregisterChannelRequestCallback(context->sshServerContext,
         sftpServerChannelRequestCallback);

      //Stop the SFTP server
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

      //Loop through SFTP sessions
      for(i = 0; i < context->numSessions; i++)
      {
         //Active session?
         if(context->sessions[i].state != SFTP_SERVER_SESSION_STATE_CLOSED)
         {
            //Close SFTP session
            sftpServerCloseSession(&context->sessions[i]);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set user's root directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] rootDir NULL-terminated string specifying the root directory
 * @return Error code
 **/

error_t sftpServerSetRootDir(SftpServerSession *session, const char_t *rootDir)
{
   SftpServerContext *context;

   //Check parameters
   if(session == NULL || rootDir == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the SFTP server context
   context = session->context;

   //Set user's root directory
   pathCopy(session->rootDir, context->rootDir, SFTP_SERVER_MAX_ROOT_DIR_LEN);
   pathCombine(session->rootDir, rootDir, SFTP_SERVER_MAX_ROOT_DIR_LEN);

   //Clean the resulting path
   pathCanonicalize(session->rootDir);
   pathRemoveSlash(session->rootDir);

   //Set default user's home directory
   pathCopy(session->homeDir, session->rootDir, SFTP_SERVER_MAX_HOME_DIR_LEN);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set user's home directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] homeDir NULL-terminated string specifying the home directory
 * @return Error code
 **/

error_t sftpServerSetHomeDir(SftpServerSession *session, const char_t *homeDir)
{
   SftpServerContext *context;

   //Check parameters
   if(session == NULL || homeDir == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the SFTP server context
   context = session->context;

   //Set user's home directory
   pathCopy(session->homeDir, context->rootDir, SFTP_SERVER_MAX_HOME_DIR_LEN);
   pathCombine(session->homeDir, homeDir, SFTP_SERVER_MAX_HOME_DIR_LEN);

   //Clean the resulting path
   pathCanonicalize(session->homeDir);
   pathRemoveSlash(session->homeDir);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief SFTP server task
 * @param[in] param Pointer to the SFTP server context
 **/

void sftpServerTask(void *param)
{
   error_t error;
   uint_t i;
   systime_t timeout;
   SftpServerContext *context;
   SftpServerSession *session;

   //Point to the SFTP server context
   context = (SftpServerContext *) param;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Set polling timeout
      timeout = SFTP_SERVER_TICK_INTERVAL;

      //Clear event descriptor set
      osMemset(context->eventDesc, 0, sizeof(context->eventDesc));

      //Loop through SFTP sessions
      for(i = 0; i < context->numSessions; i++)
      {
         //Point to the structure describing the current session
         session = &context->sessions[i];

         //Active session?
         if(session->state != SFTP_SERVER_SESSION_STATE_CLOSED)
         {
            //Register session events
            sftpServerRegisterSessionEvents(session, &context->eventDesc[i]);

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
            //Stop SFTP server operation
            context->running = FALSE;
            //Task epilogue
            osExitTask();
            //Kill ourselves
            osDeleteTask(OS_SELF_TASK_ID);
         }

         //Loop through SFTP sessions
         for(i = 0; i < context->numSessions; i++)
         {
            //Point to the structure describing the current session
            session = &context->sessions[i];

            //Active session?
            if(session->state != SFTP_SERVER_SESSION_STATE_CLOSED)
            {
               //Check whether the channel is ready to perform I/O
               if(context->eventDesc[i].eventFlags != 0)
               {
                  //Session event handler
                  sftpServerProcessSessionEvents(session);
               }
            }
         }
      }

      //Handle periodic operations
      sftpServerTick(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release SFTP server context
 * @param[in] context Pointer to the SFTP server context
 **/

void sftpServerDeinit(SftpServerContext *context)
{
   //Make sure the SFTP server context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear SFTP server context
      osMemset(context, 0, sizeof(SftpServerContext));
   }
}

#endif
