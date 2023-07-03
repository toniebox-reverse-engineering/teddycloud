/**
 * @file os_port_sys_bios.c
 * @brief RTOS abstraction layer (SYS/BIOS)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
#define TRACE_LEVEL TRACE_LEVEL_OFF

//Dependencies
#include <stdio.h>
#include <stdlib.h>
#include "os_port.h"
#include "os_port_sys_bios.h"
#include "debug.h"

//Variables
static bool_t running = FALSE;


/**
 * @brief Kernel initialization
 **/

void osInitKernel(void)
{
   //The scheduler is not running
   running = FALSE;
}


/**
 * @brief Start kernel
 **/

void osStartKernel(void)
{
   //The scheduler is now running
   running = TRUE;
   //Start the scheduler
   BIOS_start();
}


/**
 * @brief Create a task
 * @param[in] name A name identifying the task
 * @param[in] taskCode Pointer to the task entry function
 * @param[in] param A pointer to a variable to be passed to the task
 * @param[in] stackSize The initial size of the stack, in words
 * @param[in] priority The priority at which the task should run
 * @return Task identifier referencing the newly created task
 **/

OsTaskId osCreateTask(const char_t *name, OsTaskCode taskCode,
   void *param, size_t stackSize, int_t priority)
{
   Error_Block eb;
   Task_Params taskParams;
   Task_Handle handle;

   //Initialize error block
   Error_init(&eb);

   //Set parameters
   Task_Params_init(&taskParams);
   taskParams.arg0 = (UArg) param;
   taskParams.stackSize = stackSize * sizeof(uint32_t);
   taskParams.priority = priority;

   //Create a new task
   handle = Task_create((Task_FuncPtr) taskCode, &taskParams, &eb);

   //Return a handle to the newly created task
   return (OsTaskId) handle;
}


/**
 * @brief Delete a task
 * @param[in] taskId Task identifier referencing the task to be deleted
 **/

void osDeleteTask(OsTaskId taskId)
{
   //Delete the specified task
   Task_delete(&taskId);
}


/**
 * @brief Delay routine
 * @param[in] delay Amount of time for which the calling task should block
 **/

void osDelayTask(systime_t delay)
{
   //Delay the task for the specified duration
   Task_sleep(OS_MS_TO_SYSTICKS(delay));
}


/**
 * @brief Yield control to the next task
 **/

void osSwitchTask(void)
{
   //Force a context switch
   Task_yield();
}


/**
 * @brief Suspend scheduler activity
 **/

void osSuspendAllTasks(void)
{
   //Make sure the operating system is running
   if(running)
   {
      //Disable the task scheduler
      Task_disable();
   }
}


/**
 * @brief Resume scheduler activity
 **/

void osResumeAllTasks(void)
{
   //Make sure the operating system is running
   if(running)
   {
      //Enable the task scheduler
      Task_enable();
   }
}


/**
 * @brief Create an event object
 * @param[in] event Pointer to the event object
 * @return The function returns TRUE if the event object was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateEvent(OsEvent *event)
{
   //Create an event object
   event->handle = Event_create(NULL, NULL);

   //Check whether the returned handle is valid
   if(event->handle != NULL)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete an event object
 * @param[in] event Pointer to the event object
 **/

void osDeleteEvent(OsEvent *event)
{
   //Make sure the handle is valid
   if(event->handle != NULL)
   {
      //Properly dispose the event object
      Event_delete(&event->handle);
   }
}


/**
 * @brief Set the specified event object to the signaled state
 * @param[in] event Pointer to the event object
 **/

void osSetEvent(OsEvent *event)
{
   //Set the specified event to the signaled state
   Event_post(event->handle, Event_Id_00);
}


/**
 * @brief Set the specified event object to the nonsignaled state
 * @param[in] event Pointer to the event object
 **/

void osResetEvent(OsEvent *event)
{
   //Force the specified event to the nonsignaled state
   Event_pend(event->handle, Event_Id_00, Event_Id_NONE, BIOS_NO_WAIT);
}


/**
 * @brief Wait until the specified event is in the signaled state
 * @param[in] event Pointer to the event object
 * @param[in] timeout Timeout interval
 * @return The function returns TRUE if the state of the specified object is
 *   signaled. FALSE is returned if the timeout interval elapsed
 **/

bool_t osWaitForEvent(OsEvent *event, systime_t timeout)
{
   Bool ret;

   //Wait until the specified event is in the signaled state or the timeout
   //interval elapses
   if(timeout == 0)
   {
      //Non-blocking call
      ret = Event_pend(event->handle, Event_Id_00,
         Event_Id_NONE, BIOS_NO_WAIT);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      ret = Event_pend(event->handle, Event_Id_00,
         Event_Id_NONE, BIOS_WAIT_FOREVER);
   }
   else
   {
      //Wait for the specified time interval
      ret = Event_pend(event->handle, Event_Id_00,
         Event_Id_NONE, OS_MS_TO_SYSTICKS(timeout));
   }

   //The return value tells whether the event is set
   return ret;
}


/**
 * @brief Set an event object to the signaled state from an interrupt service routine
 * @param[in] event Pointer to the event object
 * @return TRUE if setting the event to signaled state caused a task to unblock
 *   and the unblocked task has a priority higher than the currently running task
 **/

bool_t osSetEventFromIsr(OsEvent *event)
{
   //Set the specified event to the signaled state
   Event_post(event->handle, Event_Id_00);

   //The return value is not relevant
   return FALSE;
}


/**
 * @brief Create a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 * @param[in] count The maximum count for the semaphore object. This value
 *   must be greater than zero
 * @return The function returns TRUE if the semaphore was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateSemaphore(OsSemaphore *semaphore, uint_t count)
{
   Semaphore_Params semaphoreParams;

   //Set parameters
   Semaphore_Params_init(&semaphoreParams);
   semaphoreParams.mode = Semaphore_Mode_COUNTING;

   //Create a semaphore
   semaphore->handle = Semaphore_create(count, &semaphoreParams, NULL);

   //Check whether the returned handle is valid
   if(semaphore->handle != NULL)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osDeleteSemaphore(OsSemaphore *semaphore)
{
   //Make sure the handle is valid
   if(semaphore->handle != NULL)
   {
      //Properly dispose the specified semaphore
      Semaphore_delete(&semaphore->handle);
   }
}


/**
 * @brief Wait for the specified semaphore to be available
 * @param[in] semaphore Pointer to the semaphore object
 * @param[in] timeout Timeout interval
 * @return The function returns TRUE if the semaphore is available. FALSE is
 *   returned if the timeout interval elapsed
 **/

bool_t osWaitForSemaphore(OsSemaphore *semaphore, systime_t timeout)
{
   Bool ret;

   //Wait until the specified semaphore becomes available
   if(timeout == 0)
   {
      //Non-blocking call
      ret = Semaphore_pend(semaphore->handle, BIOS_NO_WAIT);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      ret = Semaphore_pend(semaphore->handle, BIOS_WAIT_FOREVER);
   }
   else
   {
      //Wait for the specified time interval
      ret = Semaphore_pend(semaphore->handle, OS_MS_TO_SYSTICKS(timeout));
   }

   //The return value tells whether the semaphore is available
   return ret;
}


/**
 * @brief Release the specified semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osReleaseSemaphore(OsSemaphore *semaphore)
{
   //Release the semaphore
   Semaphore_post(semaphore->handle);
}


/**
 * @brief Create a mutex object
 * @param[in] mutex Pointer to the mutex object
 * @return The function returns TRUE if the mutex was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateMutex(OsMutex *mutex)
{
   Semaphore_Params semaphoreParams;

   //Set parameters
   Semaphore_Params_init(&semaphoreParams);
   semaphoreParams.mode = Semaphore_Mode_BINARY_PRIORITY;

   //Create a mutex
   mutex->handle = Semaphore_create(1, &semaphoreParams, NULL);

   //Check whether the returned handle is valid
   if(mutex->handle != NULL)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete a mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osDeleteMutex(OsMutex *mutex)
{
   //Make sure the handle is valid
   if(mutex->handle != NULL)
   {
      //Properly dispose the specified mutex
      Semaphore_delete(&mutex->handle);
   }
}


/**
 * @brief Acquire ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osAcquireMutex(OsMutex *mutex)
{
   //Obtain ownership of the mutex object
   Semaphore_pend(mutex->handle, BIOS_WAIT_FOREVER);
}


/**
 * @brief Release ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osReleaseMutex(OsMutex *mutex)
{
   //Release ownership of the mutex object
   Semaphore_post(mutex->handle);
}


/**
 * @brief Retrieve system time
 * @return Number of milliseconds elapsed since the system was last started
 **/

systime_t osGetSystemTime(void)
{
   systime_t time;

   //Get current tick count
   time = Clock_getTicks();

   //Convert system ticks to milliseconds
   return OS_SYSTICKS_TO_MS(time);
}


/**
 * @brief Allocate a memory block
 * @param[in] size Bytes to allocate
 * @return A pointer to the allocated memory block or NULL if
 *   there is insufficient memory available
 **/

__weak_func void *osAllocMem(size_t size)
{
   void *p;

   //Enter critical section
   osSuspendAllTasks();
   //Allocate a memory block
   p = malloc(size);
   //Leave critical section
   osResumeAllTasks();

   //Debug message
   TRACE_DEBUG("Allocating %" PRIuSIZE " bytes at 0x%08" PRIXPTR "\r\n",
      size, (uintptr_t) p);

   //Return a pointer to the newly allocated memory block
   return p;
}


/**
 * @brief Release a previously allocated memory block
 * @param[in] p Previously allocated memory block to be freed
 **/

__weak_func void osFreeMem(void *p)
{
   //Make sure the pointer is valid
   if(p != NULL)
   {
      //Debug message
      TRACE_DEBUG("Freeing memory at 0x%08" PRIXPTR "\r\n", (uintptr_t) p);

      //Enter critical section
      osSuspendAllTasks();
      //Free memory block
      free(p);
      //Leave critical section
      osResumeAllTasks();
   }
}
