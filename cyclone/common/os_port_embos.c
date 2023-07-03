/**
 * @file os_port_embos.c
 * @brief RTOS abstraction layer (Segger embOS)
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
#include <string.h>
#include "os_port.h"
#include "os_port_embos.h"
#include "debug.h"


/**
 * @brief Kernel initialization
 **/

void osInitKernel(void)
{
   //Disable interrupts
   OS_IncDI();
   //Kernel initialization
   OS_InitKern();
   //Hardware initialization
   OS_InitHW();
}


/**
 * @brief Start kernel
 **/

void osStartKernel(void)
{
   //Start the scheduler
   OS_Start();
}


/**
 * @brief Create a task with statically allocated memory
 * @param[in] name A name identifying the task
 * @param[in] taskCode Pointer to the task entry function
 * @param[in] param A pointer to a variable to be passed to the task
 * @param[in] tcb Pointer to the task control block
 * @param[in] stack Pointer to the stack
 * @param[in] stackSize The initial size of the stack, in words
 * @param[in] priority The priority at which the task should run
 * @return Task identifier referencing the newly created task
 **/

OsTaskId osCreateStaticTask(const char_t *name, OsTaskCode taskCode,
   void *param, OsTaskTcb *tcb, OsStackType *stack, size_t stackSize,
   int_t priority)
{
   //Create a new task
   OS_CreateTaskEx(tcb, name, priority, taskCode, stack,
      stackSize * sizeof(uint32_t), 1, param);

   //Return a handle to the newly created task
   return tcb;
}


/**
 * @brief Delete a task
 * @param[in] taskId Task identifier referencing the task to be deleted
 **/

void osDeleteTask(OsTaskId taskId)
{
   //Delete the specified task
   OS_TerminateTask((OS_TASK *) taskId);
}


/**
 * @brief Delay routine
 * @param[in] delay Amount of time for which the calling task should block
 **/

void osDelayTask(systime_t delay)
{
   //Delay the task for the specified duration
   OS_Delay(OS_MS_TO_SYSTICKS(delay));
}


/**
 * @brief Yield control to the next task
 **/

void osSwitchTask(void)
{
   //Not implemented
}


/**
 * @brief Suspend scheduler activity
 **/

void osSuspendAllTasks(void)
{
   //Make sure the operating system is running
   if(OS_IsRunning())
   {
      //Suspend scheduler activity
      OS_SuspendAllTasks();
   }
}


/**
 * @brief Resume scheduler activity
 **/

void osResumeAllTasks(void)
{
   //Make sure the operating system is running
   if(OS_IsRunning())
   {
      //Resume scheduler activity
      OS_ResumeAllSuspendedTasks();
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
   OS_EVENT_Create(event);

   //The event object was successfully created
   return TRUE;
}


/**
 * @brief Delete an event object
 * @param[in] event Pointer to the event object
 **/

void osDeleteEvent(OsEvent *event)
{
   //Make sure the operating system is running
   if(OS_IsRunning())
   {
      //Properly dispose the event object
      OS_EVENT_Delete(event);
   }
}


/**
 * @brief Set the specified event object to the signaled state
 * @param[in] event Pointer to the event object
 **/

void osSetEvent(OsEvent *event)
{
   //Set the specified event to the signaled state
   OS_EVENT_Set(event);
}


/**
 * @brief Set the specified event object to the nonsignaled state
 * @param[in] event Pointer to the event object
 **/

void osResetEvent(OsEvent *event)
{
   //Force the specified event to the nonsignaled state
   OS_EVENT_Reset(event);
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
   bool_t ret;

   //Wait until the specified event is in the signaled state or the timeout
   //interval elapses
   if(timeout == 0)
   {
      //Non-blocking call
      ret = OS_EVENT_Get(event);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      OS_EVENT_Wait(event);
      ret = TRUE;
   }
   else
   {
      //Wait until the specified event becomes set
      ret = !OS_EVENT_WaitTimed(event, OS_MS_TO_SYSTICKS(timeout));
   }

   //The return value specifies whether the event is set
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
   OS_EVENT_Set(event);

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
   //Create a semaphore
   OS_CreateCSema(semaphore, count);

   //The event object was successfully created
   return TRUE;
}


/**
 * @brief Delete a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osDeleteSemaphore(OsSemaphore *semaphore)
{
   //Make sure the operating system is running
   if(OS_IsRunning())
   {
      //Properly dispose the specified semaphore
      OS_DeleteCSema(semaphore);
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
   bool_t ret;

   //Wait until the semaphore is available or the timeout interval elapses
   if(timeout == 0)
   {
      //Non-blocking call
      ret = OS_CSemaRequest(semaphore);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      OS_WaitCSema(semaphore);
      ret = TRUE;
   }
   else
   {
      //Wait until the specified semaphore becomes available
      ret = OS_WaitCSemaTimed(semaphore, OS_MS_TO_SYSTICKS(timeout));
   }

   //The return value specifies whether the semaphore is available
   return ret;
}


/**
 * @brief Release the specified semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osReleaseSemaphore(OsSemaphore *semaphore)
{
   //Release the semaphore
   OS_SignalCSema(semaphore);
}


/**
 * @brief Create a mutex object
 * @param[in] mutex Pointer to the mutex object
 * @return The function returns TRUE if the mutex was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateMutex(OsMutex *mutex)
{
   //Create a mutex
   OS_CreateRSema(mutex);

   //The mutex was successfully created
   return TRUE;
}


/**
 * @brief Delete a mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osDeleteMutex(OsMutex *mutex)
{
   //Make sure the operating system is running
   if(OS_IsRunning())
   {
      //Properly dispose the specified mutex
      OS_DeleteRSema(mutex);
   }
}


/**
 * @brief Acquire ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osAcquireMutex(OsMutex *mutex)
{
   //Obtain ownership of the mutex object
   OS_Use(mutex);
}


/**
 * @brief Release ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osReleaseMutex(OsMutex *mutex)
{
   //Release ownership of the mutex object
   OS_Unuse(mutex);
}


/**
 * @brief Retrieve system time
 * @return Number of milliseconds elapsed since the system was last started
 **/

systime_t osGetSystemTime(void)
{
   systime_t time;

   //Get current tick count
   time = OS_GetTime32();

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

   //Allocate a memory block
   p = OS_malloc(size);

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

      //Free memory block
      OS_free(p);
   }
}
