/**
 * @file os_port_rtx.c
 * @brief RTOS abstraction layer (Keil RTX)
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
#include "os_port_rtx.h"
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
 * @param[in] task Pointer to the task function to start after the kernel is initialized
 **/

void osStartKernel(OsInitTaskCode task)
{
   //The scheduler is now running
   running = TRUE;
   //Start the scheduler
   os_sys_init(task);
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
   OS_TID taskId;

   //Create a new task
   taskId = os_tsk_create_ex(taskCode, priority, param);

   //Return a handle to the newly created task
   return (OsTaskId) taskId;
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
   OS_TID taskId;

   //Create a new task
   taskId = os_tsk_create_user_ex(taskCode, priority, stack,
      stackSize * sizeof(uint32_t), param);

   //Return a handle to the newly created task
   return (OsTaskId) taskId;
}


/**
 * @brief Delete a task
 * @param[in] taskId Task identifier referencing the task to be deleted
 **/

void osDeleteTask(OsTaskId taskId)
{
   //Delete the currently running task?
   if(taskId == OS_SELF_TASK_ID)
   {
      //Kill ourselves
      os_tsk_delete_self();
   }
   else
   {
      //Delete the specified task
      os_tsk_delete((OS_TID) taskId);
   }
}


/**
 * @brief Delay routine
 * @param[in] delay Amount of time for which the calling task should block
 **/

void osDelayTask(systime_t delay)
{
   uint16_t n;

   //Convert milliseconds to system ticks
   delay = OS_MS_TO_SYSTICKS(delay);

   //Delay the task for the specified duration
   while(delay > 0)
   {
      //The delay value cannot be higher than 0xFFFE...
      n = MIN(delay, 0xFFFE);
      //Wait for the specified amount of time
      os_dly_wait(n);
      //Decrement delay value
      delay -= n;
   }
}


/**
 * @brief Yield control to the next task
 **/

void osSwitchTask(void)
{
   //Pass control to the next task
   os_tsk_pass();
}


/**
 * @brief Suspend scheduler activity
 **/

void osSuspendAllTasks(void)
{
   //Make sure the operating system is running
   if(running)
   {
      //Suspend all tasks
      tsk_lock();
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
      //Resume all tasks
      tsk_unlock();
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
   //Initialize the event object
   os_sem_init(event, 0);

   //Event successfully created
   return TRUE;
}


/**
 * @brief Delete an event object
 * @param[in] event Pointer to the event object
 **/

void osDeleteEvent(OsEvent *event)
{
   //No resource to release
}


/**
 * @brief Set the specified event object to the signaled state
 * @param[in] event Pointer to the event object
 **/

void osSetEvent(OsEvent *event)
{
   //Set the specified event to the signaled state
   os_sem_send(event);
}


/**
 * @brief Set the specified event object to the nonsignaled state
 * @param[in] event Pointer to the event object
 **/

void osResetEvent(OsEvent *event)
{
   OS_RESULT res;

   //Force the specified event to the nonsignaled state
   do
   {
      //Decrement the semaphore's count by one
      res = os_sem_wait(event, 0);

      //Check status
   } while(res == OS_R_OK);
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
   uint16_t n;
   OS_RESULT res;

   //Wait until the specified event is in the signaled state or the timeout
   //interval elapses
   if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      res = os_sem_wait(event, 0xFFFF);
   }
   else
   {
      //Convert milliseconds to system ticks
      timeout = OS_MS_TO_SYSTICKS(timeout);

      //Loop until the assigned time period has elapsed
      do
      {
         //The timeout value cannot be higher than 0xFFFE...
         n = MIN(timeout, 0xFFFE);
         //Wait for the specified time interval
         res = os_sem_wait(event, n);
         //Decrement timeout value
         timeout -= n;

         //Check timeout value
      } while(res == OS_R_TMO && timeout > 0);
   }

   //Check whether the specified event is set
   if(res == OS_R_OK || res == OS_R_SEM)
   {
      //Force the event back to the nonsignaled state
      do
      {
         //Decrement the semaphore's count by one
         res = os_sem_wait(event, 0);

         //Check status
      } while(res == OS_R_OK);

      //The specified event is in the signaled state
      return TRUE;
   }
   else
   {
      //The timeout interval elapsed
      return FALSE;
   }
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
   isr_sem_send(event);

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
   //Initialize the semaphore object
   os_sem_init(semaphore, count);

   //Semaphore successfully created
   return TRUE;
}


/**
 * @brief Delete a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osDeleteSemaphore(OsSemaphore *semaphore)
{
   //No resource to release
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
   uint16_t n;
   OS_RESULT res;

   //Wait until the semaphore is available or the timeout interval elapses
   if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      res = os_sem_wait(semaphore, 0xFFFF);
   }
   else
   {
      //Convert milliseconds to system ticks
      timeout = OS_MS_TO_SYSTICKS(timeout);

      //Loop until the assigned time period has elapsed
      do
      {
         //The timeout value cannot be higher than 0xFFFE...
         n = MIN(timeout, 0xFFFE);
         //Wait for the specified time interval
         res = os_sem_wait(semaphore, n);
         //Decrement timeout value
         timeout -= n;

         //Check timeout value
      } while(res == OS_R_TMO && timeout > 0);
   }

   //Check whether the specified semaphore is available
   if(res == OS_R_OK || res == OS_R_SEM)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Release the specified semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osReleaseSemaphore(OsSemaphore *semaphore)
{
   //Release the semaphore
   os_sem_send(semaphore);
}


/**
 * @brief Create a mutex object
 * @param[in] mutex Pointer to the mutex object
 * @return The function returns TRUE if the mutex was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateMutex(OsMutex *mutex)
{
   //Initialize the mutex object
   os_mut_init(mutex);

   //Mutex successfully created
   return TRUE;
}


/**
 * @brief Delete a mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osDeleteMutex(OsMutex *mutex)
{
   //No resource to release
}


/**
 * @brief Acquire ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osAcquireMutex(OsMutex *mutex)
{
   //Obtain ownership of the mutex object
   os_mut_wait(mutex, 0xFFFF);
}


/**
 * @brief Release ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osReleaseMutex(OsMutex *mutex)
{
   //Release ownership of the mutex object
   os_mut_release(mutex);
}


/**
 * @brief Retrieve system time
 * @return Number of milliseconds elapsed since the system was last started
 **/

systime_t osGetSystemTime(void)
{
   systime_t time;

   //Get current tick count
   time = os_time_get();

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
