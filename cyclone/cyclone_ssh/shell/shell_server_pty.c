/**
 * @file shell_server_pty.c
 * @brief Pseudo-terminal emulation
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
#define TRACE_LEVEL SHELL_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "shell/shell_server.h"
#include "shell/shell_server_pty.h"
#include "shell/shell_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_SERVER_SUPPORT == ENABLED)


/**
 * @brief Process window resize event
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessWindowResize(ShellServerSession *session)
{
   error_t error;
   uint_t x;
   uint_t y;
   uint_t cursorPos;
   char_t buffer[32];
   size_t n = 0;
   size_t i;
   uint32_t newTermWidth;
   uint32_t newTermHeight;

   //Acknowledge window resize event
   session->windowResize = FALSE;

   //Retrieve the new dimensions of the terminal
   newTermWidth = session->newTermWidth;
   newTermHeight = session->newTermHeight;

   //Check client's identification string
   if(osStrstr(session->channel->connection->clientId, "Bitvise") != NULL ||
      osStrstr(session->channel->connection->clientId, "PuTTY") != NULL ||
      osStrstr(session->channel->connection->clientId, "SmartFTP") != NULL ||
      osStrstr(session->channel->connection->clientId, "libssh2") != NULL)
   {
      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferPos;
      y = cursorPos / session->termWidth;

      //Clear command line
      n += osSprintf(buffer + n, "\r");

      if(y > 0)
      {
         n += osSprintf(buffer + n, VT100_MOVE_CURSOR_UP_N, y);
      }

      n += osSprintf(buffer + n, VT100_CLEAR_SCREEN_DOWN);

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Check status code
      if(!error)
      {
         //Display shell prompt
         error = sshWriteChannel(session->channel, session->prompt,
            session->promptLen, NULL, 0);
      }

      //Check status code
      if(!error)
      {
         //Display command line
         error = sshWriteChannel(session->channel, session->buffer,
            session->bufferLen, NULL, 0);
      }

      //Check status code
      if(!error)
      {
         //Determine the current position of the cursor
         cursorPos = session->promptLen + session->bufferLen;

         //Wrap to the next line if necessary
         if((cursorPos % newTermWidth) == 0)
         {
            error = sshWriteChannel(session->channel, " \r", 2, NULL, 0);
         }
      }
   }
   else if(osStrstr(session->channel->connection->clientId, "TTSSH") != NULL)
   {
      //Clear screen
      osSprintf(buffer, VT100_CLEAR_ENTIRE_SCREEN VT100_HOME);

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Check status code
      if(!error)
      {
         //Display shell prompt
         error = sshWriteChannel(session->channel, session->prompt,
            session->promptLen, NULL, 0);
      }

      //Display command line
      for(i = 0; i < session->bufferLen && !error; )
      {
         //Determine the current position of the cursor
         cursorPos = session->promptLen + i;
         n = cursorPos % newTermWidth;
         n = newTermWidth - n;

         n = MIN(n, session->bufferLen - i);

         error = sshWriteChannel(session->channel, session->buffer + i, n,
            NULL, 0);

         i += n;

         //Check status code
         if(!error)
         {
            //Determine the current position of the cursor
            cursorPos = session->promptLen + i;

            //Wrap to the next line if necessary
            if((cursorPos % newTermWidth) == 0)
            {
               error = sshWriteChannel(session->channel, "\r\n", 2, NULL, 0);
            }
         }
      }

      //Check status code
      if(!error)
      {
         //Determine the current position of the cursor
         cursorPos = session->promptLen + session->bufferPos;
         x = cursorPos % newTermWidth;
         y = cursorPos / newTermWidth;

         //Set cursor to home
         n = osSprintf(buffer, VT100_HOME);

         //Move cursor to the desired position
         if(y > 0)
         {
            n += osSprintf(buffer + n, VT100_MOVE_CURSOR_DOWN_N, y);
         }

         if(x > 0)
         {
            n += osSprintf(buffer + n, VT100_MOVE_CURSOR_RIGHT_N, x);
         }

         error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
            NULL, 0);
      }
   }
   else
   {
      //Ignore window resize event
      error = NO_ERROR;
   }

   //Update the dimensions of the terminal
   session->termWidth = newTermWidth;
   session->termHeight = newTermHeight;

   //Return status code
   return error;
}


/**
 * @brief Process received character
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessChar(ShellServerSession *session)
{
   error_t error;
   size_t n;
   char_t c;
   SshChannel *channel;

   //Retrieve SSH channel handle
   channel = session->channel;

   //Read a single character
   error = sshReadChannel(channel, &c, 1, &n, 0);

   //Check status code
   if(error == NO_ERROR)
   {
      //Check character code
      if(c == session->backspaceCode)
      {
         //Process backspace key
         error = shellServerProcessBackspaceKey(session);
      }
      else if(c == session->deleteCode)
      {
         //Process delete key
         error = shellServerProcessDeleteKey(session);
      }
      else if(session->escSeqLen > 0)
      {
         //Limit the length of the multibyte escape sequence
         if(session->escSeqLen < SHELL_SERVER_MAX_ESC_SEQ_LEN)
         {
            session->escSeq[session->escSeqLen++] = c;
            session->escSeq[session->escSeqLen] = '\0';
         }

         //End of escape sequence?
         if(isalpha(c) || c == '~')
         {
            //Decode multibyte escape sequence
            if(!osStrcmp(session->escSeq, VT100_DELETE))
            {
               error = shellServerProcessDeleteKey(session);
            }
            else if(!osStrcmp(session->escSeq, VT100_MOVE_CURSOR_LEFT))
            {
               error = shellServerProcessLeftKey(session);
            }
            else if(!osStrcmp(session->escSeq, VT100_MOVE_CURSOR_RIGHT))
            {
               error = shellServerProcessRightKey(session);
            }
            if(!osStrcmp(session->escSeq, VT100_MOVE_CURSOR_UP))
            {
               error = shellServerProcessUpKey(session);
            }
            else if(!osStrcmp(session->escSeq, VT100_MOVE_CURSOR_DOWN))
            {
               error = shellServerProcessDownKey(session);
            }
            if(!osStrcmp(session->escSeq, VT100_PAGE_UP))
            {
               error = shellServerProcessPageUpKey(session);
            }
            else if(!osStrcmp(session->escSeq, VT100_PAGE_DOWN))
            {
               error = shellServerProcessPageDownKey(session);
            }
            else
            {
               //Unknown escape sequence
            }

            //Clear escape sequence
            session->escSeqLen = 0;
         }
      }
      else if(c == VT100_ESC_CODE)
      {
         //Escape sequences start with an escape character
         session->escSeq[0] = c;
         session->escSeqLen = 1;
      }
      else if(c == '\r')
      {
         //Send a CRLF sequence to the client
         error = sshWriteChannel(channel, "\r\n", 2, NULL, 0);

         //Check status code
         if(!error)
         {
            //Properly terminate the command line with a NULL character
            session->buffer[session->bufferLen] = '\0';
            //Add command line to history
            shellServerAddCommandLine(session, session->buffer);
            //Process command line
            error = shellServerProcessCommandLine(session, session->buffer);
         }

         //Check status code
         if(!error)
         {
            //Display shell prompt
            error = sshWriteChannel(channel, session->prompt,
               osStrlen(session->prompt), NULL, 0);
         }

         //Flush the receive buffer and wait for the next command line
         session->bufferLen = 0;
         session->bufferPos = 0;
      }
      else
      {
         //Insert character at current position
         error = shellServerInsertChar(session, c);
      }
   }
   else if(error == ERROR_TIMEOUT)
   {
      //Wait for the next character
      error = NO_ERROR;
   }
   else
   {
      //A communication error has occurred
   }

   //Return status code
   return error;
}


/**
 * @brief Insert character at current position
 * @param[in] session Handle referencing an shell session
 * @param[in] c Character to be inserted
 * @return Error code
 **/

error_t shellServerInsertChar(ShellServerSession *session, char_t c)
{
   error_t error;
   uint_t cursorPos;
   char_t buffer[16];

   //Initialize status code
   error = NO_ERROR;

   //Limit the length of the command line
   if(session->bufferLen < (SHELL_SERVER_BUFFER_SIZE - 1))
   {
      //Check the position where the character is to be inserted
      if(session->bufferPos < session->bufferLen)
      {
         //Make room for the character
         osMemmove(session->buffer + session->bufferPos + 1,
            session->buffer + session->bufferPos,
            session->bufferLen - session->bufferPos);
      }

      //Insert character at current position
      session->buffer[session->bufferPos] = c;

      //Update the length of the command line
      session->bufferLen++;
      session->bufferPos++;

      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferPos;

      //Echo back the character to the client
      buffer[0] = c;
      buffer[1] = '\0';

      if((cursorPos % session->termWidth) == 0)
      {
         osStrcat(buffer, "\r\n");
      }

      if(session->bufferPos < session->bufferLen)
      {
         osStrcat(buffer, VT100_SAVE_CURSOR_POS);
      }

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Check the position where the character is to be inserted
      if(session->bufferPos < session->bufferLen)
      {
         //Check status code
         if(!error)
         {
            error = sshWriteChannel(session->channel,
               session->buffer + session->bufferPos,
               session->bufferLen - session->bufferPos, NULL, 0);
         }

         //Check status code
         if(!error)
         {
            osStrcpy(buffer, VT100_RESTORE_CURSOR_POS);

            error = sshWriteChannel(session->channel, buffer,
               osStrlen(buffer), NULL, 0);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Process backspace key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessBackspaceKey(ShellServerSession *session)
{
   error_t error;
   uint_t cursorPos;
   char_t buffer[16];

   //Initialize status code
   error = NO_ERROR;

   //Check the length of the command line
   if(session->bufferPos > 0)
   {
      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferPos;

      //Moving left at the edge of the screen wraps to the previous line
      if((cursorPos % session->termWidth) == 0)
      {
         osSprintf(buffer, VT100_MOVE_CURSOR_UP VT100_MOVE_CURSOR_RIGHT_N,
            (uint_t) (session->termWidth - 1));
      }
      else
      {
         osStrcpy(buffer, VT100_BACKSPACE);
      }

      //Check the position where the character is to be deleted
      if(session->bufferPos < session->bufferLen)
      {
         osStrcat(buffer, VT100_SAVE_CURSOR_POS);

         error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
            NULL, 0);

         //Check status code
         if(!error)
         {
            error = sshWriteChannel(session->channel,
               session->buffer + session->bufferPos,
               session->bufferLen - session->bufferPos, NULL, 0);
         }

         //Check status code
         if(!error)
         {
            osStrcpy(buffer, " " VT100_RESTORE_CURSOR_POS);

            error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
               NULL, 0);
         }

         //Delete character at current position
         osMemmove(session->buffer + session->bufferPos - 1,
            session->buffer + session->bufferPos,
            session->bufferLen - session->bufferPos);
      }
      else
      {
         osStrcat(buffer, VT100_CLEAR_SCREEN_DOWN);

         error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
            NULL, 0);
      }

      //Update the length of the command line
      session->bufferLen--;
      session->bufferPos--;
   }

   //Return status code
   return error;
}


/**
 * @brief Process delete key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessDeleteKey(ShellServerSession *session)
{
   error_t error;
   char_t buffer[16];

   //Initialize status code
   error = NO_ERROR;

   //Check the position where the character is to be deleted
   if(session->bufferPos < session->bufferLen)
   {
      //Save cursor position
      osStrcpy(buffer, VT100_SAVE_CURSOR_POS);

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Check status code
      if(!error)
      {
         error = sshWriteChannel(session->channel,
            session->buffer + session->bufferPos + 1,
            session->bufferLen - session->bufferPos - 1, NULL, 0);
      }

      //Check status code
      if(!error)
      {
         osStrcpy(buffer, " " VT100_RESTORE_CURSOR_POS);

         error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
            NULL, 0);
      }

      //Delete character at current position
      osMemmove(session->buffer + session->bufferPos,
         session->buffer + session->bufferPos + 1,
         session->bufferLen - session->bufferPos);

      //Update the length of the command line
      session->bufferLen--;
   }

   //Return status code
   return error;
}


/**
 * @brief Process left key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessLeftKey(ShellServerSession *session)
{
   error_t error;
   uint_t cursorPos;
   char_t buffer[16];

   //Initialize status code
   error = NO_ERROR;

   //Check the length of the command line
   if(session->bufferPos > 0)
   {
      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferPos;

      //Moving left at the edge of the screen wraps to the previous line
      if((cursorPos % session->termWidth) == 0)
      {
         osSprintf(buffer, VT100_MOVE_CURSOR_UP VT100_MOVE_CURSOR_RIGHT_N,
            (uint_t) (session->termWidth - 1));
      }
      else
      {
         osStrcpy(buffer, VT100_BACKSPACE);
      }

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Update current position
      session->bufferPos--;
   }

   //Return status code
   return error;
}


/**
 * @brief Process right key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessRightKey(ShellServerSession *session)
{
   error_t error;
   uint_t cursorPos;
   char_t buffer[16];

   //Initialize status code
   error = NO_ERROR;

   //Check current position
   if(session->bufferPos < session->bufferLen)
   {
      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferPos;

      //Moving right at the edge of the screen wraps to the next line
      if((cursorPos % session->termWidth) == (session->termWidth - 1))
      {
         osStrcpy(buffer, "\r\n");
      }
      else
      {
         osStrcpy(buffer, VT100_MOVE_CURSOR_RIGHT);
      }

      error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
         NULL, 0);

      //Update current position
      session->bufferPos++;
   }

   //Return status code
   return error;
}


/**
 * @brief Process up key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessUpKey(ShellServerSession *session)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *p;

   //Retrieve the previous command line from history
   error = shellServerGetPrevCommandLine(session, &p, &n);

   //Any entry found in history?
   if(!error)
   {
      //Restore command line
      error = shellRestoreCommandLine(session, p, n);
   }
   else
   {
      //The command history is empty
      error = NO_ERROR;
   }

   //Return status code
   return error;
#else
   //Ignore up key
   return NO_ERROR;
#endif
}


/**
 * @brief Process down key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessDownKey(ShellServerSession *session)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *p;

   //Retrieve the next command line from history
   error = shellServerGetNextCommandLine(session, &p, &n);

   //Any entry found in history?
   if(!error)
   {
      //Restore command line
      error = shellRestoreCommandLine(session, p, n);
   }
   else
   {
      //The command history is empty
      error = NO_ERROR;
   }

   //Return status code
   return error;
#else
   //Ignore down key
   return NO_ERROR;
#endif
}


/**
 * @brief Process page up key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessPageUpKey(ShellServerSession *session)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *p;

   //Retrieve the first command line from history
   error = shellServerGetFirstCommandLine(session, &p, &n);

   //Any entry found in history?
   if(!error)
   {
      //Restore command line
      error = shellRestoreCommandLine(session, p, n);
   }
   else
   {
      //The command history is empty
      error = NO_ERROR;
   }

   //Return status code
   return error;
#else
   //Ignore page up key
   return NO_ERROR;
#endif
}


/**
 * @brief Process page down key
 * @param[in] session Handle referencing an shell session
 * @return Error code
 **/

error_t shellServerProcessPageDownKey(ShellServerSession *session)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *p;

   //Retrieve the last command line from history
   error = shellServerGetLastCommandLine(session, &p, &n);

   //Any entry found in history?
   if(!error)
   {
      //Restore command line
      error = shellRestoreCommandLine(session, p, n);
   }
   else
   {
      //The command history is empty
      error = NO_ERROR;
   }

   //Return status code
   return error;
#else
   //Ignore page down key
   return NO_ERROR;
#endif
}


/**
 * @brief Clear command line
 * @param[in] session Handle referencing an shell session
 * @return error code
 **/

error_t shellClearCommandLine(ShellServerSession *session)
{
   error_t error;
   uint_t y;
   uint_t cursorPos;
   char_t buffer[32];
   size_t n;

   //Determine the current position of the cursor
   cursorPos = session->promptLen + session->bufferPos;
   y = cursorPos / session->termWidth;

   //Flush buffer
   session->bufferLen = 0;
   session->bufferPos = 0;

   //Clear command line
   n = osSprintf(buffer, "\r");

   if(y > 0)
   {
      n += osSprintf(buffer + n, VT100_MOVE_CURSOR_UP_N, y);
   }

   n += osSprintf(buffer + n, VT100_CLEAR_SCREEN_DOWN);

   error = sshWriteChannel(session->channel, buffer, osStrlen(buffer),
      NULL, 0);

   //Check status code
   if(!error)
   {
      //Display shell prompt
      error = sshWriteChannel(session->channel, session->prompt,
         session->promptLen, NULL, 0);
   }

   //Return status code
   return error;
}


/**
 * @brief Restore command line
 * @param[in] session Handle referencing an shell session
 * @param[in] commandLine Pointer to the command line
 * @param[in] length Length of the command line
 * @return error code
 **/

error_t shellRestoreCommandLine(ShellServerSession *session,
   const char_t *commandLine, size_t length)
{
   error_t error;
   uint_t cursorPos;

   //Clear entire line
   error = shellClearCommandLine(session);

   //Check status code
   if(!error)
   {
      //Restore command line
      osMemcpy(session->buffer, commandLine, length);
      session->bufferLen = length;
      session->bufferPos = length;

      //Display command line
      error = sshWriteChannel(session->channel, session->buffer,
         session->bufferLen, NULL, 0);
    }

   //Check status code
   if(!error)
   {
      //Determine the current position of the cursor
      cursorPos = session->promptLen + session->bufferLen;

      //Wrap to the next line if necessary
      if((cursorPos % session->termWidth) == 0)
      {
         error = sshWriteChannel(session->channel, " \r", 2, NULL, 0);
      }
   }

   //Return status code
   return error;
}

#endif
