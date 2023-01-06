/**
 * @file scp_common.c
 * @brief Definitions common to SCP client and server
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
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
#define TRACE_LEVEL SCP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_misc.h"
#include "scp/scp_common.h"
#include "debug.h"


/**
 * @brief Format SCP directive
 * @param[in] directive SCP directive parameters
 * @param[out] buffer Buffer where to format the directive line
 * @return Error code
 **/

size_t scpFormatDirective(const ScpDirective *directive, char_t *buffer)
{
   size_t n;

   //Length of the directive line
   n = 0;

   //Set directive opcode
   buffer[n++] = directive->opcode;

   //Check directive opcode
   if(directive->opcode == SCP_OPCODE_OK)
   {
      //Debug message
      TRACE_DEBUG("Sending SCP success directive...\r\n");
   }
   else if(directive->opcode == SCP_OPCODE_WARNING ||
      directive->opcode == SCP_OPCODE_ERROR)
   {
      //Warning and error directives can be followed by a textual description
      n += osSprintf(buffer + n, "%s\n", directive->message);

      //Debug message
      TRACE_DEBUG("Sending SCP error directive...\r\n");
   }
   else if(directive->opcode == SCP_OPCODE_FILE ||
      directive->opcode == SCP_OPCODE_DIR)
   {
      //The 'C' directive indicates the next file to be transferred. The 'D'
      //directive indicates a directory change
      n += osSprintf(buffer + n, "%04" PRIo32 " %" PRIu64 " %s\n",
         directive->mode, directive->size, directive->filename);

      //Debug message
      TRACE_DEBUG("Sending SCP '%c' directive...\r\n", directive->opcode);
   }
   else if(directive->opcode == SCP_OPCODE_END)
   {
      //The 'E' directive indicates the end of the directory
      buffer[n++] = '\n';

      //Debug message
      TRACE_DEBUG("Sending SCP '%c' directive...\r\n", directive->opcode);
   }
   else if(directive->opcode == SCP_OPCODE_TIME)
   {
      //The 'T' directive indicates that the next file to be transferred must
      //have mtime and atime attributes preserved
      n += osSprintf(buffer + n, "%" PRIu32 " 0 %" PRIu32 " 0\n",
         directive->mtime, directive->atime);

      //Debug message
      TRACE_DEBUG("Sending SCP '%c' directive...\r\n", directive->opcode);
   }
   else
   {
      //Unknown directive
   }

   //Return the length of the directive line
   return n;
}


/**
 * @brief Parse SCP directive
 * @param[in] buffer Pointer to the directive line
 * @param[out] directive SCP directive parameters
 * @return Error code
 **/

error_t scpParseDirective(const char_t *buffer, ScpDirective *directive)
{
   error_t error;
   char_t *p;

   //Initialize status code
   error = NO_ERROR;

   //Initialize SCP directive
   osMemset(directive, 0, sizeof(ScpDirective));

   //Save directive opcode
   directive->opcode = (ScpOpcode) buffer[0];

   //Check directive opcode
   if(directive->opcode == SCP_OPCODE_OK)
   {
      //Debug message
      TRACE_DEBUG("SCP success directive received...\r\n");
   }
   else if(directive->opcode == SCP_OPCODE_WARNING ||
      directive->opcode == SCP_OPCODE_ERROR)
   {
      //Debug message
      TRACE_DEBUG("SCP error directive received...\r\n");

      //Warning and error directives can be followed by a textual description
      directive->message = (char_t *) buffer + 1;
   }
   else if(directive->opcode == SCP_OPCODE_FILE ||
      directive->opcode == SCP_OPCODE_DIR)
   {
      //Debug message
      TRACE_DEBUG("SCP '%c' directive received...\r\n", directive->opcode);

      //Start of exception handling block
      do
      {
         //Get file permissions
         directive->mode = osStrtoul(buffer + 1, &p, 8);

         //Any syntax error?
         if(!osIsblank(*p))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Skip whitespace characters
         while(osIsblank(*p))
         {
            p++;
         }

         //Get the size of the file
         directive->size = osStrtoull(p, &p, 10);

         //Any syntax error?
         if(!osIsblank(*p))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Skip whitespace characters
         while(osIsblank(*p))
         {
            p++;
         }

         //Get the name of the file
         directive->filename = p;

         //End of exception handling block
      } while(0);
   }
   else if(directive->opcode == SCP_OPCODE_END)
   {
      //Debug message
      TRACE_DEBUG("SCP '%c' directive received...\r\n", directive->opcode);
   }
   else if(directive->opcode == SCP_OPCODE_TIME)
   {
      //Debug message
      TRACE_DEBUG("SCP '%c' directive received...\r\n", directive->opcode);

      //Start of exception handling block
      do
      {
         //Get modification time of the file (in seconds)
         directive->mtime = osStrtoul(buffer + 1, &p, 10);

         //Any syntax error?
         if(!osIsblank(*p))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Skip the microseconds field
         osStrtoul(p, &p, 10);

         //Any syntax error?
         if(!osIsblank(*p))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Get the access time of the file (in seconds)
         directive->atime = osStrtoul(p, &p, 10);

         //Any syntax error?
         if(!osIsblank(*p))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Skip the microseconds field
         osStrtoul(p, &p, 10);

         //Any syntax error?
         if(*p != '\0')
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //End of exception handling block
      } while(0);
   }
   else
   {
      //Debug message
      TRACE_WARNING("SCP unknown directive received...\r\n");

      //Unknown directive
      error = ERROR_INVALID_COMMAND;
   }

   //Return status code
   return error;
}
