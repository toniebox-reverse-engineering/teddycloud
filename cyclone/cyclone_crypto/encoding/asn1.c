/**
 * @file asn1.c
 * @brief ASN.1 (Abstract Syntax Notation One)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (ASN1_SUPPORT == ENABLED)


/**
 * @brief Read an ASN.1 tag from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @return Error code
 **/

error_t asn1ReadTag(const uint8_t *data, size_t length, Asn1Tag *tag)
{
   uint_t i;
   uint_t n;

   //Make sure the identifier octet is present
   if(length == 0)
      return ERROR_INVALID_TAG;

   //Save the class of the ASN.1 tag
   tag->objClass = data[0] & ASN1_CLASS_MASK;
   //Primitive or constructed encoding?
   tag->constructed = (data[0] & ASN1_ENCODING_CONSTRUCTED) ? TRUE : FALSE;

   //Check the tag number
   if((data[0] & ASN1_TAG_NUMBER_MASK) < 31)
   {
      //Tag number is in the range 0 to 30
      tag->objType = data[0] & ASN1_TAG_NUMBER_MASK;
      //Point to the tag length field
      i = 1;
   }
   else
   {
      //If the tag number is greater than or equal to 31,
      //the subsequent octets will encode the tag number
      tag->objType = 0;

      //Decode the tag number
      for(i = 1; ; i++)
      {
         //The field cannot exceed 5 bytes
         if(i > (sizeof(tag->objType) + 1))
            return ERROR_INVALID_TAG;
         //Insufficient number of bytes to decode the tag number?
         if(!(length - i))
            return ERROR_INVALID_TAG;

         //Update the tag number with bits 7 to 1
         tag->objType = (tag->objType << 7) | (data[i] & 0x7F);

         //Bit 8 shall be set unless it is the last octet
         if(!(data[i] & 0x80))
            break;
      }
      //Point to the tag length field
      i++;
   }

   //Insufficient number of bytes to decode the tag length?
   if(!(length - i))
      return ERROR_INVALID_TAG;

   //Short form is used?
   if(data[i] < 128)
   {
      //Bits 7 to 1 encode the number of bytes in the contents
      tag->length = data[i];
      //Point to the contents of the tag
      i++;
   }
   //Long form is used?
   else if(data[i] > 128 && data[i] < 255)
   {
      //Bits 7 to 1 encode the number of octets in the length field
      n = data[i] & 0x7F;

      //The field cannot exceed 4 bytes
      if(n > sizeof(tag->length))
         return ERROR_INVALID_TAG;
      //Insufficient number of bytes to decode the tag length?
      if((length - i) < n)
         return ERROR_INVALID_TAG;

      //Clear the tag length
      tag->length = 0;

      //Read the subsequent octets
      for(i++; n > 0; n--)
      {
         tag->length = (tag->length << 8) | data[i++];
      }
   }
   //Indefinite form is used?
   else
   {
      //Indefinite form is not supported
      return ERROR_INVALID_TAG;
   }

   //Save the pointer to the tag contents
   tag->value = data + i;
   //Check the length of tag
   if((length - i) < tag->length)
      return ERROR_INVALID_TAG;

   //Total length occupied by the ASN.1 tag in the input stream
   tag->totalLength = i + tag->length;
   //ASN.1 tag successfully decoded
   return NO_ERROR;
}


/**
 * @brief Read an ASN.1 sequence from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @return Error code
 **/

error_t asn1ReadSequence(const uint8_t *data, size_t length, Asn1Tag *tag)
{
   error_t error;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);

   //Check status code
   if(!error)
   {
      //Enforce encoding, class and type
      error = asn1CheckTag(tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   }

   //Return status code
   return error;
}


/**
 * @brief Read an octet string from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @return Error code
 **/

error_t asn1ReadOctetString(const uint8_t *data, size_t length, Asn1Tag *tag)
{
   error_t error;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);

   //Check status code
   if(!error)
   {
      //Enforce encoding, class and type
      error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OCTET_STRING);
   }

   //Return status code
   return error;
}


/**
 * @brief Read an object identifier from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @return Error code
 **/

error_t asn1ReadOid(const uint8_t *data, size_t length, Asn1Tag *tag)
{
   error_t error;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);

   //Check status code
   if(!error)
   {
      //Enforce encoding, class and type
      error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OBJECT_IDENTIFIER);
   }

   //Return status code
   return error;
}


/**
 * @brief Read a boolean from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @param[out] value Boolean value
 * @return Error code
 **/

error_t asn1ReadBoolean(const uint8_t *data, size_t length, Asn1Tag *tag,
   bool_t *value)
{
   error_t error;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BOOLEAN);
   //Invalid tag?
   if(error)
      return error;

   //Make sure the length of the boolean is valid
   if(tag->length != 1)
      return ERROR_INVALID_LENGTH;

   //Read the value of the boolean
   *value = tag->value[0] ? TRUE : FALSE;

   //ASN.1 tag successfully decoded
   return NO_ERROR;
}


/**
 * @brief Read a 32-bit integer from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @param[out] value Integer value
 * @return Error code
 **/

error_t asn1ReadInt32(const uint8_t *data, size_t length, Asn1Tag *tag,
   int32_t *value)
{
   error_t error;
   size_t i;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //The contents shall consist of one or more octets
   if(tag->length < 1 || tag->length > 4)
      return ERROR_INVALID_TAG;

   //The contents octets shall be a two's complement binary
   //number equal to the integer value
   *value = (tag->value[0] & 0x80) ? -1 : 0;

   //Process contents octets
   for(i = 0; i < tag->length; i++)
   {
      //Rotate left operation
      *value <<= 8;
      //Reconstruct integer value
      *value |= tag->value[i];
   }

   //ASN.1 tag successfully decoded
   return NO_ERROR;
}


/**
 * @brief Write an ASN.1 tag
 * @param[in] tag Structure describing the ASN.1 tag
 * @param[in] reverse Use reverse encoding
 * @param[out] data Output stream where to write the tag (optional parameter)
 * @param[out] written Number of bytes written to the output stream (optional parameter)
 * @return Error code
 **/

error_t asn1WriteTag(Asn1Tag *tag, bool_t reverse, uint8_t *data,
   size_t *written)
{
   size_t i;
   size_t m;
   size_t n;

   //Compute the number of octets that are necessary to encode the tag number
   if(tag->objType < 31)
   {
      m = 0;
   }
   else if(tag->objType < 128)
   {
      m = 1;
   }
   else if(tag->objType < 16384)
   {
      m = 2;
   }
   else if(tag->objType < 2097152)
   {
      m = 3;
   }
   else if(tag->objType < 268435456)
   {
      m = 4;
   }
   else
   {
      m = 5;
   }

   //Compute the number of octets that are necessary to encode the length field
   if(tag->length < 128)
   {
      n = 0;
   }
   else if(tag->length < 256)
   {
      n = 1;
   }
   else if(tag->length < 65536)
   {
      n = 2;
   }
   else if(tag->length < 16777216)
   {
      n = 3;
   }
   else
   {
      n = 4;
   }

   //Valid output stream?
   if(data != NULL)
   {
      //Use reverse encoding?
      if(reverse)
      {
         //Any data to copy?
         if(tag->value != NULL && tag->length > 0)
         {
            //Make room for the data
            data -= tag->length;
            //Copy data
            osMemmove(data, tag->value, tag->length);
         }

         //Move backward
         data -= m + n + 2;
      }
      else
      {
         //Any data to copy?
         if(tag->value != NULL && tag->length > 0)
         {
            //Copy data
            osMemmove(data + m + n + 2, tag->value, tag->length);
         }
      }

      //Save the class of the ASN.1 tag
      data[0] = tag->objClass;

      //Primitive or constructed encoding?
      if(tag->constructed)
         data[0] |= ASN1_ENCODING_CONSTRUCTED;

      //Encode the tag number
      if(m == 0)
      {
         //Tag number is in the range 0 to 30
         data[0] |= tag->objType;
      }
      else
      {
         //The tag number is greater than or equal to 31
         data[0] |= ASN1_TAG_NUMBER_MASK;

         //The subsequent octets will encode the tag number
         for(i = 0; i < m; i++)
         {
            //Bits 7 to 1 encode the tag number
            data[m - i] = (tag->objType >> (i * 7)) & 0x7F;

            //Bit 8 of each octet shall be set to one unless it is the
            //last octet of the identifier octets
            if(i != 0)
               data[m - i] |= 0x80;
         }
      }

      //Encode the length field
      if(n == 0)
      {
         //Use short form encoding
         data[1 + m] = tag->length & 0x7F;
      }
      else
      {
         //Bits 7 to 1 encode the number of octets in the length field
         data[1 + m] = 0x80 | (n & 0x7F);

         //The subsequent octets will encode the length field
         for(i = 0; i < n; i++)
         {
            data[1 + m + n - i] = (tag->length >> (i * 8)) & 0xFF;
         }
      }
   }

   //Total length occupied by the ASN.1 tag
   tag->totalLength = tag->length + m + n + 2;

   //The last parameter is optional
   if(written != NULL)
   {
      //Number of bytes written to the output stream
      *written = m + n + 2;

      //Any data copied?
      if(tag->value != NULL)
         *written += tag->length;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write a 32-bit integer to the output stream
 * @param[in] value Integer value
 * @param[in] reverse Use reverse encoding
 * @param[out] data Output stream where to write the tag (optional parameter)
 * @param[out] written Number of bytes written to the output stream
 * @return Error code
 **/

error_t asn1WriteInt32(int32_t value, bool_t reverse, uint8_t *data,
   size_t *written)
{
   size_t i;
   size_t n;
   uint16_t msb;

   //An integer value is always encoded in the smallest possible number of
   //octets
   for(n = 4; n > 1; n--)
   {
      //Retrieve the upper 9 bits
      msb = (value >> (n * 8 - 9)) & 0x01FF;

      //The upper 9 bits shall not have the same value (all 0 or all 1)
      if(msb != 0x0000 && msb != 0x01FF)
         break;
   }

   //Valid output stream?
   if(data != NULL)
   {
      //Use reverse encoding?
      if(reverse)
         data -= n + 2;

      //Write tag type
      data[0] = ASN1_CLASS_UNIVERSAL | ASN1_TYPE_INTEGER;
      //Write tag length
      data[1] = n & 0xFF;

      //Write contents octets
      for(i = 0; i < n; i++)
      {
         data[1 + n - i] = (value >> (i * 8)) & 0xFF;
      }
   }

   //Number of bytes written to the output stream
   if(written != NULL)
      *written = n + 2;

   //Successful processing
   return NO_ERROR;
}


#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Read a multiple-precision integer from the input stream
 * @param[in] data Input stream where to read the tag
 * @param[in] length Number of bytes available in the input stream
 * @param[out] tag Structure describing the ASN.1 tag
 * @param[out] value Integer value
 * @return Error code
 **/

error_t asn1ReadMpi(const uint8_t *data, size_t length, Asn1Tag *tag,
   Mpi *value)
{
   error_t error;

   //Read ASN.1 tag
   error = asn1ReadTag(data, length, tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Negative integer?
   if(tag->length > 0 && (tag->value[0] & 0x80) != 0)
      return ERROR_INVALID_SYNTAX;

   //Convert the octet string to a multiple precision integer
   error = mpiImport(value, tag->value, tag->length, MPI_FORMAT_BIG_ENDIAN);

   //Return status code
   return error;
}


/**
 * @brief Write a multiple-precision integer from the output stream
 * @param[in] value Integer value
 * @param[in] reverse Use reverse encoding
 * @param[out] data Output stream where to write the tag (optional parameter)
 * @param[out] written Number of bytes written to the output stream
 * @return Error code
 **/

error_t asn1WriteMpi(const Mpi *value, bool_t reverse, uint8_t *data,
   size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Retrieve the length of the multiple precision integer
   n = mpiGetBitLength(value);

   //An integer value is always encoded in the smallest possible number of
   //octets
   n = (n / 8) + 1;

   //Valid output stream?
   if(data != NULL)
   {
      //Use reverse encoding?
      if(reverse)
         data -= n;

      //The value of the multiple precision integer is encoded MSB first
      error = mpiExport(value, data, n, MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }

   //The integer is encapsulated within an ASN.1 structure
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = n;
   tag.value = data;

   //Compute the length of the corresponding ASN.1 structure
   error = asn1WriteTag(&tag, FALSE, data, NULL);
   //Any error to report?
   if(error)
      return error;

   //Number of bytes written to the output stream
   if(written != NULL)
      *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}

#endif


/**
 * @brief Enforce the type of a specified tag
 * @param[in] tag Pointer to an ASN.1 tag
 * @param[in] constructed Expected encoding (TRUE for constructed, FALSE
 *   for primitive)
 * @param[in] objClass Expected tag class
 * @param[in] objType Expected tag type
 * @return Error code
 **/

error_t asn1CheckTag(const Asn1Tag *tag, bool_t constructed, uint_t objClass,
   uint_t objType)
{
   //Check encoding
   if(tag->constructed != constructed)
      return ERROR_WRONG_ENCODING;
   //Enforce class
   if(tag->objClass != objClass)
      return ERROR_INVALID_CLASS;
   //Enforce type
   if(tag->objType != objType)
      return ERROR_INVALID_TYPE;

   //The tag matches all the criteria
   return NO_ERROR;
}


/**
 * @brief Check ASN.1 tag against a specified OID
 * @param[in] tag Pointer to an ASN.1 tag
 * @param[in] oid Expected object identifier (OID)
 * @param[in] length Length of the OID
 * @return Error code
 **/

error_t asn1CheckOid(const Asn1Tag *tag, const uint8_t *oid, size_t length)
{
   error_t error;

   //Enforce encoding, class and type
   error = asn1CheckTag(tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
   //Any error to report?
   if(error)
      return error;

   //Compare OID against the specified value
   if(oidComp(tag->value, tag->length, oid, length))
      return ERROR_WRONG_IDENTIFIER;

   //The tag matches all the criteria
   return NO_ERROR;
}


/**
 * @brief Display an ASN.1 data object
 * @param[in] data Pointer to the ASN.1 object to dump
 * @param[in] length Length of the ASN.1 object
 * @param[in] level Current level of recursion (this parameter shall be set to 0)
 * @return Error code
 **/

error_t asn1DumpObject(const uint8_t *data, size_t length, uint_t level)
{
//Check debugging level
#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   error_t error;
   uint_t i;
   Asn1Tag tag;

   //ASN.1 universal types
   static const char_t *const label[32] =
   {
      "[0]",
      "BOOLEAN",
      "INTEGER",
      "BIT STRING",
      "OCTET STRING",
      "NULL",
      "OBJECT IDENTIFIER",
      "OBJECT DESCRIPTOR",
      "EXTERNAL",
      "REAL",
      "ENUMERATED",
      "[11]",
      "UTF8 STRING",
      "[13]",
      "[14]",
      "[15]",
      "SEQUENCE",
      "SET",
      "NUMERIC STRING",
      "PRINTABLE STRING",
      "TELETEX STRING",
      "VIDEOTEX STRING",
      "IA5 STRING",
      "UTC TIME",
      "GENERALIZED TIME",
      "GRAPHIC STRING",
      "VISIBLE STRING",
      "GENERAL STRING",
      "UNIVERSAL STRING",
      "[29]",
      "BMP STRING",
      "[31]"
   };

   //Prefix used to format the structure
   static const char_t *const prefix[10] =
   {
      "",
      "  ",
      "    ",
      "      ",
      "        ",
      "          ",
      "            ",
      "              ",
      "                ",
      "                  "
   };

   //Parse ASN.1 object
   while(length > 0)
   {
      //Decode current ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Decoding failed?
      if(error)
         return error;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Dump tag number, tag class, and contents length fields
      if(tag.objType < 32 && (tag.objClass & ASN1_CLASS_MASK) == ASN1_CLASS_UNIVERSAL)
      {
         TRACE_DEBUG("%s%s (%" PRIuSIZE " bytes)\r\n", prefix[level], label[tag.objType], tag.length);
      }
      else
      {
         TRACE_DEBUG("%s[%u] (%" PRIuSIZE " bytes)\r\n", prefix[level], tag.objType, tag.length);
      }

      //Constructed type?
      if(tag.constructed)
      {
         //Check whether the maximum level of recursion is reached
         if(level < 8)
         {
            //Recursive decoding of the ASN.1 tag
            error = asn1DumpObject(tag.value, tag.length, level + 1);
            //Decoding failed?
            if(error)
               return error;
         }
         else
         {
            //If the maximum level of recursion is reached, then dump contents
            TRACE_DEBUG_ARRAY(prefix[level + 1], tag.value, tag.length);
         }
      }
      //Primitive type?
      else
      {
         //Check the type of the current tag
         switch(tag.objType)
         {
         //OID?
         case ASN1_TYPE_OBJECT_IDENTIFIER:
            //Append prefix
            TRACE_DEBUG("%s", prefix[level + 1]);
            //Print OID
            TRACE_DEBUG("%s", oidToString(tag.value, tag.length, NULL, 0));
            //Add a line feed
            TRACE_DEBUG("\r\n");
            break;

         //String?
         case ASN1_TYPE_UTF8_STRING:
         case ASN1_TYPE_NUMERIC_STRING:
         case ASN1_TYPE_PRINTABLE_STRING:
         case ASN1_TYPE_TELETEX_STRING:
         case ASN1_TYPE_VIDEOTEX_STRING:
         case ASN1_TYPE_IA5_STRING:
         case ASN1_TYPE_GRAPHIC_STRING:
         case ASN1_TYPE_VISIBLE_STRING:
         case ASN1_TYPE_GENERAL_STRING:
         case ASN1_TYPE_UNIVERSAL_STRING:
         case ASN1_TYPE_BMP_STRING:
            //Append prefix
            TRACE_DEBUG("%s", prefix[level + 1]);

            //Dump the entire string
            for(i = 0; i < tag.length; i++)
            {
               TRACE_DEBUG("%c", tag.value[i]);
            }

            //Add a line feed
            TRACE_DEBUG("\r\n");
            break;

         //UTC time?
         case ASN1_TYPE_UTC_TIME:
            //Check length
            if(tag.length != 13)
               return ERROR_WRONG_ENCODING;
            //The encoding shall terminate with a "Z"
            if(tag.value[tag.length - 1] != 'Z')
               return ERROR_WRONG_ENCODING;

            //Append prefix
            TRACE_DEBUG("%s", prefix[level + 1]);
            //Display date
            TRACE_DEBUG("%c%c/%c%c/%c%c ", tag.value[0], tag.value[1],
               tag.value[2], tag.value[3], tag.value[4], tag.value[5]);
            //Display time
            TRACE_DEBUG("%c%c:%c%c:%c%c", tag.value[6], tag.value[7],
               tag.value[8], tag.value[9], tag.value[10], tag.value[11]);
            //Add a line feed
            TRACE_DEBUG("\r\n");
            break;

         //Generalized time?
         case ASN1_TYPE_GENERALIZED_TIME:
            //Check length
            if(tag.length != 15)
               return ERROR_WRONG_ENCODING;
            //The encoding shall terminate with a "Z"
            if(tag.value[tag.length - 1] != 'Z')
               return ERROR_WRONG_ENCODING;

            //Append prefix
            TRACE_DEBUG("%s", prefix[level + 1]);
            //Display date
            TRACE_DEBUG("%c%c%c%c/%c%c/%c%c ", tag.value[0], tag.value[1], tag.value[2],
               tag.value[3], tag.value[4], tag.value[5], tag.value[6], tag.value[7]);
            //Display time
            TRACE_DEBUG("%c%c:%c%c:%c%c", tag.value[8], tag.value[9],
               tag.value[10], tag.value[11], tag.value[12], tag.value[13]);
            //Add a line feed
            TRACE_DEBUG("\r\n");
            break;

         //Any other type?
         default:
            //Dump the contents of the tag
            TRACE_DEBUG_ARRAY(prefix[level + 1], tag.value, tag.length);
            break;
         }
      }
   }
#endif

   //ASN.1 object successfully decoded
   return NO_ERROR;
}

#endif
