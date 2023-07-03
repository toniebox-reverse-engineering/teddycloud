/**
 * @file date_time.c
 * @brief Date and time management
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

//Dependencies
#include <stdio.h>
#include <string.h>
#include "date_time.h"

#if defined(_WIN32)
   #include <time.h>
#endif

//Days
static const char days[8][10] =
{
   "",
   "Monday",
   "Tuesday",
   "Wednesday",
   "Thursday",
   "Friday",
   "Saturday",
   "Sunday"
};

//Months
static const char months[13][10] =
{
   "",
   "January",
   "February",
   "March",
   "April",
   "May",
   "June",
   "July",
   "August",
   "September",
   "October",
   "November",
   "December"
};


/**
 * @brief Format system time
 * @param[in] time System time
 * @param[out] str NULL-terminated string representing the specified time
 * @return Pointer to the formatted string
 **/

const char_t *formatSystemTime(systime_t time, char_t *str)
{
   uint16_t hours;
   uint8_t minutes;
   uint8_t seconds;
   uint16_t milliseconds;
   static char_t buffer[24];

   //Retrieve milliseconds
   milliseconds = time % 1000;
   time /= 1000;
   //Retrieve seconds
   seconds = time % 60;
   time /= 60;
   //Retrieve minutes
   minutes = time % 60;
   time /= 60;
   //Retrieve hours
   hours = time;

   //The str parameter is optional
   if(!str)
      str = buffer;

   //Format system time
   if(hours > 0)
   {
      osSprintf(str, "%" PRIu16 "h %02" PRIu8 "min %02" PRIu8 "s %03" PRIu16 "ms",
         hours, minutes, seconds, milliseconds);
   }
   else if(minutes > 0)
   {
      osSprintf(str, "%" PRIu8 "min %02" PRIu8 "s %03" PRIu16 "ms",
         minutes, seconds, milliseconds);
   }
   else if(seconds > 0)
   {
      osSprintf(str, "%" PRIu8 "s %03" PRIu16 "ms", seconds, milliseconds);
   }
   else
   {
      osSprintf(str, "%" PRIu16 "ms", milliseconds);
   }

   //Return a pointer to the formatted string
   return str;
}


/**
 * @brief Format date
 * @param[in] date Pointer to a structure representing the date
 * @param[out] str NULL-terminated string representing the specified date
 * @return Pointer to the formatted string
 **/

const char_t *formatDate(const DateTime *date, char_t *str)
{
   static char_t buffer[40];

   //The str parameter is optional
   if(!str)
      str = buffer;

   //Format date
   if(date->dayOfWeek)
   {
      osSprintf(str, "%s, %s %" PRIu8 ", %" PRIu16 " %02" PRIu8 ":%02" PRIu8 ":%02" PRIu8,
         days[MIN(date->dayOfWeek, 7)], months[MIN(date->month, 12)], date->day,
         date->year, date->hours, date->minutes, date->seconds);
   }
   else
   {
      osSprintf(str, "%s %" PRIu8 ", %" PRIu16 " %02" PRIu8 ":%02" PRIu8 ":%02" PRIu8,
         months[MIN(date->month, 12)], date->day, date->year,
         date->hours, date->minutes, date->seconds);
   }

   //Return a pointer to the formatted string
   return str;
}


/**
 * @brief Get current date and time
 * @param[out] date Pointer to a structure representing the date and time
 **/

void getCurrentDate(DateTime *date)
{
   //Retrieve current time
   time_t time = getCurrentUnixTime();

   //Convert Unix timestamp to date
   convertUnixTimeToDate(time, date);
}


/**
 * @brief Get current time
 * @return Unix timestamp
 **/

__weak_func time_t getCurrentUnixTime(void)
{
#if defined(_WIN32)
   //Retrieve current time
   return time(NULL);
#else
   //Not implemented
   return 0;
#endif
}


/**
 * @brief Convert Unix timestamp to date
 * @param[in] t Unix timestamp
 * @param[out] date Pointer to a structure representing the date and time
 **/

void convertUnixTimeToDate(time_t t, DateTime *date)
{
   uint32_t a;
   uint32_t b;
   uint32_t c;
   uint32_t d;
   uint32_t e;
   uint32_t f;

   //Negative Unix time values are not supported
   if(t < 1)
      t = 0;

   //Clear milliseconds
   date->milliseconds = 0;

   //Retrieve hours, minutes and seconds
   date->seconds = t % 60;
   t /= 60;
   date->minutes = t % 60;
   t /= 60;
   date->hours = t % 24;
   t /= 24;

   //Convert Unix time to date
   a = (uint32_t) ((4 * t + 102032) / 146097 + 15);
   b = (uint32_t) (t + 2442113 + a - (a / 4));
   c = (20 * b - 2442) / 7305;
   d = b - 365 * c - (c / 4);
   e = d * 1000 / 30601;
   f = d - e * 30 - e * 601 / 1000;

   //January and February are counted as months 13 and 14 of the previous year
   if(e <= 13)
   {
      c -= 4716;
      e -= 1;
   }
   else
   {
      c -= 4715;
      e -= 13;
   }

   //Retrieve year, month and day
   date->year = c;
   date->month = e;
   date->day = f;

   //Calculate day of week
   date->dayOfWeek = computeDayOfWeek(c, e, f);
}


/**
 * @brief Convert date to Unix timestamp
 * @param[in] date Pointer to a structure representing the date and time
 * @return Unix timestamp
 **/

time_t convertDateToUnixTime(const DateTime *date)
{
   uint_t y;
   uint_t m;
   uint_t d;
   uint32_t t;

   //Year
   y = date->year;
   //Month of year
   m = date->month;
   //Day of month
   d = date->day;

   //January and February are counted as months 13 and 14 of the previous year
   if(m <= 2)
   {
      m += 12;
      y -= 1;
   }

   //Convert years to days
   t = (365 * y) + (y / 4) - (y / 100) + (y / 400);
   //Convert months to days
   t += (30 * m) + (3 * (m + 1) / 5) + d;
   //Unix time starts on January 1st, 1970
   t -= 719561;
   //Convert days to seconds
   t *= 86400;
   //Add hours, minutes and seconds
   t += (3600 * date->hours) + (60 * date->minutes) + date->seconds;

   //Return Unix time
   return t;
}


/**
 * @brief Compare dates
 * @param[in] date1 Pointer to the first date
 * @param[in] date2 Pointer to the second date
 * @return Comparison result
 **/

int_t compareDateTime(const DateTime *date1, const DateTime *date2)
{
   int_t res;

   //Perform comparison
   if(date1->year < date2->year)
      res = -1;
   else if(date1->year > date2->year)
      res = 1;
   else if(date1->month < date2->month)
      res = -1;
   else if(date1->month > date2->month)
      res = 1;
   else if(date1->day < date2->day)
      res = -1;
   else if(date1->day > date2->day)
      res = 1;
   else if(date1->hours < date2->hours)
      res = -1;
   else if(date1->hours > date2->hours)
      res = 1;
   else if(date1->minutes < date2->minutes)
      res = -1;
   else if(date1->minutes > date2->minutes)
      res = 1;
   else if(date1->seconds < date2->seconds)
      res = -1;
   else if(date1->seconds > date2->seconds)
      res = 1;
   else if(date1->milliseconds < date2->milliseconds)
      res = -1;
   else if(date1->milliseconds > date2->milliseconds)
      res = 1;
   else
      res = 0;

   //Return comparison result
   return res;
}


/**
 * @brief Calculate day of week
 * @param[in] y Year
 * @param[in] m Month of year (in range 1 to 12)
 * @param[in] d Day of month (in range 1 to 31)
 * @return Day of week (in range 1 to 7)
 **/

uint8_t computeDayOfWeek(uint16_t y, uint8_t m, uint8_t d)
{
   uint_t h;
   uint_t j;
   uint_t k;

   //January and February are counted as months 13 and 14 of the previous year
   if(m <= 2)
   {
      m += 12;
      y -= 1;
   }

   //J is the century
   j = y / 100;
   //K the year of the century
   k = y % 100;

   //Compute H using Zeller's congruence
   h = d + (26 * (m + 1) / 10) + k + (k / 4) + (5 * j) + (j / 4);

   //Return the day of the week
   return ((h + 5) % 7) + 1;
}
