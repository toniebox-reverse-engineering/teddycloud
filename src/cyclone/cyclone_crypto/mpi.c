/**
 * @file mpi.c
 * @brief MPI (Multiple Precision Integer Arithmetic)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

// Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

#pragma GCC optimize("O3")

// Dependencies
#include "core/crypto.h"
#include "mpi/mpi.h"
#include "debug.h"
#include "rand.h"
#include "tls_adapter.h"

// Check crypto library configuration
#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Initialize a multiple precision integer
 * @param[in,out] r Pointer to the multiple precision integer to be initialized
 **/

void mpiInit(Mpi *r)
{
   // Initialize structure
   r->sign = 1;
   r->size = 0;
   r->data = NULL;
}

/**
 * @brief Release a multiple precision integer
 * @param[in,out] r Pointer to the multiple precision integer to be freed
 **/

void mpiFree(Mpi *r)
{
   // Any memory previously allocated?
   if (r->data != NULL)
   {
      // Erase contents before releasing memory
      osMemset(r->data, 0, r->size * MPI_INT_SIZE);
      cryptoFreeMem(r->data);
   }

   // Set size to zero
   r->size = 0;
   r->data = NULL;
}

/**
 * @brief Adjust the size of multiple precision integer
 * @param[in,out] r A multiple precision integer whose size is to be increased
 * @param[in] size Desired size in words
 * @return Error code
 **/

error_t mpiGrow(Mpi *r, uint_t size)
{
   uint_t *data;

   // Ensure the parameter is valid
   size = MAX(size, 1);

   // Check the current size
   if (r->size >= size)
      return NO_ERROR;

   // Allocate a memory buffer
   data = cryptoAllocMem(size * MPI_INT_SIZE);
   // Failed to allocate memory?
   if (data == NULL)
      return ERROR_OUT_OF_MEMORY;

   // Clear buffer contents
   osMemset(data, 0, size * MPI_INT_SIZE);

   // Any data to copy?
   if (r->size > 0)
   {
      // Copy original data
      osMemcpy(data, r->data, r->size * MPI_INT_SIZE);
      // Free previously allocated memory
      cryptoFreeMem(r->data);
   }

   // Update the size of the multiple precision integer
   r->size = size;
   r->data = data;

   // Successful operation
   return NO_ERROR;
}

/**
 * @brief Get the actual length in words
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual length in words
 **/

uint_t mpiGetLength(const Mpi *a)
{
   int_t i;

   // Check whether the specified multiple precision integer is empty
   if (a->size == 0)
      return 0;

   // Start from the most significant word
   for (i = a->size - 1; i >= 0; i--)
   {
      // Loop as long as the current word is zero
      if (a->data[i] != 0)
         break;
   }

   // Return the actual length
   return i + 1;
}

/**
 * @brief Get the actual length in bytes
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual byte count
 **/

uint_t mpiGetByteLength(const Mpi *a)
{
   uint_t n;
   uint32_t m;

   // Check whether the specified multiple precision integer is empty
   if (a->size == 0)
      return 0;

   // Start from the most significant word
   for (n = a->size - 1; n > 0; n--)
   {
      // Loop as long as the current word is zero
      if (a->data[n] != 0)
         break;
   }

   // Get the current word
   m = a->data[n];
   // Convert the length to a byte count
   n *= MPI_INT_SIZE;

   // Adjust the byte count
   for (; m != 0; m >>= 8)
   {
      n++;
   }

   // Return the actual length in bytes
   return n;
}

/**
 * @brief Get the actual length in bits
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual bit count
 **/

uint_t mpiGetBitLength(const Mpi *a)
{
   uint_t n;
   uint32_t m;

   // Check whether the specified multiple precision integer is empty
   if (a->size == 0)
      return 0;

   // Start from the most significant word
   for (n = a->size - 1; n > 0; n--)
   {
      // Loop as long as the current word is zero
      if (a->data[n] != 0)
         break;
   }

   // Get the current word
   m = a->data[n];
   // Convert the length to a bit count
   n *= MPI_INT_SIZE * 8;

   // Adjust the bit count
   for (; m != 0; m >>= 1)
   {
      n++;
   }

   // Return the actual length in bits
   return n;
}

/**
 * @brief Set the bit value at the specified index
 * @param[in] r Pointer to a multiple precision integer
 * @param[in] index Position of the bit to be written
 * @param[in] value Bit value
 * @return Error code
 **/

error_t mpiSetBitValue(Mpi *r, uint_t index, uint_t value)
{
   error_t error;
   uint_t n1;
   uint_t n2;

   // Retrieve the position of the bit to be written
   n1 = index / (MPI_INT_SIZE * 8);
   n2 = index % (MPI_INT_SIZE * 8);

   // Ajust the size of the multiple precision integer if necessary
   error = mpiGrow(r, n1 + 1);
   // Failed to adjust the size?
   if (error)
      return error;

   // Set bit value
   if (value)
      r->data[n1] |= (1U << n2);
   else
      r->data[n1] &= ~(1U << n2);

   // No error to report
   return NO_ERROR;
}

/**
 * @brief Get the bit value at the specified index
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] index Position where to read the bit
 * @return The actual bit value
 **/

uint_t mpiGetBitValue(const Mpi *a, uint_t index)
{
   uint_t n1;
   uint_t n2;

   // Retrieve the position of the bit to be read
   n1 = index / (MPI_INT_SIZE * 8);
   n2 = index % (MPI_INT_SIZE * 8);

   // Index out of range?
   if (n1 >= a->size)
      return 0;

   // Return the actual bit value
   return (a->data[n1] >> n2) & 0x01;
}

/**
 * @brief Compare two multiple precision integers
 * @param[in] a The first multiple precision integer to be compared
 * @param[in] b The second multiple precision integer to be compared
 * @return Comparison result
 **/

int_t mpiComp(const Mpi *a, const Mpi *b)
{
   uint_t m;
   uint_t n;

   // Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   // Compare lengths
   if (!m && !n)
      return 0;
   else if (m > n)
      return a->sign;
   else if (m < n)
      return -b->sign;

   // Compare signs
   if (a->sign > 0 && b->sign < 0)
      return 1;
   else if (a->sign < 0 && b->sign > 0)
      return -1;

   // Then compare values
   while (n--)
   {
      if (a->data[n] > b->data[n])
         return a->sign;
      else if (a->data[n] < b->data[n])
         return -a->sign;
   }

   // Multiple precision integers are equals
   return 0;
}

/**
 * @brief Compare a multiple precision integer with an integer
 * @param[in] a Multiple precision integer to be compared
 * @param[in] b Integer to be compared
 * @return Comparison result
 **/

int_t mpiCompInt(const Mpi *a, int_t b)
{
   uint_t value;
   Mpi t;

   // Initialize a temporary multiple precision integer
   value = (b >= 0) ? b : -b;
   t.sign = (b >= 0) ? 1 : -1;
   t.size = 1;
   t.data = &value;

   // Return comparison result
   return mpiComp(a, &t);
}

/**
 * @brief Compare the absolute value of two multiple precision integers
 * @param[in] a The first multiple precision integer to be compared
 * @param[in] b The second multiple precision integer to be compared
 * @return Comparison result
 **/

int_t mpiCompAbs(const Mpi *a, const Mpi *b)
{
   uint_t m;
   uint_t n;

   // Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   // Compare lengths
   if (!m && !n)
      return 0;
   else if (m > n)
      return 1;
   else if (m < n)
      return -1;

   // Then compare values
   while (n--)
   {
      if (a->data[n] > b->data[n])
         return 1;
      else if (a->data[n] < b->data[n])
         return -1;
   }

   // Operands are equals
   return 0;
}

/**
 * @brief Copy a multiple precision integer
 * @param[out] r Pointer to a multiple precision integer (destination)
 * @param[in] a Pointer to a multiple precision integer (source)
 * @return Error code
 **/

error_t mpiCopy(Mpi *r, const Mpi *a)
{
   error_t error;
   uint_t n;

   // R and A are the same instance?
   if (r == a)
      return NO_ERROR;

   // Determine the actual length of A
   n = mpiGetLength(a);

   // Ajust the size of the destination operand
   error = mpiGrow(r, n);
   // Any error to report?
   if (error)
      return error;

   // Clear the contents of the multiple precision integer
   osMemset(r->data, 0, r->size * MPI_INT_SIZE);
   // Let R = A
   osMemcpy(r->data, a->data, n * MPI_INT_SIZE);
   // Set the sign of R
   r->sign = a->sign;

   // Successful operation
   return NO_ERROR;
}

/**
 * @brief Set the value of a multiple precision integer
 * @param[out] r Pointer to a multiple precision integer
 * @param[in] a Value to be assigned to the multiple precision integer
 * @return Error code
 **/

error_t mpiSetValue(Mpi *r, int_t a)
{
   error_t error;

   // Ajust the size of the destination operand
   error = mpiGrow(r, 1);
   // Failed to adjust the size?
   if (error)
      return error;

   // Clear the contents of the multiple precision integer
   osMemset(r->data, 0, r->size * MPI_INT_SIZE);
   // Set the value or R
   r->data[0] = (a >= 0) ? a : -a;
   // Set the sign of R
   r->sign = (a >= 0) ? 1 : -1;

   // Successful operation
   return NO_ERROR;
}

/**
 * @brief Generate a random value
 * @param[out] r Pointer to a multiple precision integer
 * @param[in] length Desired length in bits
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t mpiRand(Mpi *r, uint_t length, const PrngAlgo *prngAlgo,
                void *prngContext)
{
   error_t error;
   uint_t m;
   uint_t n;

   // Compute the required length, in words
   n = (length + (MPI_INT_SIZE * 8) - 1) / (MPI_INT_SIZE * 8);
   // Number of bits in the most significant word
   m = length % (MPI_INT_SIZE * 8);

   // Ajust the size of the multiple precision integer if necessary
   error = mpiGrow(r, n);
   // Failed to adjust the size?
   if (error)
      return error;

   // Clear the contents of the multiple precision integer
   osMemset(r->data, 0, r->size * MPI_INT_SIZE);
   // Set the sign of R
   r->sign = 1;

   // Generate a random pattern
   error = prngAlgo->read(prngContext, (uint8_t *)r->data, n * MPI_INT_SIZE);
   // Any error to report?
   if (error)
      return error;

   // Remove the meaningless bits in the most significant word
   if (n > 0 && m > 0)
   {
      r->data[n - 1] &= (1 << m) - 1;
   }

   // Successful operation
   return NO_ERROR;
}

/**
 * @brief Generate a random value in the range 1 to p-1
 * @param[out] r Pointer to a multiple precision integer
 * @param[in] p The upper bound of the range
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t mpiRandRange(Mpi *r, const Mpi *p, const PrngAlgo *prngAlgo,
                     void *prngContext)
{
   error_t error;
   uint_t n;
   Mpi a;

   // Make sure p is greater than 1
   if (mpiCompInt(p, 1) <= 0)
      return ERROR_INVALID_PARAMETER;

   // Initialize multiple precision integer
   mpiInit(&a);

   // Get the actual length of p
   n = mpiGetBitLength(p);

   // Generate extra random bits so that the bias produced by the modular
   // reduction is negligible
   MPI_CHECK(mpiRand(r, n + 64, prngAlgo, prngContext));

   // Compute r = (r mod (p - 1)) + 1
   MPI_CHECK(mpiSubInt(&a, p, 1));
   MPI_CHECK(mpiMod(r, r, &a));
   MPI_CHECK(mpiAddInt(r, r, 1));

end:
   // Release previously allocated memory
   mpiFree(&a);

   // Return status code
   return error;
}

/* https://github.com/cslarsen/miller-rabin */
bool mpiCheckProbablePrimeWorker(const Mpi *n, int k, const PrngAlgo *prngAlgo, void *prngContext)
{
   bool ret = false;

   /* keep Mpi numbers initialized outside loop */
   Mpi randRange;
   Mpi num1;
   Mpi num2;
   Mpi x2;
   Mpi a;
   Mpi rnd;
   Mpi x;
   Mpi m;
   Mpi n1;
   Mpi sShifted;
   Mpi d;

   mpiInit(&m);
   mpiInit(&n1);
   mpiInit(&sShifted);
   mpiInit(&d);
   mpiInit(&randRange);
   mpiInit(&num1);
   mpiInit(&num2);
   mpiInit(&x2);
   mpiInit(&a);
   mpiInit(&rnd);
   mpiInit(&x);

   mpiSubInt(&m, n, 1);

   int s = 0;

   while (!mpiGetBitValue(&m, s))
   {
      s++;
   }
   mpiShiftRight(&m, s);

   mpiSubInt(&n1, n, 1);

   mpiSetValue(&sShifted, 1);
   mpiShiftLeft(&sShifted, s);

   mpiDiv(&d, NULL, &n1, &sShifted);

   /* randrange shall go from [2..n-2], so prepare consts for 1 + [1..n-3] */
   mpiSubInt(&randRange, n, 3);
   mpiSetValue(&num1, 1);
   mpiSetValue(&num2, 2);

   for (int i = 0; i < k; i++)
   {
      /* creates a rand between 1 and p-1, including boundaries. upper bounds already corrected */
      mpiRandRange(&rnd, &randRange, prngAlgo, prngContext);
      /* now just add one */
      mpiAddAbs(&a, &rnd, &num1);

      mpiExpMod(&x, &a, &d, n);

      if (!mpiCompInt(&x, 1) || !mpiComp(&x, &n1))
      {
         continue;
      }

      for (int r = 1; r <= s - 1; r++)
      {
         mpiExpMod(&x2, &x, &num2, n);

         if (!mpiCompInt(&x2, 1))
         {
            goto finish;
         }
         if (!mpiComp(&x2, &n1))
         {
            goto LOOP;
         }
      }

      goto finish;
   LOOP:
      continue;
   }

   /* n is *probably* prime */
   ret = true;

finish:
   mpiFree(&m);
   mpiFree(&n1);
   mpiFree(&sShifted);
   mpiFree(&d);
   mpiFree(&randRange);
   mpiFree(&num1);
   mpiFree(&num2);
   mpiFree(&x2);
   mpiFree(&a);
   mpiFree(&rnd);
   mpiFree(&x);

   return ret;
}

/**
 * @brief Test whether a number is probable prime
 * @param[in] a Pointer to a multiple precision integer
 * @return Error code
 **/

__weak_func error_t mpiCheckProbablePrime(const Mpi *a)
{
   uint_t k;
   size_t n;

   // Retrieve the length of the input integer, in bits
   n = mpiGetBitLength(a);

   // Prime numbers of a size lower than 96 bits cannot be tested by this
   // service
   if (n < 96)
      return ERROR_INVALID_LENGTH;

   // The number of repetitions controls the error probability
   if (n >= 1300)
   {
      k = 2;
   }
   else if (n >= 850)
   {
      k = 3;
   }
   else if (n >= 650)
   {
      k = 4;
   }
   else if (n >= 550)
   {
      k = 5;
   }
   else if (n >= 450)
   {
      k = 6;
   }
   else if (n >= 400)
   {
      k = 7;
   }
   else if (n >= 350)
   {
      k = 8;
   }
   else if (n >= 300)
   {
      k = 9;
   }
   else if (n >= 250)
   {
      k = 12;
   }
   else if (n >= 200)
   {
      k = 15;
   }
   else if (n >= 150)
   {
      k = 18;
   }
   else
   {
      k = 27;
   }

   /* hardcoded to tls_adapter's PRNG  (╯°□°）╯︵ ┻━┻ */
   if (mpiCheckProbablePrimeWorker(a, k, rand_get_algo(), rand_get_context()))
   {
      return NO_ERROR;
   }

   return ERROR_INVALID_VALUE;
}

/**
 * @brief Octet string to integer conversion
 *
 * Converts an octet string to a non-negative integer
 *
 * @param[out] r Non-negative integer resulting from the conversion
 * @param[in] data Octet string to be converted
 * @param[in] length Length of the octet string
 * @param[in] format Input format
 * @return Error code
 **/

error_t mpiImport(Mpi *r, const uint8_t *data, uint_t length, MpiFormat format)
{
   error_t error;
   uint_t i;

   // Check input format
   if (format == MPI_FORMAT_LITTLE_ENDIAN)
   {
      // Skip trailing zeroes
      while (length > 0 && data[length - 1] == 0)
      {
         length--;
      }

      // Ajust the size of the multiple precision integer
      error = mpiGrow(r, (length + MPI_INT_SIZE - 1) / MPI_INT_SIZE);

      // Check status code
      if (!error)
      {
         // Clear the contents of the multiple precision integer
         osMemset(r->data, 0, r->size * MPI_INT_SIZE);
         // Set sign
         r->sign = 1;

         // Import data
         for (i = 0; i < length; i++, data++)
         {
            r->data[i / MPI_INT_SIZE] |= *data << ((i % MPI_INT_SIZE) * 8);
         }
      }
   }
   else if (format == MPI_FORMAT_BIG_ENDIAN)
   {
      // Skip leading zeroes
      while (length > 1 && *data == 0)
      {
         data++;
         length--;
      }

      // Ajust the size of the multiple precision integer
      error = mpiGrow(r, (length + MPI_INT_SIZE - 1) / MPI_INT_SIZE);

      // Check status code
      if (!error)
      {
         // Clear the contents of the multiple precision integer
         osMemset(r->data, 0, r->size * MPI_INT_SIZE);
         // Set sign
         r->sign = 1;

         // Start from the least significant byte
         data += length - 1;

         // Import data
         for (i = 0; i < length; i++, data--)
         {
            r->data[i / MPI_INT_SIZE] |= *data << ((i % MPI_INT_SIZE) * 8);
         }
      }
   }
   else
   {
      // Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   // Return status code
   return error;
}

/**
 * @brief Integer to octet string conversion
 *
 * Converts an integer to an octet string of a specified length
 *
 * @param[in] a Non-negative integer to be converted
 * @param[out] data Octet string resulting from the conversion
 * @param[in] length Intended length of the resulting octet string
 * @param[in] format Output format
 * @return Error code
 **/

error_t mpiExport(const Mpi *a, uint8_t *data, uint_t length, MpiFormat format)
{
   uint_t i;
   uint_t n;
   error_t error;

   // Initialize status code
   error = NO_ERROR;

   // Check input format
   if (format == MPI_FORMAT_LITTLE_ENDIAN)
   {
      // Get the actual length in bytes
      n = mpiGetByteLength(a);

      // Make sure the output buffer is large enough
      if (n <= length)
      {
         // Clear output buffer
         osMemset(data, 0, length);

         // Export data
         for (i = 0; i < n; i++, data++)
         {
            *data = a->data[i / MPI_INT_SIZE] >> ((i % MPI_INT_SIZE) * 8);
         }
      }
      else
      {
         // Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else if (format == MPI_FORMAT_BIG_ENDIAN)
   {
      // Get the actual length in bytes
      n = mpiGetByteLength(a);

      // Make sure the output buffer is large enough
      if (n <= length)
      {
         // Clear output buffer
         osMemset(data, 0, length);

         // Point to the least significant word
         data += length - 1;

         // Export data
         for (i = 0; i < n; i++, data--)
         {
            *data = a->data[i / MPI_INT_SIZE] >> ((i % MPI_INT_SIZE) * 8);
         }
      }
      else
      {
         // Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
   {
      // Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   // Return status code
   return error;
}

/**
 * @brief Multiple precision addition
 * @param[out] r Resulting integer R = A + B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiAdd(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   int_t sign;

   // Retrieve the sign of A
   sign = a->sign;

   // Both operands have the same sign?
   if (a->sign == b->sign)
   {
      // Perform addition
      error = mpiAddAbs(r, a, b);
      // Set the sign of the resulting number
      r->sign = sign;
   }
   // Operands have different signs?
   else
   {
      // Compare the absolute value of A and B
      if (mpiCompAbs(a, b) >= 0)
      {
         // Perform subtraction
         error = mpiSubAbs(r, a, b);
         // Set the sign of the resulting number
         r->sign = sign;
      }
      else
      {
         // Perform subtraction
         error = mpiSubAbs(r, b, a);
         // Set the sign of the resulting number
         r->sign = -sign;
      }
   }

   // Return status code
   return error;
}

/**
 * @brief Add an integer to a multiple precision integer
 * @param[out] r Resulting integer R = A + B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiAddInt(Mpi *r, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi t;

   // Convert the second operand to a multiple precision integer
   value = (b >= 0) ? b : -b;
   t.sign = (b >= 0) ? 1 : -1;
   t.size = 1;
   t.data = &value;

   // Perform addition
   return mpiAdd(r, a, &t);
}

/**
 * @brief Multiple precision subtraction
 * @param[out] r Resulting integer R = A - B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiSub(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   int_t sign;

   // Retrieve the sign of A
   sign = a->sign;

   // Both operands have the same sign?
   if (a->sign == b->sign)
   {
      // Compare the absolute value of A and B
      if (mpiCompAbs(a, b) >= 0)
      {
         // Perform subtraction
         error = mpiSubAbs(r, a, b);
         // Set the sign of the resulting number
         r->sign = sign;
      }
      else
      {
         // Perform subtraction
         error = mpiSubAbs(r, b, a);
         // Set the sign of the resulting number
         r->sign = -sign;
      }
   }
   // Operands have different signs?
   else
   {
      // Perform addition
      error = mpiAddAbs(r, a, b);
      // Set the sign of the resulting number
      r->sign = sign;
   }

   // Return status code
   return error;
}

/**
 * @brief Subtract an integer from a multiple precision integer
 * @param[out] r Resulting integer R = A - B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiSubInt(Mpi *r, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi t;

   // Convert the second operand to a multiple precision integer
   value = (b >= 0) ? b : -b;
   t.sign = (b >= 0) ? 1 : -1;
   t.size = 1;
   t.data = &value;

   // Perform subtraction
   return mpiSub(r, a, &t);
}

/**
 * @brief Helper routine for multiple precision addition
 * @param[out] r Resulting integer R = |A + B|
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiAddAbs(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t i;
   uint_t n;
   uint_t c;
   uint_t d;

   // R and B are the same instance?
   if (r == b)
   {
      // Swap A and B
      const Mpi *t = a;
      a = b;
      b = t;
   }
   // R is neither A nor B?
   else if (r != a)
   {
      // Copy the first operand to R
      MPI_CHECK(mpiCopy(r, a));
   }

   // Determine the actual length of B
   n = mpiGetLength(b);
   // Extend the size of the destination register as needed
   MPI_CHECK(mpiGrow(r, n));

   // The result is always positive
   r->sign = 1;
   // Clear carry bit
   c = 0;

   // Add operands
   for (i = 0; i < n; i++)
   {
      // Add carry bit
      d = r->data[i] + c;
      // Update carry bit
      if (d != 0)
         c = 0;
      // Perform addition
      d += b->data[i];
      // Update carry bit
      if (d < b->data[i])
         c = 1;
      // Save result
      r->data[i] = d;
   }

   // Loop as long as the carry bit is set
   for (i = n; c && i < r->size; i++)
   {
      // Add carry bit
      r->data[i] += c;
      // Update carry bit
      if (r->data[i] != 0)
         c = 0;
   }

   // Check the final carry bit
   if (c && n >= r->size)
   {
      // Extend the size of the destination register
      MPI_CHECK(mpiGrow(r, n + 1));
      // Add carry bit
      r->data[n] = 1;
   }

end:
   // Return status code
   return error;
}

/**
 * @brief Helper routine for multiple precision subtraction
 * @param[out] r Resulting integer R = |A - B|
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiSubAbs(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t c;
   uint_t d;
   uint_t i;
   uint_t m;
   uint_t n;

   // Check input parameters
   if (mpiCompAbs(a, b) < 0)
   {
      // Swap A and B if necessary
      const Mpi *t = b;
      a = b;
      b = t;
   }

   // Determine the actual length of A
   m = mpiGetLength(a);
   // Determine the actual length of B
   n = mpiGetLength(b);

   // Extend the size of the destination register as needed
   MPI_CHECK(mpiGrow(r, m));

   // The result is always positive
   r->sign = 1;
   // Clear carry bit
   c = 0;

   // Subtract operands
   for (i = 0; i < n; i++)
   {
      // Read first operand
      d = a->data[i];

      // Check the carry bit
      if (c)
      {
         // Update carry bit
         if (d != 0)
            c = 0;
         // Propagate carry bit
         d -= 1;
      }

      // Update carry bit
      if (d < b->data[i])
         c = 1;
      // Perform subtraction
      r->data[i] = d - b->data[i];
   }

   // Loop as long as the carry bit is set
   for (i = n; c && i < m; i++)
   {
      // Update carry bit
      if (a->data[i] != 0)
         c = 0;
      // Propagate carry bit
      r->data[i] = a->data[i] - 1;
   }

   // R and A are not the same instance?
   if (r != a)
   {
      // Copy the remaining words
      for (; i < m; i++)
      {
         r->data[i] = a->data[i];
      }

      // Zero the upper part of R
      for (; i < r->size; i++)
      {
         r->data[i] = 0;
      }
   }

end:
   // Return status code
   return error;
}

/**
 * @brief Left shift operation
 * @param[in,out] r The multiple precision integer to be shifted to the left
 * @param[in] n The number of bits to shift
 * @return Error code
 **/

error_t mpiShiftLeft(Mpi *r, uint_t n)
{
   error_t error;
   uint_t i;

   // Number of 32-bit words to shift
   uint_t n1 = n / (MPI_INT_SIZE * 8);
   // Number of bits to shift
   uint_t n2 = n % (MPI_INT_SIZE * 8);

   // Check parameters
   if (!r->size || !n)
      return NO_ERROR;

   // Increase the size of the multiple-precision number
   error = mpiGrow(r, r->size + (n + 31) / 32);
   // Check return code
   if (error)
      return error;

   // First, shift words
   if (n1 > 0)
   {
      // Process the most significant words
      for (i = r->size - 1; i >= n1; i--)
      {
         r->data[i] = r->data[i - n1];
      }

      // Fill the rest with zeroes
      for (i = 0; i < n1; i++)
      {
         r->data[i] = 0;
      }
   }

   // Then shift bits
   if (n2 > 0)
   {
      // Process the most significant words
      for (i = r->size - 1; i >= 1; i--)
      {
         r->data[i] = (r->data[i] << n2) | (r->data[i - 1] >> (32 - n2));
      }

      // The least significant word requires a special handling
      r->data[0] <<= n2;
   }

   // Shift operation is complete
   return NO_ERROR;
}

/**
 * @brief Right shift operation
 * @param[in,out] r The multiple precision integer to be shifted to the right
 * @param[in] n The number of bits to shift
 * @return Error code
 **/

error_t mpiShiftRight(Mpi *r, uint_t n)
{
   uint_t i;
   uint_t m;

   // Number of 32-bit words to shift
   uint_t n1 = n / (MPI_INT_SIZE * 8);
   // Number of bits to shift
   uint_t n2 = n % (MPI_INT_SIZE * 8);

   // Check parameters
   if (n1 >= r->size)
   {
      osMemset(r->data, 0, r->size * MPI_INT_SIZE);
      return NO_ERROR;
   }

   // First, shift words
   if (n1 > 0)
   {
      // Process the least significant words
      for (m = r->size - n1, i = 0; i < m; i++)
      {
         r->data[i] = r->data[i + n1];
      }

      // Fill the rest with zeroes
      for (i = m; i < r->size; i++)
      {
         r->data[i] = 0;
      }
   }

   // Then shift bits
   if (n2 > 0)
   {
      // Process the least significant words
      for (m = r->size - n1 - 1, i = 0; i < m; i++)
      {
         r->data[i] = (r->data[i] >> n2) | (r->data[i + 1] << (32 - n2));
      }

      // The most significant word requires a special handling
      r->data[m] >>= n2;
   }

   // Shift operation is complete
   return NO_ERROR;
}

/**
 * @brief Multiple precision multiplication
 * @param[out] r Resulting integer R = A * B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

__weak_func error_t mpiMul(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   int_t i;
   int_t m;
   int_t n;
   Mpi ta;
   Mpi tb;

   // Initialize multiple precision integers
   mpiInit(&ta);
   mpiInit(&tb);

   // R and A are the same instance?
   if (r == a)
   {
      // Copy A to TA
      MPI_CHECK(mpiCopy(&ta, a));
      // Use TA instead of A
      a = &ta;
   }

   // R and B are the same instance?
   if (r == b)
   {
      // Copy B to TB
      MPI_CHECK(mpiCopy(&tb, b));
      // Use TB instead of B
      b = &tb;
   }

   // Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   // Adjust the size of R
   MPI_CHECK(mpiGrow(r, m + n));
   // Set the sign of R
   r->sign = (a->sign == b->sign) ? 1 : -1;

   // Clear the contents of the destination integer
   osMemset(r->data, 0, r->size * MPI_INT_SIZE);

   // Perform multiplication
   if (m < n)
   {
      for (i = 0; i < m; i++)
      {
         mpiMulAccCore(&r->data[i], b->data, n, a->data[i]);
      }
   }
   else
   {
      for (i = 0; i < n; i++)
      {
         mpiMulAccCore(&r->data[i], a->data, m, b->data[i]);
      }
   }

end:
   // Release multiple precision integers
   mpiFree(&ta);
   mpiFree(&tb);

   // Return status code
   return error;
}

/**
 * @brief Multiply a multiple precision integer by an integer
 * @param[out] r Resulting integer R = A * B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiMulInt(Mpi *r, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi t;

   // Convert the second operand to a multiple precision integer
   value = (b >= 0) ? b : -b;
   t.sign = (b >= 0) ? 1 : -1;
   t.size = 1;
   t.data = &value;

   // Perform multiplication
   return mpiMul(r, a, &t);
}

/**
 * @brief Multiple precision division
 * @param[out] q The quotient Q = A / B
 * @param[out] r The remainder R = A mod B
 * @param[in] a The dividend A
 * @param[in] b The divisor B
 * @return Error code
 **/

error_t mpiDiv(Mpi *q, Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t m;
   uint_t n;
   Mpi c;
   Mpi d;
   Mpi e;

   // Check whether the divisor is equal to zero
   if (!mpiCompInt(b, 0))
      return ERROR_INVALID_PARAMETER;

   // Initialize multiple precision integers
   mpiInit(&c);
   mpiInit(&d);
   mpiInit(&e);

   MPI_CHECK(mpiCopy(&c, a));
   MPI_CHECK(mpiCopy(&d, b));
   MPI_CHECK(mpiSetValue(&e, 0));

   m = mpiGetBitLength(&c);
   n = mpiGetBitLength(&d);

   if (m > n)
      MPI_CHECK(mpiShiftLeft(&d, m - n));

   while (n++ <= m)
   {
      MPI_CHECK(mpiShiftLeft(&e, 1));

      if (mpiComp(&c, &d) >= 0)
      {
         MPI_CHECK(mpiSetBitValue(&e, 0, 1));
         MPI_CHECK(mpiSub(&c, &c, &d));
      }

      MPI_CHECK(mpiShiftRight(&d, 1));
   }

   if (q != NULL)
      MPI_CHECK(mpiCopy(q, &e));

   if (r != NULL)
      MPI_CHECK(mpiCopy(r, &c));

end:
   // Release previously allocated memory
   mpiFree(&c);
   mpiFree(&d);
   mpiFree(&e);

   // Return status code
   return error;
}

/**
 * @brief Divide a multiple precision integer by an integer
 * @param[out] q The quotient Q = A / B
 * @param[out] r The remainder R = A mod B
 * @param[in] a The dividend A
 * @param[in] b The divisor B
 * @return Error code
 **/

error_t mpiDivInt(Mpi *q, Mpi *r, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi t;

   // Convert the divisor to a multiple precision integer
   value = (b >= 0) ? b : -b;
   t.sign = (b >= 0) ? 1 : -1;
   t.size = 1;
   t.data = &value;

   // Perform division
   return mpiDiv(q, r, a, &t);
}

/**
 * @brief Modulo operation
 * @param[out] r Resulting integer R = A mod P
 * @param[in] a The multiple precision integer to be reduced
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiMod(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   int_t sign;
   uint_t m;
   uint_t n;
   Mpi c;

   // Make sure the modulus is positive
   if (mpiCompInt(p, 0) <= 0)
      return ERROR_INVALID_PARAMETER;

   // Initialize multiple precision integer
   mpiInit(&c);

   // Save the sign of A
   sign = a->sign;
   // Determine the actual length of A
   m = mpiGetBitLength(a);
   // Determine the actual length of P
   n = mpiGetBitLength(p);

   // Let R = A
   MPI_CHECK(mpiCopy(r, a));

   if (m >= n)
   {
      MPI_CHECK(mpiCopy(&c, p));
      MPI_CHECK(mpiShiftLeft(&c, m - n));

      while (mpiCompAbs(r, p) >= 0)
      {
         if (mpiCompAbs(r, &c) >= 0)
         {
            MPI_CHECK(mpiSubAbs(r, r, &c));
         }

         MPI_CHECK(mpiShiftRight(&c, 1));
      }
   }

   if (sign < 0)
   {
      MPI_CHECK(mpiSubAbs(r, p, r));
   }

end:
   // Release previously allocated memory
   mpiFree(&c);

   // Return status code
   return error;
}

/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = A + B mod P
 * @param[in] a The first operand A
 * @param[in] b The second operand B
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiAddMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;

   // Perform modular addition
   MPI_CHECK(mpiAdd(r, a, b));
   MPI_CHECK(mpiMod(r, r, p));

end:
   // Return status code
   return error;
}

/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = A - B mod P
 * @param[in] a The first operand A
 * @param[in] b The second operand B
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiSubMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;

   // Perform modular subtraction
   MPI_CHECK(mpiSub(r, a, b));
   MPI_CHECK(mpiMod(r, r, p));

end:
   // Return status code
   return error;
}

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = A * B mod P
 * @param[in] a The first operand A
 * @param[in] b The second operand B
 * @param[in] p The modulus P
 * @return Error code
 **/

__weak_func error_t mpiMulMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;

   // Perform modular multiplication
   MPI_CHECK(mpiMul(r, a, b));
   MPI_CHECK(mpiMod(r, r, p));

end:
   // Return status code
   return error;
}

/**
 * @brief Modular inverse
 * @param[out] r Resulting integer R = A^-1 mod P
 * @param[in] a The multiple precision integer A
 * @param[in] p The modulus P
 * @return Error code
 **/

__weak_func error_t mpiInvMod(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   Mpi b;
   Mpi c;
   Mpi q0;
   Mpi r0;
   Mpi t;
   Mpi u;
   Mpi v;

   // Initialize multiple precision integers
   mpiInit(&b);
   mpiInit(&c);
   mpiInit(&q0);
   mpiInit(&r0);
   mpiInit(&t);
   mpiInit(&u);
   mpiInit(&v);

   MPI_CHECK(mpiCopy(&b, p));
   MPI_CHECK(mpiCopy(&c, a));
   MPI_CHECK(mpiSetValue(&u, 0));
   MPI_CHECK(mpiSetValue(&v, 1));

   while (mpiCompInt(&c, 0) > 0)
   {
      MPI_CHECK(mpiDiv(&q0, &r0, &b, &c));

      MPI_CHECK(mpiCopy(&b, &c));
      MPI_CHECK(mpiCopy(&c, &r0));

      MPI_CHECK(mpiCopy(&t, &v));
      MPI_CHECK(mpiMul(&q0, &q0, &v));
      MPI_CHECK(mpiSub(&v, &u, &q0));
      MPI_CHECK(mpiCopy(&u, &t));
   }

   if (mpiCompInt(&b, 1))
   {
      MPI_CHECK(ERROR_FAILURE);
   }

   if (mpiCompInt(&u, 0) > 0)
   {
      MPI_CHECK(mpiCopy(r, &u));
   }
   else
   {
      MPI_CHECK(mpiAdd(r, &u, p));
   }

end:
   // Release previously allocated memory
   mpiFree(&b);
   mpiFree(&c);
   mpiFree(&q0);
   mpiFree(&r0);
   mpiFree(&t);
   mpiFree(&u);
   mpiFree(&v);

   // Return status code
   return error;
}

/**
 * @brief Modular exponentiation
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

__weak_func error_t mpiExpMod(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   int_t i;
   int_t j;
   int_t n;
   uint_t d;
   uint_t k;
   uint_t u;
   Mpi b;
   Mpi c2;
   Mpi t;
   Mpi s[8];

   // Initialize multiple precision integers
   mpiInit(&b);
   mpiInit(&c2);
   mpiInit(&t);

   // Initialize precomputed values
   for (i = 0; (uint_t)i < arraysize(s); i++)
   {
      mpiInit(&s[i]);
   }

   // Very small exponents are often selected with low Hamming weight.
   // The sliding window mechanism should be disabled in that case
   d = (mpiGetBitLength(e) <= 32) ? 1 : 4;

   // Even modulus?
   if (mpiIsEven(p))
   {
      // Let B = A^2
      MPI_CHECK(mpiMulMod(&b, a, a, p));
      // Let S[0] = A
      MPI_CHECK(mpiCopy(&s[0], a));

      // Precompute S[i] = A^(2 * i + 1)
      for (i = 1; i < (1 << (d - 1)); i++)
      {
         MPI_CHECK(mpiMulMod(&s[i], &s[i - 1], &b, p));
      }

      // Let R = 1
      MPI_CHECK(mpiSetValue(r, 1));

      // The exponent is processed in a left-to-right fashion
      i = mpiGetBitLength(e) - 1;

      // Perform sliding window exponentiation
      while (i >= 0)
      {
         // The sliding window exponentiation algorithm decomposes E
         // into zero and nonzero windows
         if (!mpiGetBitValue(e, i))
         {
            // Compute R = R^2
            MPI_CHECK(mpiMulMod(r, r, r, p));
            // Next bit to be processed
            i--;
         }
         else
         {
            // Find the longest window
            n = MAX(i - d + 1, 0);

            // The least significant bit of the window must be equal to 1
            while (!mpiGetBitValue(e, n))
               n++;

            // The algorithm processes more than one bit per iteration
            for (u = 0, j = i; j >= n; j--)
            {
               // Compute R = R^2
               MPI_CHECK(mpiMulMod(r, r, r, p));
               // Compute the relevant index to be used in the precomputed table
               u = (u << 1) | mpiGetBitValue(e, j);
            }

            // Perform a single multiplication per iteration
            MPI_CHECK(mpiMulMod(r, r, &s[u >> 1], p));
            // Next bit to be processed
            i = n - 1;
         }
      }
   }
   else
   {
      // Compute the smaller C = (2^32)^k such as C > P
      k = mpiGetLength(p);

      // Compute C^2 mod P
      MPI_CHECK(mpiSetValue(&c2, 1));
      MPI_CHECK(mpiShiftLeft(&c2, 2 * k * (MPI_INT_SIZE * 8)));
      MPI_CHECK(mpiMod(&c2, &c2, p));

      // Let B = A * C mod P
      if (mpiComp(a, p) >= 0)
      {
         MPI_CHECK(mpiMod(&b, a, p));
         MPI_CHECK(mpiMontgomeryMul(&b, &b, &c2, k, p, &t));
      }
      else
      {
         MPI_CHECK(mpiMontgomeryMul(&b, a, &c2, k, p, &t));
      }

      // Let R = B^2 * C^-1 mod P
      MPI_CHECK(mpiMontgomeryMul(r, &b, &b, k, p, &t));
      // Let S[0] = B
      MPI_CHECK(mpiCopy(&s[0], &b));

      // Precompute S[i] = B^(2 * i + 1) * C^-1 mod P
      for (i = 1; i < (1 << (d - 1)); i++)
      {
         MPI_CHECK(mpiMontgomeryMul(&s[i], &s[i - 1], r, k, p, &t));
      }

      // Let R = C mod P
      MPI_CHECK(mpiCopy(r, &c2));
      MPI_CHECK(mpiMontgomeryRed(r, r, k, p, &t));

      // The exponent is processed in a left-to-right fashion
      i = mpiGetBitLength(e) - 1;

      // Perform sliding window exponentiation
      while (i >= 0)
      {
         // The sliding window exponentiation algorithm decomposes E
         // into zero and nonzero windows
         if (!mpiGetBitValue(e, i))
         {
            // Compute R = R^2 * C^-1 mod P
            MPI_CHECK(mpiMontgomeryMul(r, r, r, k, p, &t));
            // Next bit to be processed
            i--;
         }
         else
         {
            // Find the longest window
            n = MAX(i - d + 1, 0);

            // The least significant bit of the window must be equal to 1
            while (!mpiGetBitValue(e, n))
               n++;

            // The algorithm processes more than one bit per iteration
            for (u = 0, j = i; j >= n; j--)
            {
               // Compute R = R^2 * C^-1 mod P
               MPI_CHECK(mpiMontgomeryMul(r, r, r, k, p, &t));
               // Compute the relevant index to be used in the precomputed table
               u = (u << 1) | mpiGetBitValue(e, j);
            }

            // Compute R = R * T[u/2] * C^-1 mod P
            MPI_CHECK(mpiMontgomeryMul(r, r, &s[u >> 1], k, p, &t));
            // Next bit to be processed
            i = n - 1;
         }
      }

      // Compute R = R * C^-1 mod P
      MPI_CHECK(mpiMontgomeryRed(r, r, k, p, &t));
   }

end:
   // Release multiple precision integers
   mpiFree(&b);
   mpiFree(&c2);
   mpiFree(&t);

   // Release precomputed values
   for (i = 0; (uint_t)i < arraysize(s); i++)
   {
      mpiFree(&s[i]);
   }

   // Return status code
   return error;
}

/**
 * @brief Modular exponentiation (fast calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

__weak_func error_t mpiExpModFast(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   // Perform modular exponentiation
   return mpiExpMod(r, a, e, p);
}

/**
 * @brief Modular exponentiation (regular calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

__weak_func error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   // Perform modular exponentiation
   return mpiExpMod(r, a, e, p);
}

/**
 * @brief Montgomery multiplication
 * @param[out] r Resulting integer R = A * B / 2^k mod P
 * @param[in] a An integer A such as 0 <= A < 2^k
 * @param[in] b An integer B such as 0 <= B < 2^k
 * @param[in] k An integer k such as P < 2^k
 * @param[in] p Modulus P
 * @param[in] t An preallocated integer T (for internal operation)
 * @return Error code
 **/

error_t mpiMontgomeryMul(Mpi *r, const Mpi *a, const Mpi *b, uint_t k,
                         const Mpi *p, Mpi *t)
{
   error_t error;
   uint_t i;
   uint_t m;
   uint_t n;
   uint_t q;

   // Use Newton's method to compute the inverse of P[0] mod 2^32
   for (m = 2 - p->data[0], i = 0; i < 4; i++)
   {
      m = m * (2 - m * p->data[0]);
   }

   // Precompute -1/P[0] mod 2^32;
   m = ~m + 1;

   // We assume that B is always less than 2^k
   n = MIN(b->size, k);

   // Make sure T is large enough
   MPI_CHECK(mpiGrow(t, 2 * k + 1));
   // Let T = 0
   MPI_CHECK(mpiSetValue(t, 0));

   // Perform Montgomery multiplication
   for (i = 0; i < k; i++)
   {
      // Check current index
      if (i < a->size)
      {
         // Compute q = ((T[i] + A[i] * B[0]) * m) mod 2^32
         q = (t->data[i] + a->data[i] * b->data[0]) * m;
         // Compute T = T + A[i] * B
         mpiMulAccCore(t->data + i, b->data, n, a->data[i]);
      }
      else
      {
         // Compute q = (T[i] * m) mod 2^32
         q = t->data[i] * m;
      }

      // Compute T = T + q * P
      mpiMulAccCore(t->data + i, p->data, k, q);
   }

   // Compute R = T / 2^(32 * k)
   MPI_CHECK(mpiShiftRight(t, k * (MPI_INT_SIZE * 8)));
   MPI_CHECK(mpiCopy(r, t));

   // A final subtraction is required
   if (mpiComp(r, p) >= 0)
   {
      MPI_CHECK(mpiSub(r, r, p));
   }

end:
   // Return status code
   return error;
}

/**
 * @brief Montgomery reduction
 * @param[out] r Resulting integer R = A / 2^k mod P
 * @param[in] a An integer A such as 0 <= A < 2^k
 * @param[in] k An integer k such as P < 2^k
 * @param[in] p Modulus P
 * @param[in] t An preallocated integer T (for internal operation)
 * @return Error code
 **/

error_t mpiMontgomeryRed(Mpi *r, const Mpi *a, uint_t k, const Mpi *p, Mpi *t)
{
   uint_t value;
   Mpi b;

   // Let B = 1
   value = 1;
   b.sign = 1;
   b.size = 1;
   b.data = &value;

   // Compute R = A / 2^k mod P
   return mpiMontgomeryMul(r, a, &b, k, p, t);
}

#if (MPI_ASM_SUPPORT == DISABLED)

/**
 * @brief Multiply-accumulate operation
 * @param[out] r Resulting integer
 * @param[in] a First operand A
 * @param[in] m Size of A in words
 * @param[in] b Second operand B
 **/

void mpiMulAccCore(uint_t *r, const uint_t *a, int_t m, const uint_t b)
{
   int_t i;
   uint32_t c;
   uint32_t u;
   uint32_t v;
   uint64_t p;

   // Clear variables
   c = 0;
   u = 0;
   v = 0;

   // Perform multiplication
   for (i = 0; i < m; i++)
   {
      p = (uint64_t)a[i] * b;
      u = (uint32_t)p;
      v = (uint32_t)(p >> 32);

      u += c;
      if (u < c)
         v++;

      u += r[i];
      if (u < r[i])
         v++;

      r[i] = u;
      c = v;
   }

   // Propagate carry
   for (; c != 0; i++)
   {
      r[i] += c;
      c = (r[i] < c);
   }
}

#endif

/**
 * @brief Display the contents of a multiple precision integer
 * @param[in] stream Pointer to a FILE object that identifies an output stream
 * @param[in] prepend String to prepend to the left of each line
 * @param[in] a Pointer to a multiple precision integer
 **/

void mpiDump(FILE *stream, const char_t *prepend, const Mpi *a)
{
   uint_t i;

   // Process each word
   for (i = 0; i < a->size; i++)
   {
      // Beginning of a new line?
      if (i == 0 || ((a->size - i - 1) % 8) == 7)
         fprintf(stream, "%s", prepend);

      // Display current data
      fprintf(stream, "%08X ", a->data[a->size - 1 - i]);

      // End of current line?
      if (((a->size - i - 1) % 8) == 0 || i == (a->size - 1))
         fprintf(stream, "\r\n");
   }
}

#endif
