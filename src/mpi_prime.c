/*
 * Miller-Rabin primality test used by RSA key generation. Replaces Cyclone's
 * weak mpiCheckProbablePrime(), which is "implemented by hardware" there.
 */
#include "core/crypto.h"
#include "mpi/mpi.h"
#include "debug.h"
#include "rand.h"

/* https://github.com/cslarsen/miller-rabin */
static bool mpiCheckProbablePrimeWorker(const Mpi *n, int k, const PrngAlgo *prngAlgo, void *prngContext)
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

error_t mpiCheckProbablePrime(const Mpi *a)
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
