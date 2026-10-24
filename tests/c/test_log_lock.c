#include <assert.h>
#include <pthread.h>

#include "os_port_config.h"
#include "tests.h"

#define THREADS 4
#define ROUNDS 20000

static long counter;

static void *worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < ROUNDS; i++)
    {
        tc_log_lock();
        tc_log_lock(); /* trace macros nest */
        counter++;
        tc_log_unlock();
        tc_log_unlock();
    }
    return NULL;
}

void test_log_lock(void)
{
    pthread_t threads[THREADS];

    counter = 0;
    for (int i = 0; i < THREADS; i++)
    {
        assert(pthread_create(&threads[i], NULL, worker, NULL) == 0);
    }
    for (int i = 0; i < THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
    assert(counter == (long)THREADS * ROUNDS);
}
