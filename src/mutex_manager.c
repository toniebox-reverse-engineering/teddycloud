#include "mutex_manager.h"

static OsMutex mutex_list[MUTEX_LAST];

void mutex_manager_init()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        osCreateMutex(&mutex_list[i]);
    }
}

void mutex_manager_deinit()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        osDeleteMutex(&mutex_list[i]);
    }
}

void mutex_lock(mutex_id_t mutex)
{
    osAcquireMutex(&mutex_list[mutex]);
}
void mutex_unlock(mutex_id_t mutex)
{
    osReleaseMutex(&mutex_list[mutex]);
}