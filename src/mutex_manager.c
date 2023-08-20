#include "mutex_manager.h"
#include "debug.h"

typedef struct
{
    OsMutex mutex;
    systime_t last_lock;
    bool_t locked;
    bool_t warned;
    bool_t errored;
} mutex_info_t;

static mutex_info_t mutex_list[MUTEX_LAST];

#define MUTEX_TIMEOUT_WARNING_MS 100
#define MUTEX_TIMEOUT_ERROR_MS 1000

void mutex_manager_init()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        mutex_info->locked = FALSE;
        mutex_info->warned = FALSE;
        mutex_info->errored = FALSE;
        osCreateMutex(&mutex_info->mutex);
    }
}

void mutex_manager_deinit()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        osDeleteMutex(&mutex_info->mutex);
    }
}

void mutex_lock(mutex_id_t mutex_id)
{
    mutex_info_t *mutex_info = &mutex_list[mutex_id];

    TRACE_VERBOSE(">locking mutex %" PRIu8 "\r\n", mutex_id);
    osAcquireMutex(&mutex_info->mutex);
    mutex_info->last_lock = osGetSystemTime();
    mutex_info->locked = TRUE;
    TRACE_VERBOSE(">mutex locked %" PRIu8 "\r\n", mutex_id);
}
void mutex_unlock(mutex_id_t mutex_id)
{
    mutex_info_t *mutex_info = &mutex_list[mutex_id];

    TRACE_VERBOSE("<unlocking mutex %" PRIu8 "\r\n", mutex_id);
    osReleaseMutex(&mutex_info->mutex);
    mutex_info->locked = FALSE;
    if (mutex_info->warned)
    {
        TRACE_WARNING("<mutex %" PRIu8 " had a warning\r\n", mutex_id);
        mutex_info->warned = FALSE;
    }
    if (mutex_info->errored)
    {
        TRACE_ERROR("<mutex %" PRIu8 " had an error\r\n", mutex_id);
        mutex_info->errored = FALSE;
    }
    TRACE_VERBOSE("<mutex unlocked %" PRIu8 "\r\n", mutex_id);
}

void mutex_manager_loop()
{
    mutex_manager_check();
}
void mutex_manager_check()
{
    systime_t now = osGetSystemTime();
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        if (!mutex_info->locked)
            continue;
        time_t locked_time = now - mutex_info->last_lock;
        if (locked_time < MUTEX_TIMEOUT_WARNING_MS)
            continue;
        if (locked_time < MUTEX_TIMEOUT_ERROR_MS)
        {
            if (!mutex_info->warned)
            {
                TRACE_WARNING("Mutex %" PRIuSIZE " locked for %" PRIuTIME "\r\n", i, locked_time);
                mutex_info->warned = true;
            }
        }
        else
        {
            if (!mutex_info->errored)
            {
                TRACE_ERROR("Mutex %" PRIuSIZE " locked for %" PRIuTIME "\r\n", i, locked_time);
                mutex_info->errored = true;
            }
        }
    }
}