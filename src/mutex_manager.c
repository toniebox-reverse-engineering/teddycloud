#define TRACE_LEVEL TRACE_LEVEL_VERBOSE

#include "mutex_manager.h"
#include "server_helpers.h"
#include "debug.h"

typedef struct
{
    OsMutex mutex;
    systime_t last_lock;
    bool_t locked;
    bool_t warned;
    bool_t errored;
    char *id;
} mutex_info_t;

static mutex_info_t mutex_list[MUTEX_LAST];

#define MUTEX_TIMEOUT_WARNING_MS 100
#define MUTEX_TIMEOUT_ERROR_MS 1000

void mutex_manager_init()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        osMemset(mutex_info, 0, sizeof(mutex_info_t));
        if (i < MUTEX_ID_START)
        {
            mutex_info->id = custom_asprintf("%" PRIu8, i);
        }
        osCreateMutex(&mutex_info->mutex);
    }
}

void mutex_manager_deinit()
{
    for (size_t i = 0; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        osFreeMem(mutex_info->id);
        osDeleteMutex(&mutex_info->mutex);
    }
}

void mutex_lock_id(char *id)
{
    while (true)
    {
        mutex_lock(MUTEX_ID);
        for (uint8_t i = MUTEX_ID_START; i < MUTEX_LAST; i++)
        {
            mutex_info_t *mutex_info = &mutex_list[i];
            if (mutex_info->id != NULL && osStrcmp(mutex_info->id, id) == 0)
            {
                mutex_lock(i);
                mutex_unlock(MUTEX_ID);
                return;
            }
        }
        for (uint8_t i = MUTEX_ID_START; i < MUTEX_LAST; i++)
        {
            mutex_info_t *mutex_info = &mutex_list[i];
            if (mutex_info->id == NULL)
            {
                mutex_info->id = strdup(id);
                mutex_lock(i);
                mutex_unlock(MUTEX_ID);
                return;
            }
        }
        TRACE_WARNING("Too many mutexes by id, waiting for %s!\r\n", id);
        mutex_unlock(MUTEX_ID);
    }
}
void mutex_unlock_id(char *id)
{
    mutex_lock(MUTEX_ID);
    for (uint8_t i = MUTEX_ID_START; i < MUTEX_LAST; i++)
    {
        mutex_info_t *mutex_info = &mutex_list[i];
        if (mutex_info->id != NULL && osStrcmp(mutex_info->id, id) == 0)
        {
            mutex_unlock(i);
            osFreeMem(mutex_info->id);
            mutex_info->id = NULL;
            mutex_unlock(MUTEX_ID);
            return;
        }
    }
    mutex_unlock(MUTEX_ID);
}

void mutex_lock(mutex_id_t mutex_id)
{
    mutex_info_t *mutex_info = &mutex_list[mutex_id];

    TRACE_VERBOSE(">locking mutex %s\r\n", mutex_info->id);
    osAcquireMutex(&mutex_info->mutex);
    mutex_info->locked = TRUE;
    mutex_info->last_lock = osGetSystemTime();
    TRACE_VERBOSE(">mutex locked %s\r\n", mutex_info->id);
}
void mutex_unlock(mutex_id_t mutex_id)
{
    mutex_info_t *mutex_info = &mutex_list[mutex_id];

    TRACE_VERBOSE("<unlocking mutex %s\r\n", mutex_info->id);
    if (!mutex_info->locked)
    {
        TRACE_WARNING("<unlocking mutex %s, which is not locked?!\r\n", mutex_info->id);
    }
    osReleaseMutex(&mutex_info->mutex);
    mutex_info->locked = FALSE;
    if (mutex_info->warned)
    {
        TRACE_WARNING("<mutex %s had a warning\r\n", mutex_info->id);
        mutex_info->warned = FALSE;
    }
    if (mutex_info->errored)
    {
        TRACE_ERROR("<mutex %s had an error\r\n", mutex_info->id);
        mutex_info->errored = FALSE;
    }
    TRACE_VERBOSE("<mutex unlocked %s\r\n", mutex_info->id);
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
                TRACE_WARNING("Mutex %s locked for %" PRIuTIME "\r\n", mutex_info->id, locked_time);
                mutex_info->warned = true;
            }
        }
        else
        {
            if (!mutex_info->errored)
            {
                TRACE_ERROR("Mutex %s locked for %" PRIuTIME "\r\n", mutex_info->id, locked_time);
                mutex_info->errored = true;
            }
        }
    }
}