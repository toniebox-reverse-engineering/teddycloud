#pragma once

#include "os_port.h"

typedef enum
{
    MUTEX_SETTINGS = 0,
    MUTEX_SSE_CTX,
    MUTEX_SSE_EVENT,
    MUTEX_RTNL_FILE,
    MUTEX_LAST
} mutex_id_t;

void mutex_manager_init();
void mutex_manager_deinit();

void mutex_lock(mutex_id_t mutex);
void mutex_unlock(mutex_id_t mutex);