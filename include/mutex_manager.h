#pragma once

#include "os_port.h"

typedef enum
{
    MUTEX_SETTINGS = 0,
    MUTEX_CLIENT_CTX,
    MUTEX_SSE_CTX,
    MUTEX_SSE_EVENT,
    MUTEX_RTNL_FILE,
    MUTEX_MQTT_TX_BUFFER,
    MUTEX_MQTT_BOX,
    MUTEX_TONIES_JSON_CACHE,
    MUTEX_PCAPLOG_FILE,
    MUTEX_ID,
    MUTEX_ID_START,
    MUTEX_LAST = MUTEX_ID_START + 16
} mutex_id_t;

void mutex_manager_init();
void mutex_manager_deinit();

void mutex_lock(mutex_id_t mutex_id);
void mutex_unlock(mutex_id_t mutex_id);

void mutex_lock_id(char *id);
void mutex_unlock_id(char *id);

void mutex_manager_loop();
void mutex_manager_check();