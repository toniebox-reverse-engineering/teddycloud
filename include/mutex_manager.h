#pragma once

#include "os_port.h"

typedef enum
{
    MUTEX_SETTINGS = 0,
    MUTEX_SETTINGS_CN,
    MUTEX_SETTINGS_LOAD,
    MUTEX_SETTINGS_LOAD_OVL,
    MUTEX_SETTINGS_SAVE,
    MUTEX_SETTINGS_SAVE_OVL,
    MUTEX_SETTINGS_CHANGED,
    MUTEX_CLIENT_CTX,
    MUTEX_SSE_CTX,
    MUTEX_SSE_EVENT,
    MUTEX_RTNL_FILE,
    MUTEX_MQTT_TX_BUFFER,
    MUTEX_MQTT_BOX,
    MUTEX_LAST
} mutex_id_t;

void mutex_manager_init();
void mutex_manager_deinit();

void mutex_lock(mutex_id_t mutex_id);
void mutex_unlock(mutex_id_t mutex_id);

void mutex_manager_loop();
void mutex_manager_check();