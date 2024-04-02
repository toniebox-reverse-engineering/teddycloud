#pragma once

#include "toniefile.h"

typedef enum
{
    TBS_SYS_SOUND_STARTUP_JINGLE = 0x00000000,
    TBS_SYS_SOUND_TADA = 0x00000001,
    TBS_SYS_SOUND_TADUM_MHHH = 0x00000002,
    TBS_SYS_SOUND_LOW_BATTERY_WARNING = 0x00000003,
    TBS_SYS_SOUND_TONIE_PLAYBACK_FINISHED = 0x00000006,
    TBS_SYS_SOUND_OFFLINE_MODE_ON = 0x00000007,
    TBS_SYS_SOUND_OFFLINE_MODE_OFF = 0x00000008,
    TBS_SYS_SOUND_LOW_BATTERY_SHUTDOWN = 0x00000009,
    TBS_SYS_SOUND_OFFLINE_EC_KOALA = 0x0000000A,
    TBS_SYS_SOUND_INSTALL_HINT = 0x0000000B,
    TBS_SYS_SOUND_KEEP_ON_CHARGER = 0x0000000D,
    TBS_SYS_SOUND_PLAYBACK_LIMIT = 0x0000000E,
    TBS_SYS_SOUND_DOWNLOAD_INTERRUPTED = 0x0000000F,
    TBS_SYS_SOUND_INSTALL_SUCCESS = 0x00000010,
    TBS_SYS_SOUND_NO_INTERNET_EC_TURTLE = 0x00000011,
    TBS_SYS_SOUND_NO_CONTENT_EC_GROUNDHOG = 0x00000012,
    TBS_SYS_SOUND_WIFI_PW_WRONG = 0x00000013,
    TBS_SYS_SOUND_CONNECTION_EC_HEDGEHOG = 0x00000014,
    TBS_SYS_SOUND_CONNECTION_EC_ANT = 0x00000015,
    TBS_SYS_SOUND_CONNECTION_EC_MEERKAT = 0x00000016,
    TBS_SYS_SOUND_CONNECTION_EC_OWL = 0x00000017,
    TBS_SYS_SOUND_WIFI_EC_ELEPHANT = 0x00000018,
} toniebox_state_system_sound_t;

typedef enum
{
    TBS_SYS_SOUND_LANG_EN_GB = 0x00000000,
    TBS_SYS_SOUND_LANG_DE_DE = 0x00000001,
    TBS_SYS_SOUND_LANG_EN_US = 0x00000002,
    TBS_SYS_SOUND_LANG_FR_FR = 0x00000003,
} toniebox_state_system_sound_lang_t;

typedef struct
{
    const char *id;
    const char *name;
    bool playback;
    bool charger;
    uint32_t volumeLevel;
    uint32_t volumedB;
    stream_ctx_t stream_ctx;
} toniebox_state_box_t;

typedef struct
{
    uint64_t uid;
    bool valid;
    uint32_t audio_id;
    bool custom;
} toniebox_state_tag_t;

typedef struct
{
    toniebox_state_box_t box;
    toniebox_state_tag_t tag;
} toniebox_state_t;

typedef enum
{
    TBS_PLAYBACK_NONE,
    TBS_PLAYBACK_STARTING,
    TBS_PLAYBACK_STARTED,
    TBS_PLAYBACK_STOPPED,
} toniebox_state_playback_t;