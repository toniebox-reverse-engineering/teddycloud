#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "debug.h"
#include "error.h"

#ifndef SETTINGS_H
#define SETTINGS_H

#define TONIES_JSON_PATH "config/tonies.json"
#define TONIES_CUSTOM_JSON_PATH "config/tonies.custom.json"
#define CONFIG_PATH "config/config.ini"
#define CONFIG_OVERLAY_PATH "config/config.overlay.ini"
#define CONFIG_VERSION 4
#define MAX_OVERLAYS 16 + 1

typedef enum
{
    LOGLEVEL_OFF = 0,
    LOGLEVEL_FATAL = 1,
    LOGLEVEL_ERROR = 2,
    LOGLEVEL_WARNING = 3,
    LOGLEVEL_INFO = 4,
    LOGLEVEL_DEBUG = 5,
    LOGLEVEL_VERBOSE = 6
} settings_loglevel;

typedef enum
{
    EAR_NONE = 0,
    EAR_SMALL = 1,
    EAR_BIG = 2,
} settings_earid;

typedef enum
{
    BOX_UNKNOWN = 0,
    BOX_CC3200 = 1,
    BOX_CC3235 = 2,
    BOX_ESP32 = 3,
} settings_box_type;

typedef struct
{
    bool enabled;
    char *remote_hostname;
    uint32_t remote_port;
    bool enableV1Claim;
    bool enableV1CloudReset;
    bool enableV1FreshnessCheck;
    bool enableV1Log;
    bool enableV1Time;
    bool enableV1Ota;
    bool enableV2Content;
    bool cacheContent;
    bool markCustomTagByPass;
    bool prioCustomContent;
    bool updateOnLowerAudioId;
} settings_cloud_t;

typedef struct
{
    bool enabled;
    char *hostname;
    uint32_t port;
    char *username;
    char *password;
    char *identification;
    char *topic;
    uint32_t qosLevel;
} settings_mqtt_t;

typedef struct
{
    char *name;
    char *id;
} settings_hass_t;

typedef struct
{
    bool overrideCloud;
    uint32_t max_vol_spk;
    uint32_t max_vol_hdp;
    bool slap_enabled;
    bool slap_back_left;
    uint32_t led;
} settings_toniebox_t;

typedef struct
{
    char *ca;
    char *ca_key;
    char *crt;
    char *key;
    char *cert_chain;
} settings_cert_t;

typedef struct
{
    char *id;
    char *git_sha_short;
    char *git_sha;
    bool dirty;
    char *datetime;
    char *platform;
    char *os;
    char *architecture;
    char *v_short;
    char *v_long;
    char *v_full;
} settings_version_t;

typedef struct
{
    settings_earid lastEarId;
    uint64_t lastEarpress;
    bool wasDoubleEarpress;
    uint32_t multipressTime;
} settings_internal_rtnl_t;

typedef struct
{
    settings_box_type boxIC;

    time_t uaVersionFirmware;
    time_t uaVersionServicePack;
    time_t uaVersionHardware;
    char *uaEsp32Firmware;

    char *rtnlVersion;
    char *rtnlFullVersion;
    char *rtnlDetail;
    char *rtnlRegion;

    uint32_t otaVersionSfx;
    uint32_t otaVersionServicePack;
    uint32_t otaVersionHtml;
    uint32_t otaVersionEu;
    uint32_t otaVersionPd;

} settings_internal_toniebox_firmware_t;

typedef struct
{
    bool exit;
    int32_t returncode;
    settings_cert_t server;
    settings_cert_t client;
    bool config_init;
    bool config_used;
    bool config_changed;
    bool logColorSupport;

    char *cwd;
    char *contentdirrel;
    char *contentdirfull;
    char *librarydirfull;
    char *datadirfull;
    char *wwwdirfull;
    char *firmwaredirfull;

    char *overlayUniqueId;
    uint8_t overlayNumber;
    char *assign_unknown;

    settings_internal_rtnl_t rtnl;
    settings_version_t version;
    settings_internal_toniebox_firmware_t toniebox_firmware;

    time_t last_connection;
    bool online;
} settings_internal_t;

typedef struct
{
    settings_cert_t file;
    settings_cert_t data;
} settings_cert_opt_t;

typedef struct
{
    uint32_t http_port;
    uint32_t https_port;
    char *host_url;
    char *certdir;
    char *contentdir;
    char *firmwaredir;
    char *librarydir;
    char *datadir;
    char *wwwdir;
    char *sslkeylogfile;
    settings_cert_opt_t server_cert;
    settings_cert_opt_t client_cert;
    char *allowOrigin;

    bool flex_enabled;
    char *flex_uid;
    char *bind_ip;
} settings_core_t;

typedef struct
{
    settings_loglevel level;
    bool color;
    bool logFullAuth;
} settings_log_t;

typedef struct
{
    bool logRaw;
    char *logRawFile;
    bool logHuman;
    char *logHumanFile;
} settings_rtnl_t;

typedef struct
{
    uint32_t configVersion;
    char *commonName;
    char *boxName;
    settings_core_t core;
    settings_cloud_t cloud;
    settings_mqtt_t mqtt;
    settings_hass_t hass;
    settings_toniebox_t toniebox;
    settings_internal_t internal;
    settings_log_t log;
    settings_rtnl_t rtnl;
} settings_t;

typedef enum
{
    TYPE_BOOL,
    TYPE_SIGNED,
    TYPE_UNSIGNED,
    TYPE_HEX,
    TYPE_STRING,
    TYPE_FLOAT,
    TYPE_TREE_DESC,
    TYPE_END
} settings_type;

typedef union
{
    bool bool_value;
    int32_t signed_value;
    uint64_t unsigned_value;
    uint32_t hex_value;
    float float_value;
    const char *string_value;
} setting_value_t;

/**
 * @typedef struct setting_item_t
 * @brief Structure representing a settings item.
 *
 * This structure encapsulates all the relevant information for a setting in the system,
 * such as its name, description, value pointer, type, initial value, range (min, max) and whether it is an internal setting.
 *
 * @var const char *option_name
 * The name of the setting item.
 *
 * @var const char *description
 * A description of the setting item, which can be used to give users an understanding of its purpose.
 *
 * @var const char *label
 * A short description of the setting item, which can be used as an entry name.
 *
 * @var void *ptr
 * A pointer to the value of the setting. The type of the value pointed to should match the specified setting type.
 *
 * @var settings_type type
 * The type of the setting item's value. This determines how the value should be interpreted.
 *
 * @var setting_value_t init
 * The initial value for the setting item. This is used when initializing the settings subsystem.
 *
 * @var setting_value_t min
 * The minimum allowable value for the setting item. This is used to enforce boundaries on setting values.
 *
 * @var setting_value_t max
 * The maximum allowable value for the setting item. This is used to enforce boundaries on setting values.
 *
 * @var bool internal
 * If true, this setting is intended for internal use by the system and should not be exposed to end users.
 */
typedef struct
{
    const char *option_name;
    const char *description;
    const char *label;
    void *ptr;
    settings_type type;
    setting_value_t init;
    setting_value_t min;
    setting_value_t max;
    bool internal;
    bool overlayed;
} setting_item_t;

#define OPTION_START() setting_item_t option_map_array[] = {
#define OPTION_ADV_BOOL(o, p, d, short, desc, i, ov) {.option_name = o, .ptr = p, .init = {.bool_value = d}, .type = TYPE_BOOL, .description = desc, .label = short, .internal = i, .overlayed = ov},
#define OPTION_ADV_SIGNED(o, p, d, minVal, maxVal, short, desc, i, ov) {.option_name = o, .ptr = p, .init = {.signed_value = d}, .min = {.signed_value = minVal}, .max = {.signed_value = maxVal}, .type = TYPE_SIGNED, .description = desc, .label = short, .internal = i, .overlayed = ov},
#define OPTION_ADV_UNSIGNED(o, p, d, minVal, maxVal, short, desc, i, ov) {.option_name = o, .ptr = p, .init = {.unsigned_value = d}, .min = {.unsigned_value = minVal}, .max = {.unsigned_value = maxVal}, .type = TYPE_UNSIGNED, .description = desc, .label = short, .internal = i, .overlayed = ov},
#define OPTION_ADV_FLOAT(o, p, d, minVal, maxVal, short, desc, i, ov) {.option_name = o, .ptr = p, .init = {.float_value = d}, .min = {.float_value = minVal}, .max = {.float_value = maxVal}, .type = TYPE_FLOAT, .description = desc, .label = short, .internal = i, .overlayed = ov},
#define OPTION_ADV_STRING(o, p, d, short, desc, i, ov) {.option_name = o, .ptr = p, .init = {.string_value = d}, .type = TYPE_STRING, .description = desc, .label = short, .internal = i, .overlayed = ov},
#define OPTION_ADV_TREE_DESC(o, p, d, desc, i, ov) {.option_name = o, .ptr = p, .init = {.string_value = d}, .type = TYPE_TREE_DESC, .description = desc, .label = NULL, .internal = i, .overlayed = ov},

#define OPTION_BOOL(o, p, d, short, desc) OPTION_ADV_BOOL(o, p, d, short, desc, false, false)
#define OPTION_SIGNED(o, p, d, min, max, short, desc) OPTION_ADV_SIGNED(o, p, d, min, max, short, desc, false, false)
#define OPTION_UNSIGNED(o, p, d, min, max, short, desc) OPTION_ADV_UNSIGNED(o, p, d, min, max, short, desc, false, false)
#define OPTION_FLOAT(o, p, d, min, max, short, desc) OPTION_ADV_FLOAT(o, p, d, min, max, short, desc, false, false)
#define OPTION_STRING(o, p, d, short, desc) OPTION_ADV_STRING(o, p, d, short, desc, false, false)

#define OPTION_INTERNAL_BOOL(o, p, d, desc) OPTION_ADV_BOOL(o, p, d, desc, desc, true, false)
#define OPTION_INTERNAL_SIGNED(o, p, d, min, max, desc) OPTION_ADV_SIGNED(o, p, d, min, max, desc, desc, true, false)
#define OPTION_INTERNAL_UNSIGNED(o, p, d, min, max, desc) OPTION_ADV_UNSIGNED(o, p, d, min, max, desc, desc, true, false)
#define OPTION_INTERNAL_FLOAT(o, p, d, min, max, desc) OPTION_ADV_FLOAT(o, p, d, min, max, desc, desc, true, false)
#define OPTION_INTERNAL_STRING(o, p, d, desc) OPTION_ADV_STRING(o, p, d, desc, desc, true, false)

#define OPTION_TREE_DESC(o, desc) OPTION_ADV_TREE_DESC(o, NULL, NULL, desc, false, false)

#define OPTION_END()     \
    {                    \
        .type = TYPE_END \
    }                    \
    }                    \
    ;

void overlay_settings_init();

settings_t *get_settings();
settings_t *get_settings_ovl(const char *overlay_unique_id);
settings_t *get_settings_id(uint8_t settingsId);
settings_t *get_settings_cn(const char *cn);

uint8_t get_overlay_id(const char *overlay_unique_id);

void settings_resolve_dir(char **resolvedPath, char *path, char *basePath);
void settings_generate_internal_dirs(settings_t *settings);
void settings_changed();
void settings_loop();

/**
 * @brief Initializes the settings subsystem.
 *
 * This function should be called once, before any other settings functions are used.
 */
error_t settings_init(char *cwd);

/**
 * @brief Deinitializes the settings subsystem.
 *
 * This function should be called to clean up all allocated memory.
 */
void settings_deinit(uint8_t overlayNumber);
void settings_deinit_all();

/**
 * @brief Saves the current settings to a persistent storage (like a file or database).
 *
 * The settings_save() function is used to persistently store the current settings,
 * allowing them to be reloaded after the program is restarted. The exact method of storage
 * depends on the specific implementation: it may be saved to a file, a database, or another
 * type of persistent storage.
 *
 * This function does not return a value, and it is assumed that it will handle any errors
 * internally. If the settings cannot be saved for some reason (for instance, if the storage
 * medium is not available), it is up to the function implementation to handle this case.
 *
 * Usage:
 * @code
 *    settings_save();
 * @endcode
 */
error_t settings_save();
error_t settings_save_ovl(bool overlay);

/**
 * @brief Loads settings from a persistent storage (like a file or database).
 *
 * The settings_load() function is used to load settings that have been saved persistently,
 * such as when the program is first started. The settings are loaded from the same place
 * that the settings_save() function saves to.
 *
 * This function does not return a value, and it is assumed that it will handle any errors
 * internally. If the settings cannot be loaded for some reason (for instance, if the storage
 * medium is not available or the settings file is corrupted), it is up to the function
 * implementation to handle this case.
 *
 * Usage:
 * @code
 *    settings_load();
 * @endcode
 */
error_t settings_load();
error_t settings_load_ovl(bool overlay);

uint16_t settings_get_size();

/**
 * @brief Gets the setting item at a specific index.
 *
 * @param index The index of the setting item.
 * @return A pointer to the setting item, or NULL if the index is out of bounds.
 */
setting_item_t *settings_get(int index);
setting_item_t *settings_get_ovl(int index, const char *overlay_name);
setting_item_t *settings_get_by_name_id(const char *item, uint8_t settingsId);

/**
 * @brief Sets the value of a boolean setting item.
 *
 * @param item The name of the setting item.
 * @param value The new value for the setting item.
 */
bool settings_set_bool(const char *item, bool value);
bool settings_set_bool_ovl(const char *item, bool value, const char *overlay_name);

/**
 * @brief Gets the value of a boolean setting item.
 *
 * @param item The name of the setting item.
 * @return The current value of the setting item. If the item does not exist or is not a boolean, the behavior is undefined.
 */
bool settings_get_bool(const char *item);
bool settings_get_bool_ovl(const char *item, const char *overlay_name);

/**
 * @brief Gets the value of an signed integer setting item.
 *
 * @param item The name of the setting item.
 * @return The current value of the setting item. If the item does not exist or is not an integer, the behavior is undefined.
 */
int32_t settings_get_signed(const char *item);
int32_t settings_get_signed_ovl(const char *item, const char *overlay_name);

/**
 * @brief Sets the value of an integer setting item.
 *
 * @param item The name of the setting item.
 * @param value The new value for the setting item.
 */
bool settings_set_signed(const char *item, int32_t value);
bool settings_set_signed_ovl(const char *item, int32_t value, const char *overlay_name);

/**
 * @brief Gets the value of an unsigned integer setting item.
 *
 * @param item The name of the setting item.
 * @return The current value of the setting item. If the item does not exist or is not an integer, the behavior is undefined.
 */
uint32_t settings_get_unsigned(const char *item);
uint32_t settings_get_unsigned_ovl(const char *item, const char *overlay_name);

/**
 * @brief Sets the value of an unsigned integer setting item.
 *
 * @param item The name of the setting item.
 * @param value The new value for the setting item.
 */
bool settings_set_unsigned(const char *item, uint32_t value);
bool settings_set_unsigned_ovl(const char *item, uint32_t value, const char *overlay_name);

/**
 * @brief Retrieves a setting item by its name.
 *
 * @param item The name of the setting item.
 * @return A pointer to the setting item, or NULL if the item does not exist.
 */
setting_item_t *settings_get_by_name(const char *item);
setting_item_t *settings_get_by_name_ovl(const char *item, const char *overlay_name);

/**
 * @brief Retrieves the value of a string setting item.
 *
 * @param item The name of the setting item.
 * @return The current string value of the setting item. If the item does not exist or is not a string, the behavior is undefined.
 */
const char *settings_get_string(const char *item);
const char *settings_get_string_ovl(const char *item, const char *overlay_name);
const char *settings_get_string_id(const char *item, uint8_t settingsId);

/**
 * @brief Sets the value of a string setting item.
 *
 * @param item The name of the setting item.
 * @param value The new string value for the setting item.
 */
bool settings_set_string(const char *item, const char *value);
bool settings_set_string_ovl(const char *item, const char *value, const char *overlay_name);
bool settings_set_string_id(const char *item, const char *value, uint8_t settingsId);

/**
 * @brief Retrieves the value of a floating point setting item.
 *
 * @param item The name of the setting item.
 * @return The current float value of the setting item. If the item does not exist or is not a float, the behavior is undefined.
 */
float settings_get_float(const char *item);
float settings_get_float_ovl(const char *item, const char *overlay_name);

/**
 * @brief Sets the value of a floating point setting item.
 *
 * @param item The name of the setting item.
 * @param value The variable where the floating point value of the setting item will be stored. If the item does not exist or is not a float, the behavior is undefined.
 */
bool settings_set_float(const char *item, float value);
bool settings_set_float_ovl(const char *item, float value, const char *overlay_name);

char *settings_sanitize_box_id(const char *input_id);

void settings_load_all_certs();
error_t settings_try_load_certs_id(uint8_t settingsId);
error_t settings_load_certs_id(uint8_t settingsId);

#endif
