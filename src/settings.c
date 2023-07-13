
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "debug.h"
#include "settings.h"

#include "fs_port.h"

settings_t Settings;

OPTION_START()
OPTION_INTERNAL_UNSIGNED("internal.configVersion", &Settings.internal.configVersion, CONFIG_VERSION, 0, 255, "Config version")
OPTION_INTERNAL_BOOL("internal.exit", &Settings.internal.exit, FALSE, "Exit the server")
OPTION_INTERNAL_SIGNED("internal.returncode", &Settings.internal.returncode, 0, -128, 127, "Returncode when exiting")

OPTION_BOOL("cloud.enabled", &Settings.cloud.enabled, FALSE, "Generally enable cloud operation")
OPTION_BOOL("cloud.enableV1Claim", &Settings.cloud.enableV1Claim, TRUE, "Pass 'claim' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1FreshnessCheck", &Settings.cloud.enableV1FreshnessCheck, TRUE, "Pass 'freshnessCheck' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Log", &Settings.cloud.enableV1Log, FALSE, "Pass 'log' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Time", &Settings.cloud.enableV1Time, FALSE, "Pass 'time' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Ota", &Settings.cloud.enableV1Ota, FALSE, "Pass 'ota' queries to boxine cloud")
OPTION_BOOL("cloud.enableV2Content", &Settings.cloud.enableV2Content, TRUE, "Pass 'content' queries to boxine cloud")
OPTION_BOOL("cloud.cacheContent", &Settings.cloud.cacheContent, FALSE, "Cache cloud content on local server")

OPTION_BOOL("toniebox.overrideCloud", &Settings.toniebox.overrideCloud, TRUE, "Override toniebox settings from the boxine cloud")
OPTION_UNSIGNED("toniebox.max_vol_spk", &Settings.toniebox.max_vol_spk, 3, 0, 3, "Limit speaker volume (0-3)")
OPTION_UNSIGNED("toniebox.max_vol_hdp", &Settings.toniebox.max_vol_hdp, 3, 0, 3, "Limit headphone volume (0-3)")
OPTION_BOOL("toniebox.slap_enabled", &Settings.toniebox.slap_enabled, TRUE, "Enable slapping to skip a track")
OPTION_BOOL("toniebox.slap_back_left", &Settings.toniebox.slap_back_left, FALSE, "False=left-backwards - True=left-forward")
OPTION_UNSIGNED("toniebox.led", &Settings.toniebox.led, 0, 0, 2, "0=on, 1=off, 2=dimmed")

OPTION_BOOL("mqtt.enabled", &Settings.mqtt.enabled, FALSE, "Enable MQTT service")
OPTION_STRING("mqtt.hostname", Settings.mqtt.hostname, sizeof(Settings.mqtt.hostname) - 1, "", "MQTT hostname")
OPTION_STRING("mqtt.username", Settings.mqtt.username, sizeof(Settings.mqtt.username) - 1, "", "Username")
OPTION_STRING("mqtt.password", Settings.mqtt.password, sizeof(Settings.mqtt.password) - 1, "", "Password")
OPTION_STRING("mqtt.identification", Settings.mqtt.identification, sizeof(Settings.mqtt.identification) - 1, "", "Client identification")

OPTION_END()

void settings_init()
{
    TRACE_INFO("Init Settings\r\n");
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        switch (option_map[pos].type)
        {
        case TYPE_BOOL:
            TRACE_INFO("  %s = %s\r\n", option_map[pos].option_name, option_map[pos].init.bool_value ? "true" : "false");
            *((bool *)option_map[pos].ptr) = option_map[pos].init.bool_value;
            break;
        case TYPE_SIGNED:
            TRACE_INFO("  %s = %d\r\n", option_map[pos].option_name, option_map[pos].init.signed_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.signed_value;
            break;
        case TYPE_UNSIGNED:
        case TYPE_HEX:
            TRACE_INFO("  %s = %d\r\n", option_map[pos].option_name, option_map[pos].init.unsigned_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.unsigned_value;
            break;
        case TYPE_FLOAT:
            TRACE_INFO("  %s = %f\r\n", option_map[pos].option_name, option_map[pos].init.float_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.float_value;
            break;
        case TYPE_STRING:
            // TRACE_INFO("  %s = %s\r\n", option_map[pos].option_name, option_map[pos].init.string_value);
            // strncpy((char *)option_map[pos].ptr, option_map[pos].init.string_value, option_map[pos].max.unsigned_value);
            //((char *)option_map[pos].ptr)[option_map[pos].max.unsigned_value] = '\0'; // Ensure null-terminated string
            break;
        default:
            break;
        }
        pos++;
    }

    settings_load();
}

void settings_save()
{
    TRACE_INFO("Save settings to %s\r\n", CONFIG_PATH);
    FsFile *file = fsOpenFile(CONFIG_PATH, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
    if (file == NULL)
    {
        TRACE_WARNING("Failed to open config file for writing\r\n");
        return;
    }

    int pos = 0;
    char buffer[256]; // Buffer to hold the file content
    while (option_map[pos].type != TYPE_END)
    {
        if (!option_map[pos].internal || !osStrcmp(option_map[pos].option_name, "internal.configVersion"))
        {

            switch (option_map[pos].type)
            {
            case TYPE_BOOL:
                sprintf(buffer, "%s=%s\n", option_map[pos].option_name, *((bool *)option_map[pos].ptr) ? "true" : "false");
                break;
            case TYPE_SIGNED:
                sprintf(buffer, "%s=%d\n", option_map[pos].option_name, *((int32_t *)option_map[pos].ptr));
                break;
            case TYPE_UNSIGNED:
            case TYPE_HEX:
                sprintf(buffer, "%s=%u\n", option_map[pos].option_name, *((uint32_t *)option_map[pos].ptr));
                break;
            case TYPE_FLOAT:
                sprintf(buffer, "%s=%f\n", option_map[pos].option_name, *((float *)option_map[pos].ptr));
                break;
            case TYPE_STRING:
                // sprintf(buffer, "%s=%s\n", option_map[pos].option_name, *((char_t *)option_map[pos].ptr));
                // break;
            default:
                buffer[0] = 0;
                break;
            }
            if (osStrlen(buffer) > 0)
                fsWriteFile(file, buffer, osStrlen(buffer));
        }
        pos++;
    }

    fsCloseFile(file);
}

void settings_load()
{
    TRACE_INFO("Load settings from %s\r\n", CONFIG_PATH);
    if (!fsFileExists(CONFIG_PATH))
    {
        TRACE_WARNING("Config file does not exist\r\n");
        settings_save();
        return;
    }

    uint32_t file_size;
    error_t result = fsGetFileSize(CONFIG_PATH, &file_size);
    if (result != NO_ERROR)
    {
        TRACE_WARNING("Failed to get config file size\r\n");
        return;
    }

    FsFile *file = fsOpenFile(CONFIG_PATH, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        TRACE_WARNING("Failed to open config file for reading\r\n");
        return;
    }

    // Buffer to hold the file content
    char buffer[256];
    size_t read_length;
    bool last_line_incomplete = false;
    char *line;
    while (fsReadFile(file, buffer, sizeof(buffer) - 1, &read_length) == NO_ERROR)
    {
        buffer[read_length] = '\0';

        // Process each line in the buffer
        line = buffer;
        char *next_line;

        while ((next_line = strchr(line, '\n')) != NULL)
        {
            *next_line = '\0'; // Terminate the line at the newline character

            // Skip empty lines or lines starting with a comment character '#'
            if (*line != '\0' && *line != '#')
            {
                // Split the line into option_name and value
                char *option_name = strtok(line, "=");
                char *value_str = strtok(NULL, "=");

                if (option_name != NULL && value_str != NULL)
                {
                    // Find the corresponding setting item
                    setting_item_t *opt = settings_get_by_name(option_name);
                    if (opt != NULL)
                    {
                        // Update the setting value based on the type
                        switch (opt->type)
                        {
                        case TYPE_BOOL:
                            if (strcmp(value_str, "true") == 0)
                                *((bool *)opt->ptr) = true;
                            else if (strcmp(value_str, "false") == 0)
                                *((bool *)opt->ptr) = false;
                            else
                                TRACE_WARNING("Invalid boolean value '%s' for setting '%s'\r\n", value_str, option_name);
                            break;
                        case TYPE_SIGNED:
                            *((int32_t *)opt->ptr) = atoi(value_str);
                            break;
                        case TYPE_UNSIGNED:
                        case TYPE_HEX:
                            *((uint32_t *)opt->ptr) = strtoul(value_str, NULL, 10);
                            break;
                        case TYPE_FLOAT:
                            *((float *)opt->ptr) = strtof(value_str, NULL);
                            break;

                        case TYPE_STRING:
                            // strncpy((char *)opt->ptr, value_str, opt->max.unsigned_value);
                            //((char *)opt->ptr)[opt->max.unsigned_value] = '\0'; // Ensure null-terminated string
                            // break;

                        default:
                            break;
                        }
                    }
                    else
                    {
                        TRACE_WARNING("Setting item '%s' not found\r\n", option_name);
                    }
                }
            }

            line = next_line + 1; // Move to the next line
        }

        // Check if the last line is incomplete (does not end with a newline character)
        last_line_incomplete = (buffer[read_length - 1] != '\n');
    }

    // If the last line is incomplete, the buffer might contain a partial line
    // Append the remaining content to the next read block
    if (last_line_incomplete)
    {
        size_t remaining_length = strlen(line);
        memmove(buffer, line, remaining_length);
        read_length = remaining_length;
    }
    else
    {
        read_length = 0; // No remaining content
    }

    fsCloseFile(file);

    if (Settings.internal.configVersion < CONFIG_VERSION)
    {
        settings_save();
    }
}

setting_item_t *settings_get(int index)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (pos == index)
        {
            return &option_map[pos];
        }
        pos++;
    }
    TRACE_WARNING("Setting item #%d not found\r\n", index);
    return NULL;
}

setting_item_t *settings_get_by_name(const char *item)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            return &option_map[pos];
        }
        pos++;
    }
    TRACE_WARNING("Setting item '%s' not found\r\n", item);
    return NULL;
}

bool settings_get_bool(const char *item)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    return *((bool *)opt->ptr);
}

bool settings_set_bool(const char *item, bool value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    *((bool *)opt->ptr) = value;
    return true;
}

int32_t settings_get_signed(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_SIGNED)
    {
        return 0;
    }

    return *((int32_t *)opt->ptr);
}

bool settings_set_signed(const char *item, int32_t value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_SIGNED)
    {
        return false;
    }

    if (value < opt->min.signed_value || value > opt->max.signed_value)
    {
        TRACE_ERROR("  %s = %d out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((int32_t *)opt->ptr) = value;
    return true;
}

uint32_t settings_get_unsigned(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_UNSIGNED)
    {
        return 0;
    }

    return *((uint32_t *)opt->ptr);
}

bool settings_set_unsigned(const char *item, uint32_t value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_UNSIGNED)
    {
        return false;
    }

    if (value < opt->min.unsigned_value || value > opt->max.unsigned_value)
    {
        TRACE_ERROR("  %s = %d out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((uint32_t *)opt->ptr) = value;
    return true;
}

float settings_get_float(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_FLOAT)
    {
        return 0;
    }

    return *((float *)opt->ptr);
}

bool settings_set_float(const char *item, float value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_FLOAT)
    {
        return false;
    }

    if (value < opt->min.float_value || value > opt->max.float_value)
    {
        TRACE_ERROR("  %s = %f out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((float *)opt->ptr) = value;
    return true;
}

const char *settings_get_string(const char *item)
{
    if (!item)
    {
        return NULL;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_STRING)
    {
        return NULL;
    }

    return (const char *)opt->ptr;
}

bool settings_set_string(const char *item, const char *value)
{
    if (!item || !value)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_STRING)
    {
        return false;
    }

    if (osStrlen(value) > opt->max.unsigned_value)
    {
        TRACE_WARNING("Setting item '%s' is too small for the %lu bytes requested to store\r\n", item, osStrlen(value));
        return false;
    }

    osStrcpy((char *)opt->ptr, value);
    return true;
}
