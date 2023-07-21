
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "debug.h"
#include "settings.h"

#include "fs_port.h"

settings_t Settings;

OPTION_START()

OPTION_INTERNAL_UNSIGNED("configVersion", &Settings.configVersion, 0, 0, 255, "Config version")
/* settings for HTTPS server */
OPTION_STRING("core.server_cert.file.ca", &Settings.core.server_cert.file.ca, "certs/server/ca-root.pem", "Server CA")
OPTION_STRING("core.server_cert.file.crt", &Settings.core.server_cert.file.crt, "certs/server/teddy-cert.pem", "Server certificate")
OPTION_STRING("core.server_cert.file.key", &Settings.core.server_cert.file.key, "certs/server/teddy-key.pem", "Server key")
OPTION_STRING("core.server_cert.data.ca", &Settings.core.server_cert.data.ca, "", "Server CA data")
OPTION_STRING("core.server_cert.data.crt", &Settings.core.server_cert.data.crt, "", "Server certificate data")
OPTION_STRING("core.server_cert.data.key", &Settings.core.server_cert.data.key, "", "Server key data")

/* settings for HTTPS/cloud client */
OPTION_STRING("core.client_cert.file.ca", &Settings.core.client_cert.file.ca, "certs/server/ca-root.pem", "Client CA")
OPTION_STRING("core.client_cert.file.crt", &Settings.core.client_cert.file.crt, "certs/client/teddy-cert.pem", "Client certificate")
OPTION_STRING("core.client_cert.file.key", &Settings.core.client_cert.file.key, "certs/client/teddy-key.pem", "Client key")
OPTION_STRING("core.client_cert.data.ca", &Settings.core.client_cert.data.ca, "", "Client CA")
OPTION_STRING("core.client_cert.data.crt", &Settings.core.client_cert.data.crt, "", "Client certificate data")
OPTION_STRING("core.client_cert.data.key", &Settings.core.client_cert.data.key, "", "Client key data")

OPTION_INTERNAL_STRING("internal.server.ca", &Settings.internal.server.ca, "", "Server CA data")
OPTION_INTERNAL_STRING("internal.server.crt", &Settings.internal.server.crt, "", "Server certificate data")
OPTION_INTERNAL_STRING("internal.server.key", &Settings.internal.server.key, "", "Server key data")
OPTION_INTERNAL_STRING("internal.client.ca", &Settings.internal.client.ca, "", "Client CA")
OPTION_INTERNAL_STRING("internal.client.crt", &Settings.internal.client.crt, "", "Client certificate data")
OPTION_INTERNAL_STRING("internal.client.key", &Settings.internal.client.key, "", "Client key data")

OPTION_INTERNAL_BOOL("internal.exit", &Settings.internal.exit, FALSE, "Exit the server")
OPTION_INTERNAL_SIGNED("internal.returncode", &Settings.internal.returncode, 0, -128, 127, "Returncode when exiting")

OPTION_BOOL("cloud.enabled", &Settings.cloud.enabled, FALSE, "Generally enable cloud operation")
OPTION_STRING("cloud.hostname", &Settings.cloud.remote_hostname, "prod.de.tbs.toys", "Hostname of remote cloud server")
OPTION_UNSIGNED("cloud.port", &Settings.cloud.remote_port, 443, 1, 65535, "Port of remote cloud server")
OPTION_BOOL("cloud.enableV1Claim", &Settings.cloud.enableV1Claim, TRUE, "Pass 'claim' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1FreshnessCheck", &Settings.cloud.enableV1FreshnessCheck, TRUE, "Pass 'freshnessCheck' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Log", &Settings.cloud.enableV1Log, FALSE, "Pass 'log' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Time", &Settings.cloud.enableV1Time, FALSE, "Pass 'time' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Ota", &Settings.cloud.enableV1Ota, FALSE, "Pass 'ota' queries to boxine cloud")
OPTION_BOOL("cloud.enableV2Content", &Settings.cloud.enableV2Content, TRUE, "Pass 'content' queries to boxine cloud")
OPTION_BOOL("cloud.cacheContent", &Settings.cloud.cacheContent, FALSE, "Cache cloud content on local server")
OPTION_BOOL("cloud.markCustomTagByPass", &Settings.cloud.markCustomTagByPass, TRUE, "Automatically mark custom tags by password")
OPTION_BOOL("cloud.markCustomTagByUid", &Settings.cloud.markCustomTagByUid, TRUE, "Automatically mark custom tags by Uid")

OPTION_BOOL("toniebox.overrideCloud", &Settings.toniebox.overrideCloud, TRUE, "Override toniebox settings from the boxine cloud")
OPTION_UNSIGNED("toniebox.max_vol_spk", &Settings.toniebox.max_vol_spk, 3, 0, 3, "Limit speaker volume (0-3)")
OPTION_UNSIGNED("toniebox.max_vol_hdp", &Settings.toniebox.max_vol_hdp, 3, 0, 3, "Limit headphone volume (0-3)")
OPTION_BOOL("toniebox.slap_enabled", &Settings.toniebox.slap_enabled, TRUE, "Enable slapping to skip a track")
OPTION_BOOL("toniebox.slap_back_left", &Settings.toniebox.slap_back_left, FALSE, "False=left-backwards - True=left-forward")
OPTION_UNSIGNED("toniebox.led", &Settings.toniebox.led, 0, 0, 2, "0=on, 1=off, 2=dimmed")

OPTION_BOOL("mqtt.enabled", &Settings.mqtt.enabled, FALSE, "Enable MQTT service")
OPTION_STRING("mqtt.hostname", &Settings.mqtt.hostname, "", "MQTT hostname")
OPTION_STRING("mqtt.username", &Settings.mqtt.username, "", "Username")
OPTION_STRING("mqtt.password", &Settings.mqtt.password, "", "Password")
OPTION_STRING("mqtt.identification", &Settings.mqtt.identification, "", "Client identification")

OPTION_END()

void settings_deinit()
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        setting_item_t *opt = &option_map[pos];

        switch (opt->type)
        {
        case TYPE_STRING:
            if (*((char **)opt->ptr))
            {
                free(*((char **)opt->ptr));
            }
            break;
        default:
            break;
        }
        pos++;
    }
}

void settings_init()
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        setting_item_t *opt = &option_map[pos];

        switch (opt->type)
        {
        case TYPE_BOOL:
            TRACE_DEBUG("  %s = %s\r\n", opt->option_name, opt->init.bool_value ? "true" : "false");
            *((bool *)opt->ptr) = opt->init.bool_value;
            break;
        case TYPE_SIGNED:
            TRACE_DEBUG("  %s = %d\r\n", opt->option_name, opt->init.signed_value);
            *((uint32_t *)opt->ptr) = opt->init.signed_value;
            break;
        case TYPE_UNSIGNED:
        case TYPE_HEX:
            TRACE_DEBUG("  %s = %d\r\n", opt->option_name, opt->init.unsigned_value);
            *((uint32_t *)opt->ptr) = opt->init.unsigned_value;
            break;
        case TYPE_FLOAT:
            TRACE_DEBUG("  %s = %f\r\n", opt->option_name, opt->init.float_value);
            *((uint32_t *)opt->ptr) = opt->init.float_value;
            break;
        case TYPE_STRING:
            TRACE_DEBUG("  %s = %s\r\n", opt->option_name, opt->init.string_value);
            *((char **)opt->ptr) = strdup(opt->init.string_value);
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

    Settings.configVersion = CONFIG_VERSION;

    int pos = 0;
    char buffer[256]; // Buffer to hold the file content
    while (option_map[pos].type != TYPE_END)
    {
        if (!option_map[pos].internal || !osStrcmp(option_map[pos].option_name, "configVersion"))
        {
            setting_item_t *opt = &option_map[pos];

            switch (opt->type)
            {
            case TYPE_BOOL:
                sprintf(buffer, "%s=%s\n", opt->option_name, *((bool *)opt->ptr) ? "true" : "false");
                break;
            case TYPE_SIGNED:
                sprintf(buffer, "%s=%d\n", opt->option_name, *((int32_t *)opt->ptr));
                break;
            case TYPE_UNSIGNED:
            case TYPE_HEX:
                sprintf(buffer, "%s=%u\n", opt->option_name, *((uint32_t *)opt->ptr));
                break;
            case TYPE_FLOAT:
                sprintf(buffer, "%s=%f\n", opt->option_name, *((float *)opt->ptr));
                break;
            case TYPE_STRING:
                sprintf(buffer, "%s=%s\n", opt->option_name, *((char **)opt->ptr));
                break;
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
    size_t from_read;
    size_t read_length;
    bool last_line_incomplete = false;
    char *line;
    from_read = 0;
    while (fsReadFile(file, &buffer[from_read], sizeof(buffer) - from_read - 1, &read_length) == NO_ERROR || last_line_incomplete)
    {
        read_length = from_read + read_length;
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
                char *value_str = &line[osStrlen(option_name) + 1];

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
                            TRACE_INFO("%s=%s\r\n", opt->option_name, *((bool *)opt->ptr) ? "true" : "false");
                            break;
                        case TYPE_SIGNED:
                            *((int32_t *)opt->ptr) = atoi(value_str);
                            TRACE_INFO("%s=%d\r\n", opt->option_name, *((int32_t *)opt->ptr));
                            break;
                        case TYPE_UNSIGNED:
                        case TYPE_HEX:
                            *((uint32_t *)opt->ptr) = strtoul(value_str, NULL, 10);
                            TRACE_INFO("%s=%u\r\n", opt->option_name, *((uint32_t *)opt->ptr));
                            break;
                        case TYPE_FLOAT:
                            *((float *)opt->ptr) = strtof(value_str, NULL);
                            TRACE_INFO("%s=%f\r\n", opt->option_name, *((float *)opt->ptr));
                            break;
                        case TYPE_STRING:
                            free(*((char **)opt->ptr));
                            *((char **)opt->ptr) = strdup(value_str);
                            TRACE_INFO("%s=%s\r\n", opt->option_name, *((char **)opt->ptr));
                            break;

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

        if (last_line_incomplete && read_length == 0)
            break;

        // Check if the last line is incomplete (does not end with a newline character)
        last_line_incomplete = (buffer[read_length - 1] != '\n');
        if (last_line_incomplete)
        {
            from_read = strlen(line);
            memmove(buffer, line, from_read);
        }
        else
        {
            from_read = 0;
        }
    }
    fsCloseFile(file);

    if (Settings.configVersion < CONFIG_VERSION)
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

    return *(const char **)opt->ptr;
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

    char **ptr = (char **)opt->ptr;

    if (*ptr)
    {
        free(*ptr);
    }

    *ptr = strdup(value);
    return true;
}
