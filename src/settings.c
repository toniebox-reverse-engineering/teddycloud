
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "version.h"
#include "debug.h"
#include "settings.h"
#include "mutex_manager.h"
#include "tls_adapter.h"

#include "fs_port.h"

#define OVERLAY_CONFIG_PREFIX "overlay."
static settings_t Settings_Overlay[MAX_OVERLAYS];
static setting_item_t *Option_Map_Overlay[MAX_OVERLAYS];
static uint16_t settings_size = 0;
DateTime settings_last_load;
DateTime settings_last_load_ovl;

static void option_map_init(uint8_t settingsId)
{
    settings_t *settings = &Settings_Overlay[settingsId];

    OPTION_START()

    OPTION_INTERNAL_UNSIGNED("configVersion", &settings->configVersion, 0, 0, 255, "Config version")
    OPTION_INTERNAL_STRING("commonName", &settings->commonName, "default", "common name of the certificate (for overlays)")
    OPTION_INTERNAL_STRING("boxName", &settings->boxName, "Toniebox", "Name of the box")

    OPTION_TREE_DESC("log", "Logging")
    OPTION_UNSIGNED("log.level", &settings->log.level, 4, 0, 6, "Loglevel", "0=off - 6=verbose")
    OPTION_BOOL("log.color", &settings->log.color, TRUE, "Colored log", "Colored log")
    OPTION_BOOL("log.logFullAuth", &settings->log.logFullAuth, FALSE, "Log auth", "Log full authentication of tags")

    /* settings for HTTPS server */
    OPTION_TREE_DESC("core.server", "Server ports")
    OPTION_UNSIGNED("core.server.https_port", &settings->core.https_port, 443, 1, 65535, "HTTPS port", "HTTPS port")
    OPTION_UNSIGNED("core.server.http_port", &settings->core.http_port, 80, 1, 65535, "HTTP port", "HTTP port")

    OPTION_TREE_DESC("core.server", "HTTP server")
    OPTION_STRING("core.host_url", &settings->core.host_url, "http://localhost", "Host URL", "URL to teddyCloud server")
    OPTION_STRING("core.certdir", &settings->core.certdir, "certs/client", "Cert dir", "Directory to upload genuine client certificates")
    OPTION_STRING("core.contentdir", &settings->core.contentdir, "default", "Content dir", "Directory for placing cloud content")
    OPTION_STRING("core.librarydir", &settings->core.librarydir, "library", "Library dir", "Directory of the audio library")
    OPTION_STRING("core.datadir", &settings->core.datadir, "data", "Data dir", "Base directory for 'contentdir' and 'wwwdir' when they are relative")
    OPTION_STRING("core.wwwdir", &settings->core.wwwdir, "www", "WWW dir", "Directory for placing web content")
    OPTION_STRING("core.sslkeylogfile", &settings->core.sslkeylogfile, "", "SSL-key logfile", "SSL/TLS key log filename")

    OPTION_TREE_DESC("core.server_cert", "HTTPS server certificates")
    OPTION_TREE_DESC("core.client_cert.file", "File certificates")
    OPTION_STRING("core.server_cert.file.ca", &settings->core.server_cert.file.ca, "certs/server/ca-root.pem", "Server CA", "Server CA")
    OPTION_STRING("core.server_cert.file.crt", &settings->core.server_cert.file.crt, "certs/server/teddy-cert.pem", "Server certificate", "Server certificate")
    OPTION_STRING("core.server_cert.file.key", &settings->core.server_cert.file.key, "certs/server/teddy-key.pem", "Server key", "Server key")
    OPTION_TREE_DESC("core.server_cert.data", "Raw certificates")
    OPTION_STRING("core.server_cert.data.ca", &settings->core.server_cert.data.ca, "", "Server CA data", "Server CA data")
    OPTION_STRING("core.server_cert.data.crt", &settings->core.server_cert.data.crt, "", "Server certificate data", "Server certificate data")
    OPTION_STRING("core.server_cert.data.key", &settings->core.server_cert.data.key, "", "Server key data", "Server key data")

    /* settings for HTTPS/cloud client */
    OPTION_TREE_DESC("core.client_cert", "Cloud client certificates")
    OPTION_TREE_DESC("core.client_cert.file", "File certificates")
    OPTION_STRING("core.client_cert.file.ca", &settings->core.client_cert.file.ca, "certs/client/ca.der", "Client CA", "Client CA")
    OPTION_STRING("core.client_cert.file.crt", &settings->core.client_cert.file.crt, "certs/client/client.der", "Client certificate", "Client certificate")
    OPTION_STRING("core.client_cert.file.key", &settings->core.client_cert.file.key, "certs/client/private.der", "Client key", "Client key")
    OPTION_TREE_DESC("core.client_cert.data", "Raw certificates")
    OPTION_STRING("core.client_cert.data.ca", &settings->core.client_cert.data.ca, "", "Client CA", "Client CA")
    OPTION_STRING("core.client_cert.data.crt", &settings->core.client_cert.data.crt, "", "Client certificate data", "Client certificate data")
    OPTION_STRING("core.client_cert.data.key", &settings->core.client_cert.data.key, "", "Client key data", "Client key data")

    OPTION_STRING("core.allowOrigin", &settings->core.allowOrigin, "", "CORS Allow-Origin", "Set CORS Access-Control-Allow-Origin header")

    OPTION_BOOL("core.flex_enabled", &settings->core.flex_enabled, TRUE, "Enable Flex-Tonie", "When enabled this UID always gets assigned the audio selected from web interface")
    OPTION_STRING("core.flex_uid", &settings->core.flex_uid, "", "Flex-Tonie UID", "UID which shall get selected audio files assigned")

    OPTION_TREE_DESC("internal", "Internal")
    OPTION_INTERNAL_STRING("internal.server.ca", &settings->internal.server.ca, "", "Server CA data")
    OPTION_INTERNAL_STRING("internal.server.crt", &settings->internal.server.crt, "", "Server certificate data")
    OPTION_INTERNAL_STRING("internal.server.key", &settings->internal.server.key, "", "Server key data")
    OPTION_INTERNAL_STRING("internal.client.ca", &settings->internal.client.ca, "", "Client CA")
    OPTION_INTERNAL_STRING("internal.client.crt", &settings->internal.client.crt, "", "Client certificate data")
    OPTION_INTERNAL_STRING("internal.client.key", &settings->internal.client.key, "", "Client key data")

    OPTION_INTERNAL_BOOL("internal.exit", &settings->internal.exit, FALSE, "Exit the server")
    OPTION_INTERNAL_SIGNED("internal.returncode", &settings->internal.returncode, 0, -128, 127, "Returncode when exiting")
    OPTION_INTERNAL_BOOL("internal.config_init", &settings->internal.config_init, FALSE, "Config initialized?")
    OPTION_INTERNAL_BOOL("internal.config_used", &settings->internal.config_used, FALSE, "Config used?")
    OPTION_INTERNAL_BOOL("internal.config_changed", &settings->internal.config_changed, FALSE, "Config changed and unsaved?")
    OPTION_INTERNAL_BOOL("internal.logColorSupport", &settings->internal.logColorSupport, FALSE, "Terminal supports color (log)")
    OPTION_INTERNAL_STRING("internal.cwd", &settings->internal.cwd, "", "current working dir (cwd)")
    OPTION_INTERNAL_STRING("internal.contentdirrel", &settings->internal.contentdirrel, "", "Directory where cloud content is placed (relative)")
    OPTION_INTERNAL_STRING("internal.contentdirfull", &settings->internal.contentdirfull, "", "Directory where cloud content is placed (absolute)")
    OPTION_INTERNAL_STRING("internal.librarydirfull", &settings->internal.librarydirfull, "", "Directory of the audio library (absolute)")
    OPTION_INTERNAL_STRING("internal.datadirfull", &settings->internal.datadirfull, "", "Directory where data is placed (absolute)")
    OPTION_INTERNAL_STRING("internal.wwwdirfull", &settings->internal.wwwdirfull, "", "Directory where web content is placed (absolute)")
    OPTION_INTERNAL_STRING("internal.overlayUniqueId", &settings->internal.overlayUniqueId, "", "Unique Id of the overlay")
    OPTION_INTERNAL_UNSIGNED("internal.overlayNumber", &settings->internal.overlayNumber, 0, 0, MAX_OVERLAYS, "Id of the overlay")
    OPTION_INTERNAL_STRING("internal.assign_unknown", &settings->internal.assign_unknown, "", "TAF file to assign to the next unknown tag")

    OPTION_INTERNAL_UNSIGNED("internal.rtnl.lastEarId", &settings->internal.rtnl.lastEarId, EAR_NONE, EAR_BIG, EAR_NONE, "Id of the last pressed id")
    OPTION_INTERNAL_UNSIGNED("internal.rtnl.lastEarpress", &settings->internal.rtnl.lastEarpress, 0, 0, UINT64_MAX, "Timestamp of the last pressed ear")
    OPTION_INTERNAL_BOOL("internal.rtnl.wasDoubleEarpress", &settings->internal.rtnl.wasDoubleEarpress, FALSE, "Was double Earpress?")
    OPTION_INTERNAL_UNSIGNED("internal.rtnl.multipressTime", &settings->internal.rtnl.multipressTime, 300, 0, UINT16_MAX, "Multipress time")

    OPTION_INTERNAL_STRING("internal.version.id", &settings->internal.version.id, "", "Version id")
    OPTION_INTERNAL_STRING("internal.version.git_sha_short", &settings->internal.version.git_sha_short, "", "Short Git SHA-1 hash of the build version")
    OPTION_INTERNAL_STRING("internal.version.git_sha", &settings->internal.version.git_sha, "", "Full Git SHA-1 hash of the build version")
    OPTION_INTERNAL_BOOL("internal.version.dirty", &settings->internal.version.dirty, FALSE, "Indicates if the build was made from a modified (dirty) git tree")
    OPTION_INTERNAL_STRING("internal.version.datetime", &settings->internal.version.datetime, "", "Datetime of the build or git commit")
    OPTION_INTERNAL_STRING("internal.version.platform", &settings->internal.version.platform, "", "Platform on which the software was built")
    OPTION_INTERNAL_STRING("internal.version.os", &settings->internal.version.os, "", "Operating System used for the build")
    OPTION_INTERNAL_STRING("internal.version.architecture", &settings->internal.version.architecture, "", "System architecture for the build")
    OPTION_INTERNAL_STRING("internal.version.v_short", &settings->internal.version.v_short, "", "Concise version descriptor")
    OPTION_INTERNAL_STRING("internal.version.v_long", &settings->internal.version.v_long, "", "Detailed version descriptor")
    OPTION_INTERNAL_STRING("internal.version.v_full", &settings->internal.version.v_full, "", "Complete version descriptor with all details")

    OPTION_INTERNAL_STRING("internal.toniebox_firmware.rtnlVersion", &settings->internal.toniebox_firmware.rtnlVersion, "", "Firmware version from RTNL")
    OPTION_INTERNAL_STRING("internal.toniebox_firmware.rtnlFullVersion", &settings->internal.toniebox_firmware.rtnlFullVersion, "", "Firmware full version from RTNL")
    OPTION_INTERNAL_STRING("internal.toniebox_firmware.rtnlDetail", &settings->internal.toniebox_firmware.rtnlDetail, "", "Firmware detail information")
    OPTION_INTERNAL_STRING("internal.toniebox_firmware.rtnlRegion", &settings->internal.toniebox_firmware.rtnlRegion, "", "Firmware region")
    OPTION_INTERNAL_UNSIGNED("internal.toniebox_firmware.otaVersionSfx", &settings->internal.toniebox_firmware.otaVersionSfx, 0, 0, 0, " ota version")
    OPTION_INTERNAL_UNSIGNED("internal.toniebox_firmware.otaVersionServicePack", &settings->internal.toniebox_firmware.otaVersionServicePack, 0, 0, 0, " ota version")
    OPTION_INTERNAL_UNSIGNED("internal.toniebox_firmware.otaVersionHtml", &settings->internal.toniebox_firmware.otaVersionHtml, 0, 0, 0, " ota version")
    OPTION_INTERNAL_UNSIGNED("internal.toniebox_firmware.otaVersionEu", &settings->internal.toniebox_firmware.otaVersionEu, 0, 0, 0, " ota version")
    OPTION_INTERNAL_UNSIGNED("internal.toniebox_firmware.otaVersionPd", &settings->internal.toniebox_firmware.otaVersionPd, 0, 0, 0, " ota version")

    OPTION_TREE_DESC("cloud", "Cloud")
    OPTION_BOOL("cloud.enabled", &settings->cloud.enabled, FALSE, "Cloud enabled", "Generally enable cloud operation")
    OPTION_STRING("cloud.remote_hostname", &settings->cloud.remote_hostname, "prod.de.tbs.toys", "Cloud hostname", "Hostname of remote cloud server")
    OPTION_UNSIGNED("cloud.remote_port", &settings->cloud.remote_port, 443, 1, 65535, "Cloud port", "Port of remote cloud server")
    OPTION_BOOL("cloud.enableV1Claim", &settings->cloud.enableV1Claim, TRUE, "Forward 'claim'", "Forward 'claim' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV1CloudReset", &settings->cloud.enableV1CloudReset, FALSE, "Forward 'cloudReset'", "Forward 'cloudReset' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV1FreshnessCheck", &settings->cloud.enableV1FreshnessCheck, TRUE, "Forward 'freshnessCheck'", "Forward 'freshnessCheck' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV1Log", &settings->cloud.enableV1Log, FALSE, "Forward 'log'", "Forward 'log' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV1Time", &settings->cloud.enableV1Time, FALSE, "Forward 'time'", "Forward 'time' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV1Ota", &settings->cloud.enableV1Ota, FALSE, "Forward 'ota'", "Forward 'ota' queries to tonies cloud")
    OPTION_BOOL("cloud.enableV2Content", &settings->cloud.enableV2Content, TRUE, "Forward 'content'", "Forward 'content' queries to tonies cloud")
    OPTION_BOOL("cloud.cacheContent", &settings->cloud.cacheContent, FALSE, "Cache content", "Cache cloud content on local server")
    OPTION_BOOL("cloud.markCustomTagByPass", &settings->cloud.markCustomTagByPass, TRUE, "Autodetect custom tags", "Automatically mark custom tags by password")
    OPTION_BOOL("cloud.prioCustomContent", &settings->cloud.prioCustomContent, TRUE, "Prioritize custom content", "Prioritize custom content over tonies content (force update)")

    OPTION_TREE_DESC("toniebox", "Toniebox")
    OPTION_BOOL("toniebox.overrideCloud", &settings->toniebox.overrideCloud, TRUE, "Override cloud settings", "Override tonies cloud settings")
    OPTION_UNSIGNED("toniebox.max_vol_spk", &settings->toniebox.max_vol_spk, 3, 0, 3, "Limit speaker volume", "Limit speaker volume (0-3)")
    OPTION_UNSIGNED("toniebox.max_vol_hdp", &settings->toniebox.max_vol_hdp, 3, 0, 3, "Limit headphone volume", "Limit headphone volume (0-3)")
    OPTION_BOOL("toniebox.slap_enabled", &settings->toniebox.slap_enabled, TRUE, "Slap to skip", "Enable track skip via slapping gesture")
    OPTION_BOOL("toniebox.slap_back_left", &settings->toniebox.slap_back_left, FALSE, "Slap direction", "Determine slap direction for skipping track: False for left-backward, True for left-forward")
    OPTION_UNSIGNED("toniebox.led", &settings->toniebox.led, 0, 0, 2, "LED brightness", "0=on, 1=off, 2=dimmed")

    OPTION_TREE_DESC("rtnl", "RTNL log")
    OPTION_BOOL("rtnl.logRaw", &settings->rtnl.logRaw, FALSE, "Log RTNL (bin)", "Enable logging for raw RTNL data")
    OPTION_BOOL("rtnl.logHuman", &settings->rtnl.logHuman, FALSE, "Log RTNL (csv)", "Enable logging for human-readable RTNL data")
    OPTION_STRING("rtnl.logRawFile", &settings->rtnl.logRawFile, "config/rtnl.bin", "RTNL bin file", "Specify the filepath for raw RTNL log")
    OPTION_STRING("rtnl.logHumanFile", &settings->rtnl.logHumanFile, "config/rtnl.csv", "RTNL csv file", "Specify the filepath for human-readable RTNL log")

    OPTION_TREE_DESC("mqtt", "MQTT")
    OPTION_BOOL("mqtt.enabled", &settings->mqtt.enabled, FALSE, "Enable MQTT", "Enable MQTT client")
    OPTION_STRING("mqtt.hostname", &settings->mqtt.hostname, "", "MQTT hostname", "MQTT hostname")
    OPTION_UNSIGNED("mqtt.port", &settings->mqtt.port, 1883, 1, 65535, "MQTT port", "Port of MQTT server")
    OPTION_STRING("mqtt.username", &settings->mqtt.username, "", "Username", "Username")
    OPTION_STRING("mqtt.password", &settings->mqtt.password, "", "Password", "Password")
    OPTION_STRING("mqtt.identification", &settings->mqtt.identification, "", "Client identification", "Client identification")
    OPTION_STRING("mqtt.topic", &settings->mqtt.topic, "teddyCloud", "Topic prefix", "Topic prefix")
    OPTION_UNSIGNED("mqtt.qosLevel", &settings->mqtt.qosLevel, 0, 0, 2, "QoS level", "QoS level")
    OPTION_END()

    settings_size = sizeof(option_map_array) / sizeof(option_map_array[0]) - 1;

    if (Option_Map_Overlay[settingsId] == NULL)
    {
        Option_Map_Overlay[settingsId] = osAllocMem(sizeof(option_map_array));
    }

    osMemcpy(Option_Map_Overlay[settingsId], option_map_array, sizeof(option_map_array));
}

static setting_item_t *get_option_map(const char *overlay)
{
    return Option_Map_Overlay[get_overlay_id(overlay)];
}

void overlay_settings_init()
{
    for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
    {
        if (Settings_Overlay[i].internal.config_init)
        {
            settings_deinit(i);
        }

        option_map_init(i);

        setting_item_t *option_map = Option_Map_Overlay[i];
        setting_item_t *option_map_src = Option_Map_Overlay[0];

        int pos = 0;
        while (option_map[pos].type != TYPE_END)
        {
            setting_item_t *opt = &option_map[pos];
            setting_item_t *opt_src = &option_map_src[pos];

            switch (opt->type)
            {
            case TYPE_BOOL:
                *((bool *)opt->ptr) = *((bool *)opt_src->ptr);
                break;
            case TYPE_SIGNED:
            case TYPE_UNSIGNED:
            case TYPE_HEX:
            case TYPE_FLOAT:
                *((uint32_t *)opt->ptr) = *((uint32_t *)opt_src->ptr);
                break;
            case TYPE_STRING:
                *((char **)opt->ptr) = strdup(*((char **)opt_src->ptr));
                break;
            default:
                break;
            }
            pos++;
        }
        Settings_Overlay[i].internal.overlayNumber = i;
        Settings_Overlay[i].internal.config_init = true;
        Settings_Overlay[i].internal.config_used = false;
    }
}

settings_t *get_settings()
{
    return get_settings_id(0);
}

settings_t *get_settings_ovl(const char *overlay_unique_id)
{
    return get_settings_id(get_overlay_id(overlay_unique_id));
}
settings_t *get_settings_id(uint8_t settingsId)
{
    return &Settings_Overlay[settingsId];
}

settings_t *get_settings_cn(const char *commonName)
{
    mutex_lock(MUTEX_SETTINGS_CN);
    if (commonName != NULL && osStrcmp(commonName, "") != 0)
    {

        for (size_t i = 1; i < MAX_OVERLAYS; i++)
        {
            if (osStrcmp(Settings_Overlay[i].commonName, commonName) == 0)
            {
                mutex_unlock(MUTEX_SETTINGS_CN);
                return &Settings_Overlay[i];
            }
        }

        for (size_t i = 1; i < MAX_OVERLAYS; i++)
        {
            if (!Settings_Overlay[i].internal.config_used)
            {
                char *boxId = settings_sanitize_box_id((const char *)commonName);
                char *boxPrefix = "teddyCloud Box ";
                char *boxName = osAllocMem(osStrlen(boxPrefix) + osStrlen(commonName) + 1);
                osSprintf(boxName, "%s%s", boxPrefix, commonName);

                settings_set_string_id("commonName", boxId, i);
                settings_set_string_id("internal.overlayUniqueId", boxId, i);
                settings_set_string_id("boxName", boxName, i);
                settings_get_by_name_id("core.client_cert.file.crt", i)->overlayed = true;
                settings_get_by_name_id("core.client_cert.file.key", i)->overlayed = true;
                Settings_Overlay[i].internal.config_used = true;
                settings_save_ovl(true);
                mutex_unlock(MUTEX_SETTINGS_CN);

                free(boxId);
                free(boxName);
                return &Settings_Overlay[i];
            }
        }

        TRACE_WARNING("Could not create new overlay for unknown client %s, to many overlays.\r\n", commonName);
    }
    mutex_unlock(MUTEX_SETTINGS_CN);
    return get_settings();
}

uint8_t get_overlay_id(const char *overlay_unique_id)
{
    if (overlay_unique_id == NULL || osStrlen(overlay_unique_id) == 0)
    {
        return 0;
    }

    for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
    {
        if (osStrcmp(Settings_Overlay[i].internal.overlayUniqueId, overlay_unique_id) == 0)
        {
            return i;
        }
    }
    return 0;
}

void settings_resolve_dir(char **resolvedPath, char *path, char *basePath)
{
    if (path[0] == '/')
    {
        snprintf(*resolvedPath, 255, "%s", path);
    }
    else
    {
        snprintf(*resolvedPath, 255, "%s/%s", basePath, path);
    }
}

void settings_generate_internal_dirs(settings_t *settings)
{
    free(settings->internal.contentdirrel);
    free(settings->internal.contentdirfull);
    free(settings->internal.librarydirfull);
    free(settings->internal.datadirfull);
    free(settings->internal.wwwdirfull);

    settings->internal.contentdirrel = osAllocMem(256);
    settings->internal.contentdirfull = osAllocMem(256);
    settings->internal.librarydirfull = osAllocMem(256);
    settings->internal.datadirfull = osAllocMem(256);
    settings->internal.wwwdirfull = osAllocMem(256);

    char *tmpPath = osAllocMem(256);

    settings_resolve_dir(&settings->internal.datadirfull, settings->core.datadir, settings->internal.cwd);

    settings_resolve_dir(&settings->internal.wwwdirfull, settings->core.wwwdir, settings->internal.datadirfull);

    settings_resolve_dir(&tmpPath, settings->core.contentdir, "content");
    settings_resolve_dir(&settings->internal.contentdirrel, tmpPath, settings->core.datadir);
    settings_resolve_dir(&settings->internal.contentdirfull, tmpPath, settings->internal.datadirfull);
    fsCreateDir(settings->internal.contentdirfull);

    settings_resolve_dir(&settings->internal.librarydirfull, settings->core.librarydir, settings->internal.datadirfull);

    free(tmpPath);
}

void settings_changed()
{
    Settings_Overlay[0].internal.config_changed = true;
    settings_generate_internal_dirs(get_settings());
    settings_load_ovl(true);
}

void settings_deinit(uint8_t overlayNumber)
{
    int pos = 0;
    setting_item_t *option_map = Option_Map_Overlay[overlayNumber];
    if (option_map == NULL)
    {
        return;
    }

    while (option_map[pos].type != TYPE_END)
    {
        setting_item_t *opt = &option_map[pos];
        opt->overlayed = false;

        switch (opt->type)
        {
        case TYPE_STRING:
            if (*((char **)opt->ptr))
            {
                osFreeMem(*((char **)opt->ptr));
            }
            break;
        default:
            break;
        }
        pos++;
    }
    Settings_Overlay[overlayNumber].internal.config_init = false;

    osFreeMem(Option_Map_Overlay[overlayNumber]);
    Option_Map_Overlay[overlayNumber] = NULL;
}

void settings_deinit_all()
{
    for (uint8_t i = 0; i < MAX_OVERLAYS; i++)
    {
        settings_deinit(i);
    }
}

void settings_init(char *cwd)
{
    option_map_init(0);

    Settings_Overlay[0].log.level = LOGLEVEL_INFO;

    int pos = 0;
    setting_item_t *option_map = get_option_map(NULL);
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
            TRACE_DEBUG("  %s = %" PRIu64 "\r\n", opt->option_name, opt->init.unsigned_value);
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
    settings_set_string("internal.cwd", cwd);

    settings_set_string("internal.version.id", BUILD_VERSION);
    settings_set_string("internal.version.git_sha_short", BUILD_GIT_SHORT_SHA);
    settings_set_string("internal.version.git_sha", BUILD_GIT_SHA);
    settings_set_bool("internal.version.id", BUILD_GIT_IS_DIRTY);
    settings_set_string("internal.version.datetime", BUILD_DATETIME);
    settings_set_string("internal.version.platform", BUILD_PLATFORM);
    settings_set_string("internal.version.os", BUILD_OS);
    settings_set_string("internal.version.architecture", BUILD_ARCH);
    settings_set_string("internal.version.v_short", BUILD_FULL_NAME_SHORT);
    settings_set_string("internal.version.v_long", BUILD_FULL_NAME_LONG);
    settings_set_string("internal.version.v_full", BUILD_FULL_NAME_FULL);

    settings_set_bool("internal.logColorSupport", supportsAnsiColors());

    Settings_Overlay[0].internal.config_init = true;
    Settings_Overlay[0].internal.config_used = true;

    settings_changed();
    settings_load();
}

void settings_save()
{
    settings_save_ovl(false);
    settings_save_ovl(true);
}

void settings_save_ovl(bool overlay)
{
    char_t *config_path = (!overlay ? CONFIG_PATH : CONFIG_OVERLAY_PATH);

    TRACE_INFO("Save settings to %s\r\n", config_path);
    FsFile *file = fsOpenFile(config_path, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
    if (file == NULL)
    {
        TRACE_WARNING("Failed to open config file for writing\r\n");
        return;
    }

    for (size_t i = 0; i < MAX_OVERLAYS; i++)
    {
        int pos = 0;
        char buffer[256]; // Buffer to hold the file content

        if (i == 0 && overlay)
        {
            i++;
        }
        else if (i > 0 && !overlay)
        {
            break;
        }
        Settings_Overlay[i].configVersion = CONFIG_VERSION;

        setting_item_t *option_map = Option_Map_Overlay[i];
        while (option_map[pos].type != TYPE_END)
        {
            setting_item_t *opt = &option_map[pos];
            if (!opt->internal || !osStrcmp(opt->option_name, "configVersion") || (overlay && (!osStrcmp(opt->option_name, "commonName") || !osStrcmp(opt->option_name, "boxName"))))
            {
                char *overlayPrefix;
                if (overlay)
                {
                    if (!opt->overlayed)
                    {
                        pos++;
                        continue; // Only write overlay settings if they were overlayed
                    }
                    overlayPrefix = osAllocMem(8 + osStrlen(Settings_Overlay[i].internal.overlayUniqueId) + 1 + 1); // overlay.[NAME].
                    osStrcpy(overlayPrefix, "overlay.");
                    osStrcat(overlayPrefix, Settings_Overlay[i].internal.overlayUniqueId);
                    osStrcat(overlayPrefix, ".");
                }
                else
                {
                    overlayPrefix = osAllocMem(1);
                    osStrcpy(overlayPrefix, "");
                }

                switch (opt->type)
                {
                case TYPE_BOOL:
                    sprintf(buffer, "%s%s=%s\n", overlayPrefix, opt->option_name, *((bool *)opt->ptr) ? "true" : "false");
                    break;
                case TYPE_SIGNED:
                    sprintf(buffer, "%s%s=%d\n", overlayPrefix, opt->option_name, *((int32_t *)opt->ptr));
                    break;
                case TYPE_UNSIGNED:
                case TYPE_HEX:
                    sprintf(buffer, "%s%s=%u\n", overlayPrefix, opt->option_name, *((uint32_t *)opt->ptr));
                    break;
                case TYPE_FLOAT:
                    sprintf(buffer, "%s%s=%f\n", overlayPrefix, opt->option_name, *((float *)opt->ptr));
                    break;
                case TYPE_STRING:
                    sprintf(buffer, "%s%s=%s\n", overlayPrefix, opt->option_name, *((char **)opt->ptr));
                    break;
                default:
                    buffer[0] = '\0';
                    break;
                }
                if (osStrlen(buffer) > 0)
                    fsWriteFile(file, buffer, osStrlen(buffer));
                osFreeMem(overlayPrefix);
            }
            pos++;
        }
    }
    fsCloseFile(file);
    Settings_Overlay[0].internal.config_changed = false;
}

void settings_load()
{
    settings_load_ovl(false);
    settings_load_ovl(true);
}

void settings_load_ovl(bool overlay)
{
    char_t *config_path = (!overlay ? CONFIG_PATH : CONFIG_OVERLAY_PATH);

    TRACE_INFO("Load settings from %s\r\n", config_path);
    if (!fsFileExists(config_path))
    {
        TRACE_WARNING("Config file does not exist, creating it...\r\n");
        settings_save_ovl(overlay);
        return;
    }

    uint32_t file_size;
    error_t result = fsGetFileSize(config_path, &file_size);
    if (result != NO_ERROR)
    {
        TRACE_WARNING("Failed to get config file size\r\n");
        return;
    }

    FsFile *file = fsOpenFile(config_path, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        TRACE_WARNING("Failed to open config file for reading\r\n");
        return;
    }

    if (overlay)
    {
        overlay_settings_init();
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

                char *overlay_unique_id = NULL;
                char *tokenizer = NULL;
                if (overlay && osStrncmp(OVERLAY_CONFIG_PREFIX, option_name, osStrlen(OVERLAY_CONFIG_PREFIX)) == 0)
                {
                    option_name += osStrlen(OVERLAY_CONFIG_PREFIX);
                    tokenizer = strdup(option_name);
                    overlay_unique_id = settings_sanitize_box_id((const char *)strtok(tokenizer, "."));
                    option_name += osStrlen(overlay_unique_id) + 1;

                    if (get_overlay_id(overlay_unique_id) == 0)
                    {
                        for (size_t i = 1; i < MAX_OVERLAYS; i++)
                        {
                            if (!Settings_Overlay[i].internal.config_used)
                            {
                                settings_set_string_id("internal.overlayUniqueId", overlay_unique_id, i);
                                Settings_Overlay[i].internal.config_used = true;
                                break;
                            }
                        }
                    }
                }

                if (option_name != NULL && value_str != NULL)
                {
                    // Find the corresponding setting item
                    setting_item_t *opt = settings_get_by_name_ovl(option_name, overlay_unique_id);
                    if (opt != NULL)
                    {
                        // Update the setting value based on the type
                        if (overlay)
                        {
                            opt->overlayed = true;
                        }
                        switch (opt->type)
                        {
                        case TYPE_BOOL:
                            if (strcmp(value_str, "true") == 0)
                                *((bool *)opt->ptr) = true;
                            else if (strcmp(value_str, "false") == 0)
                                *((bool *)opt->ptr) = false;
                            else
                                TRACE_WARNING("Invalid boolean value '%s' for setting '%s'\r\n", value_str, option_name);
                            TRACE_DEBUG("%s=%s\r\n", opt->option_name, *((bool *)opt->ptr) ? "true" : "false");
                            break;
                        case TYPE_SIGNED:
                            *((int32_t *)opt->ptr) = atoi(value_str);
                            TRACE_DEBUG("%s=%d\r\n", opt->option_name, *((int32_t *)opt->ptr));
                            break;
                        case TYPE_UNSIGNED:
                        case TYPE_HEX:
                            *((uint32_t *)opt->ptr) = strtoul(value_str, NULL, 10);
                            TRACE_DEBUG("%s=%u\r\n", opt->option_name, *((uint32_t *)opt->ptr));
                            break;
                        case TYPE_FLOAT:
                            *((float *)opt->ptr) = strtof(value_str, NULL);
                            TRACE_DEBUG("%s=%f\r\n", opt->option_name, *((float *)opt->ptr));
                            break;
                        case TYPE_STRING:
                            free(*((char **)opt->ptr));
                            *((char **)opt->ptr) = strdup(value_str);
                            TRACE_DEBUG("%s=%s\r\n", opt->option_name, *((char **)opt->ptr));
                            break;

                        default:
                            opt->overlayed = false;
                            break;
                        }
                    }
                    else
                    {
                        TRACE_WARNING("Setting item '%s' not found\r\n", option_name);
                    }
                }
                osFreeMem(overlay_unique_id);
                osFreeMem(tokenizer);
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
    if (overlay)
    {
        for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
        {
            settings_generate_internal_dirs(&Settings_Overlay[i]);
            settings_load_certs_id(i);
            Settings_Overlay[i].internal.config_changed = false;
        }
    }
    else
    {
        settings_generate_internal_dirs(get_settings());
        settings_load_certs_id(0);

        if (Settings_Overlay[0].configVersion < CONFIG_VERSION)
        {
            settings_save();
        }
        Settings_Overlay[0].internal.config_changed = false;
    }

    FsFileStat stat;
    if (fsGetFileStat(config_path, &stat) == NO_ERROR)
    {
        if (overlay)
        {
            settings_last_load_ovl = stat.modified;
        }
        else
        {
            settings_last_load = stat.modified;
        }
    }
}

uint16_t settings_get_size()
{
    return settings_size;
}

setting_item_t *settings_get(int index)
{
    return settings_get_ovl(index, NULL);
}

setting_item_t *settings_get_ovl(int index, const char *overlay_name)
{
    if (index < settings_get_size())
        return &get_option_map(overlay_name)[index];
    TRACE_WARNING("Setting item #%d not found\r\n", index);
    return NULL;
}

setting_item_t *settings_get_by_name(const char *item)
{
    return settings_get_by_name_ovl(item, NULL);
}

setting_item_t *settings_get_by_name_ovl(const char *item, const char *overlay_name)
{
    return settings_get_by_name_id(item, get_overlay_id(overlay_name));
}

setting_item_t *settings_get_by_name_id(const char *item, uint8_t settingsId)
{
    int pos = 0;
    setting_item_t *option_map = Option_Map_Overlay[settingsId];
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
    return settings_get_bool_ovl(item, NULL);
}

bool settings_get_bool_ovl(const char *item, const char *overlay_name)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    return *((bool *)opt->ptr);
}

bool settings_set_bool(const char *item, bool value)
{
    return settings_set_bool_ovl(item, value, NULL);
}
bool settings_set_bool_ovl(const char *item, bool value, const char *overlay_name)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    *((bool *)opt->ptr) = value;

    if (overlay_name)
    {
        opt->overlayed = true;
    }
    if (!opt->internal)
    {
        settings_changed();
    }
    return true;
}

int32_t settings_get_signed(const char *item)
{
    return settings_get_signed_ovl(item, NULL);
}

int32_t settings_get_signed_ovl(const char *item, const char *overlay_name)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
    if (!opt || opt->type != TYPE_SIGNED)
    {
        return 0;
    }

    return *((int32_t *)opt->ptr);
}

bool settings_set_signed(const char *item, int32_t value)
{
    return settings_set_signed_ovl(item, value, NULL);
}
bool settings_set_signed_ovl(const char *item, int32_t value, const char *overlay_name)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
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

    if (overlay_name)
    {
        opt->overlayed = true;
    }
    if (!opt->internal)
    {
        settings_changed();
    }
    return true;
}

uint32_t settings_get_unsigned(const char *item)
{
    return settings_get_unsigned_ovl(item, NULL);
}
uint32_t settings_get_unsigned_ovl(const char *item, const char *overlay_name)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
    if (!opt || opt->type != TYPE_UNSIGNED)
    {
        return 0;
    }

    return *((uint32_t *)opt->ptr);
}

bool settings_set_unsigned(const char *item, uint32_t value)
{
    return settings_set_unsigned_ovl(item, value, NULL);
}
bool settings_set_unsigned_ovl(const char *item, uint32_t value, const char *overlay_name)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
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

    if (overlay_name)
    {
        opt->overlayed = true;
    }
    if (!opt->internal)
    {
        settings_changed();
    }
    return true;
}

float settings_get_float(const char *item)
{
    return settings_get_float_ovl(item, NULL);
}
float settings_get_float_ovl(const char *item, const char *overlay_name)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
    if (!opt || opt->type != TYPE_FLOAT)
    {
        return 0;
    }

    return *((float *)opt->ptr);
}

bool settings_set_float(const char *item, float value)
{
    return settings_set_float_ovl(item, value, NULL);
}
bool settings_set_float_ovl(const char *item, float value, const char *overlay_name)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_ovl(item, overlay_name);
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

    if (overlay_name)
    {
        opt->overlayed = true;
    }
    if (!opt->internal)
    {
        settings_changed();
    }
    return true;
}

const char *settings_get_string(const char *item)
{
    return settings_get_string_id(item, 0);
}
const char *settings_get_string_ovl(const char *item, const char *overlay_name)
{
    return settings_get_string_id(item, get_overlay_id(overlay_name));
}
const char *settings_get_string_id(const char *item, uint8_t settingsId)
{
    if (!item)
    {
        return NULL;
    }

    setting_item_t *opt = settings_get_by_name_id(item, settingsId);
    if (!opt || opt->type != TYPE_STRING)
    {
        return NULL;
    }

    return *(const char **)opt->ptr;
}

bool settings_set_string(const char *item, const char *value)
{
    return settings_set_string_id(item, value, 0);
}
bool settings_set_string_ovl(const char *item, const char *value, const char *overlay_name)
{
    return settings_set_string_id(item, value, get_overlay_id(overlay_name));
}
bool settings_set_string_id(const char *item, const char *value, uint8_t settingsId)
{
    if (!item || !value)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name_id(item, settingsId);
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

    if (settingsId > 0)
    {
        opt->overlayed = true;
    }
    if (!opt->internal)
    {
        settings_changed();
    }
    return true;
}

void settings_loop()
{
    FsFileStat stat;
    if (fsGetFileStat(CONFIG_PATH, &stat) == NO_ERROR)
    {
        if (compareDateTime(&stat.modified, &settings_last_load))
        {
            TRACE_INFO("Settings file changed. Reloading.\r\n");
            settings_load();
        }
    }
    if (fsGetFileStat(CONFIG_OVERLAY_PATH, &stat) == NO_ERROR)
    {
        if (compareDateTime(&stat.modified, &settings_last_load_ovl))
        {
            TRACE_INFO("Overlay settings file changed. Reloading.\r\n");
            settings_load();
        }
    }
}

char *settings_sanitize_box_id(const char *input_id)
{
    char *new_str = osAllocMem(osStrlen(input_id) + 1);
    if (new_str == NULL)
    {
        return NULL;
    }

    char *dst = new_str;
    const char *src = input_id;
    while (*src)
    {
        if (isalnum((unsigned char)*src) || *src == '_' || *src == '-')
        {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0'; // null terminate the string

    return new_str;
}

void settings_load_all_certs()
{
    for (size_t id = 0; id < MAX_OVERLAYS; id++)
    {
        settings_load_certs_id(id);
    }
}
void settings_load_certs_id(uint8_t settingsId)
{
    if (get_settings_id(settingsId)->internal.config_used)
    {
        load_cert("internal.server.ca", "core.server_cert.file.ca", "core.server_cert.data.ca", settingsId);
        load_cert("internal.server.crt", "core.server_cert.file.crt", "core.server_cert.data.crt", settingsId);
        load_cert("internal.server.key", "core.server_cert.file.key", "core.server_cert.data.key", settingsId);
        load_cert("internal.client.ca", "core.client_cert.file.ca", "core.client_cert.data.ca", settingsId);
        load_cert("internal.client.crt", "core.client_cert.file.crt", "core.client_cert.data.crt", settingsId);
        load_cert("internal.client.key", "core.client_cert.file.key", "core.client_cert.data.key", settingsId);
    }
}