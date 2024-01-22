
// Platform-specific dependencies
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "error.h"
#include "debug.h"
#include "cJSON.h"
#include "esp32.h"

#include "version.h"

#include "tls_adapter.h"
#include "cloud_request.h"

#include "settings.h"
#include "toniebox_state.h"
#include "mqtt.h"
#include "cert.h"
#include "toniefile.h"

#ifdef _WIN32
#include <direct.h>
#define PATH_LEN 260
#else
#include <unistd.h>
#include <limits.h>
#define PATH_LEN PATH_MAX
#endif

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443
#define PORT_MAX 65535

void platform_init(void);
void platform_deinit(void);
void server_init(bool test);
static char *get_cwd(char *buffer, size_t size);
static void print_usage(char *argv[]);

typedef enum
{
    PROT_HTTP,
    PROT_HTTPS
} Protocol;

bool parse_url(const char *url, char **hostname, uint16_t *port, char **uri, Protocol *protocol)
{
    if (strstr(url, "http://") == url)
    {
        *protocol = PROT_HTTP;
        url += strlen("http://");
    }
    else if (strstr(url, "https://") == url)
    {
        *protocol = PROT_HTTPS;
        url += strlen("https://");
    }
    else
    {
        TRACE_ERROR("Unknown protocol\r\n");
        return false;
    }

    char *port_start = strchr(url, ':');
    char *path_start = strchr(url, '/');
    if (path_start == NULL)
    {
        TRACE_ERROR("URL must contain a path\r\n");
        return false;
    }

    if (port_start != NULL)
    {
        // Port is specified
        int hostname_length = port_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        // ensures port is in a valid range before casting
        long temp = strtol(port_start + 1, NULL, 10);
        if ((temp >= 0) && (temp <= PORT_MAX))
        {
            *port = (uint16_t)temp;
        }
        else
        {
            *port = (*protocol == PROT_HTTP) ? DEFAULT_HTTP_PORT : DEFAULT_HTTPS_PORT;
        }
    }
    else
    {
        // Port is not specified, use default port based on protocol
        int hostname_length = path_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        *port = (*protocol == PROT_HTTP) ? DEFAULT_HTTP_PORT : DEFAULT_HTTPS_PORT;
    }

    *uri = strdup(path_start);

    return true;
}

int_t main(int argc, char *argv[])
{
    TRACE_PRINTF(BUILD_FULL_NAME_LONG "\r\n\r\n");

    error_t error = 0;

    char *cwd = calloc(PATH_LEN, sizeof(char));

    if ((cwd == NULL) || (get_cwd(cwd, PATH_LEN) == NULL))
    {
        free(cwd);
        return -1;
    }

    /* platform specific init */
    char *base_path = strdup(BASE_PATH);
    if (osStrlen(base_path) == 0)
    {
        char *linux_usrlocaletc = "/usr/local/etc/teddycloud";
        char *linux_etc = "/etc/teddycloud";
        if (fsDirExists(linux_usrlocaletc))
        {
            free(base_path);
            base_path = strdup(linux_usrlocaletc);
        }
        else if (fsDirExists(linux_etc))
        {
            free(base_path);
            base_path = strdup(linux_etc);
        }
    }

    error = settings_init(cwd, base_path); // TODO: dynamicly read from cli
    free(base_path);
    free(cwd);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("settings_init() failed with error code %d\r\n", error);
        TRACE_ERROR("Make sure the config path exists and is writable\r\n");
        return -1;
    }
    toniebox_state_init();
    platform_init();

    cJSON_Hooks hooks = {.malloc_fn = osAllocMem, .free_fn = osFreeMem};
    cJSON_InitHooks(&hooks);

    /* load certificates and TLS RNG */
    if (tls_adapter_init() != NO_ERROR)
    {
        TRACE_ERROR("tls_adapter_init() failed\r\n");
        return -1;
    }

    if (argc > 1)
    {
        const char *type = argv[1];

        if (!strcasecmp(type, "GENERIC"))
        {
            TRACE_WARNING("**********************************\r\n");
            TRACE_WARNING("***       Generic URL test     ***\r\n");
            TRACE_WARNING("**********************************\r\n");

            char *request = NULL;
            uint8_t *hash = NULL;

            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s GENERIC <url> [hash]\r\n", argv[0]);
                return -1;
            }
            if (argc > 2)
            {
                request = argv[2];
                TRACE_WARNING("Request URL: %s\r\n", request);
            }
            if (argc > 3)
            {
                hash = (uint8_t *)argv[3];
                TRACE_WARNING("Hash: %s\r\n", hash);
            }

            char *hostname;
            uint16_t port;
            char *uri;
            Protocol protocol;

            if (!parse_url(request, &hostname, &port, &uri, &protocol))
            {
                return ERROR_FAILURE;
            }

            TRACE_WARNING("Hostname: %s\n", hostname);
            TRACE_WARNING("Port: %u\n", port);
            TRACE_WARNING("URI: %s\n", uri);
            TRACE_WARNING("Protocol: %s\n", protocol == PROT_HTTP ? "HTTP" : "HTTPS");

            settings_set_bool("cloud.enabled", true);

            error = cloud_request(hostname, port, protocol == PROT_HTTPS, uri, "", "GET", NULL, 0, hash, NULL);

            free(hostname);
            free(uri);
        }
        else if (!strcasecmp(type, "SERVER_CERTS"))
        {
            cert_generate_default();
        }
        else if (!strcasecmp(type, "CLOUD"))
        {
            TRACE_WARNING("**********************************\r\n");
            TRACE_WARNING("***       Cloud API test       ***\r\n");
            TRACE_WARNING("**********************************\r\n");

            char *request = NULL;
            uint8_t *hash = NULL;

            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s CLOUD <request> [hash]\r\n", argv[0]);
                return -1;
            }
            if (argc > 2)
            {
                request = argv[2];
                TRACE_WARNING("Request URI: %s\r\n", request);
            }
            if (argc > 3)
            {
                hash = (uint8_t *)argv[3];
                TRACE_WARNING("Hash: %s\r\n", hash);
            }

            TRACE_WARNING("\r\n");

            error = cloud_request_get(NULL, 0, request, "", hash, NULL);
        }
        else if (!strcasecmp(type, "CERTGEN"))
        {
            /* sanity checks */
            if (argc != 4)
            {
                TRACE_ERROR("Usage: %s CERTGEN <mac_address> <target-dir>\r\n", argv[0]);
                return -1;
            }
            const char *mac = argv[2];
            const char *dest = argv[3];

            if (osStrlen(mac) != 12)
            {
                TRACE_ERROR("MAC address must be in format 001122334455\r\n");
                return -1;
            }
            if (!fsDirExists(dest))
            {
                TRACE_ERROR("Destination directory must exist\r\n");
                return -1;
            }

            cert_generate_mac(mac, dest);
        }
        else if (!strcasecmp(type, "ESP32CERT"))
        {
            if (argc < 5)
            {
                TRACE_ERROR("Usage: %s ESP32CERT (extract/inject) <esp32-image-bin> <source/target-dir>\r\n", argv[0]);
                return -1;
            }
            const char *cmd = argv[2];
            if (!strcasecmp(cmd, "inject"))
            {
                esp32_fat_inject((const char *)argv[3], "CERT", (const char *)argv[4]);
            }
            else if (!strcasecmp(cmd, "extract"))
            {
                esp32_fat_extract((const char *)argv[3], "CERT", (const char *)argv[4]);
            }
        }
        else if (!strcasecmp(type, "ESP32FIXUP"))
        {
            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s ESP32FIXUP <esp32-image-bin>\r\n", argv[0]);
                return -1;
            }
            esp32_fixup((const char *)argv[2], true);
        }
        else if (!strcasecmp(type, "ESP32HOST"))
        {
            char *oldrtnl = "rtnl.bxcl.de";
            char *oldapi = "prod.de.tbs.toys";

            if (argc < 4 || argc > 6)
            {
                TRACE_ERROR("Usage: %s ESP32HOST <esp32-image-bin> <hostname> [oldrtnlhost] [oldapihost]\r\n", argv[0]);
                return -1;
            }
            if (argc == 5)
            {
                oldrtnl = argv[4];
                oldapi = argv[4];
            }
            if (argc == 6)
            {
                oldrtnl = argv[4];
                oldapi = argv[5];
            }
            esp32_patch_host((const char *)argv[2], (const char *)argv[3], oldrtnl, oldapi);
        }
#ifdef FFMPEG_DECODING
        else if (!strcasecmp(type, "ENCODE"))
        {
            if (argc != 4 && argc != 5)
            {
                TRACE_ERROR("Usage: %s ENCODE <source> <taf_file> [skip_secondes]\r\n", argv[0]);
                return -1;
            }
            char *source = argv[2];
            char *taf_file = argv[3];
            size_t skip_seconds = 0;
            if (argc == 5)
            {
                skip_seconds = atoi(argv[4]);
            }

            ffmpeg_convert(source, taf_file, skip_seconds);

            return 1;
        }
#endif
        else if (!strcasecmp(type, "ENCODE_TEST"))
        {
            toniefile_t *taf = toniefile_create("test2.ogg", 0xDEAFBEEF);

            if (!taf)
            {
                TRACE_ERROR("toniefile_create() failed\r\n");
                return -1;
            }

#define SAMPLES 333333
            int sample_total = 0;
            int16_t *sample_buffer = osAllocMem(2 * SAMPLES * sizeof(int16_t));

            osMemset(sample_buffer, 0x00, sizeof(2 * SAMPLES * sizeof(int16_t)));

            for (int pos = 0; pos < 100; pos++)
            {
                for (int sample = 0; sample < SAMPLES; sample++)
                {
                    sample_buffer[2 * sample + 0] = 8192 * sinf(sample_total / 10.0f * (1 + sinf(sample_total / 100000.0f)));
                    sample_buffer[2 * sample + 1] = 8192 * sinf(sample_total / 20.0f * (1 + sinf(sample_total / 30000.0f)));
                    sample_total++;
                }
                if (toniefile_encode(taf, sample_buffer, SAMPLES) != NO_ERROR)
                {
                    break;
                }

                toniefile_new_chapter(taf);
            }
            toniefile_close(taf);

            return 1;
        }
        else if (!strcasecmp(type, "DOCKER_TEST"))
        {
            printf("Docker container started teddyCloud for testing, running smoke test.\r\n");
            mqtt_init();
            server_init(true);
        }
        else
        {
            TRACE_ERROR("Bad argument provided: %s\r\n", argv[1]);
            print_usage(argv);
            return -1;
        }
    }
    else
    {
        mqtt_init();
        server_init(false);
    }

    tls_adapter_deinit();
    platform_deinit();
    settings_deinit_all();

    return error;
}

static char *get_cwd(char *buffer, size_t size)
{
#ifdef _WIN32
    return _getcwd(buffer, size);
#else
    return getcwd(buffer, size);
#endif
}

static void print_usage(char *argv[])
{
    printf(
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  ENCODE <source> <taf_file> [skip_secondes]\r\n"
        "  GENERIC <url> [hash]                Generic URL test.\r\n"
        "  SERVER_CERTS                        Generates Server Certs.\r\n"
        "  CLOUD <request> [hash]              Cloud API test.\r\n"
        "  CERTGEN <mac_address> <target_dir>  Generate client certs\r\n"
        "  ESP32CERT (extract/inject) <esp32-image-bin> <source/target-dir>\r\n"
        "  ESP32FIXUP <esp32-image-bin>\r\n"
        "  ESP32HOST <esp32-image-bin> <hostname> [oldrtnlhost] [oldapihost]   Patch hostname\r\n"
        "  ENCODE_TEST                         Runs an encoding test\r\n"
        "  DOCKER_TEST                         Runs a test to ensure the docker image is fine\r\n",
        argv[0]);
}
