
// Platform-specific dependencies
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <getopt.h>

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
#include "fs_ext.h"

#define COUNT(x) (sizeof(x) / sizeof((x)[0]))

/* helper to make switch/case life easier */
#define OPT_SIMPLE_STR(c, elem)                                      \
    case c:                                                          \
        printf("[options] specified '" #elem "' as '%s'\n", optarg); \
        options.elem = optarg;                                       \
        break
#define OPT_SIMPLE_INT(c, elem)                                      \
    case c:                                                          \
        printf("[options] specified '" #elem "' as '%s'\n", optarg); \
        options.elem = atoi(optarg);                                 \
        break
#define OPT_SIMPLE_NON(c, elem)                      \
    case c:                                          \
        printf("[options] specified '" #elem "'\n"); \
        options.elem = 1;                            \
        break

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

void main_init_settings(const char *cwd, const char *base_path)
{
    int_t error = 0;
    /* try to find base path */
    bool settings_initialized = false;

    const char *base_path_resolved;
    if (osStrcmp(".", base_path) == 0)
    {
        base_path_resolved = cwd;
    }
    else
    {
        base_path_resolved = base_path;
    }

    const char *base_paths[] = {
        base_path_resolved
#ifndef _WIN32
        ,
        "/usr/local/etc/teddycloud",
        "/usr/local/lib/teddycloud",
        "/usr/etc/teddycloud",
        "/usr/lib/teddycloud",
        "/etc/teddycloud",
        "/opt/teddycloud"
#endif
    };

    for (int pos = 0; pos < COUNT(base_paths); pos++)
    {
        const char *path = base_paths[pos];

        if (fsDirExists(path) || (fsDirExists(".") && path[0] == '\0'))
        {
            error = settings_init(cwd, path);
            if (error == NO_ERROR)
            {
                settings_initialized = true;
                break;
            }
        }
    }

    if (!settings_initialized)
    {
        if (error == NO_ERROR)
        {
            TRACE_ERROR("ERROR: settings_init() could not find the config file\r\n");
            TRACE_ERROR("ERROR: Tried paths in this order:\r\n");
            for (int pos = 0; pos < COUNT(base_paths); pos++)
            {
                const char *path = base_paths[pos];

                TRACE_ERROR("ERROR:   - '%s': %s\r\n", path, fsDirExists(path) ? "FOUND" : "NOT FOUND");
            }
        }
        else
        {
            TRACE_ERROR("ERROR: settings_init() failed with error code %d\r\n", error);
            TRACE_ERROR("ERROR: Make sure the config path exists and is writable\r\n");
        }
        exit(-1);
    }
}

void tls_init(void)
{
    // TODO: Move settings_try_load_certs_id call to here, so that the initialization is done only when tls is used.
    /* load certificates and TLS RNG */
    if (tls_adapter_init() != NO_ERROR)
    {
        TRACE_ERROR("tls_adapter_init() failed\r\n");
        exit(-1);
    }
}

void cbr_header(void *ctx, HttpClientContext *cloud_ctx, const char *header, const char *value)
{
    if (header)
    {
        printf("%s:%s\n", header, value);
    }
}

int_t main(int argc, char *argv[])
{
    char cwd[PATH_LEN] = {0};

    get_settings()->log.level = TRACE_LEVEL_WARNING;

    TRACE_PRINTF(BUILD_FULL_NAME_LONG "\r\n\r\n");

    if (get_cwd(cwd, PATH_LEN) == NULL)
    {
        TRACE_ERROR("ERROR: Failed to resolve current working dir.\r\n");
        return -1;
    }

    struct
    {
        const char *base_path;
        const char *source;
        char multisource[99][PATH_LEN];
        size_t multisource_size;
        const char *destination;
        int generate_server_certs;
        const char *generate_client_cert;
        const char *encode;
        const char *encode_test;
        int skip_seconds;
        const char *esp32_hostpatch;
        const char *esp32_fixup;
        const char *esp32_inject;
        const char *esp32_extract;
        int docker_test;
        const char *url_test;
        const char *cloud_test;
        const char *hash;
        const char *hostname;
        const char *oldrtnlhost;
        const char *oldapihost;
    } options = {0};

    options.base_path = BASE_PATH;
    options.multisource_size = 0;

    do
    {
        static struct option long_options[] =
            {
                {"base_path", required_argument, 0, 'b'},
                {"source", required_argument, 0, 's'},
                {"destination", required_argument, 0, 'd'},
                {"generate-server-certs", no_argument, 0, 'g'},
                {"generate-client-cert", required_argument, 0, 'c'},
                {"encode", required_argument, 0, 'e'},
                {"encode_test", required_argument, 0, 'E'},
                {"skip-seconds", required_argument, 0, 'S'},
                {"esp32-hostpatch", required_argument, 0, 'P'},
                {"oldrtnlhost", required_argument, 0, 0x100},
                {"oldapihost", required_argument, 0, 0x101},
                {"esp32-fixup", required_argument, 0, 'F'},
                {"esp32-inject", required_argument, 0, 'I'},
                {"esp32-extract", required_argument, 0, 'X'},
                {"docker-test", no_argument, 0, 'D'},
                {"url-test", required_argument, 0, 'U'},
                {"cloud-test", required_argument, 0, 'C'},
                {"hash", required_argument, 0, 'H'},
                {"hostname", required_argument, 0, 'h'},
                {"help", no_argument, 0, '?'},
                {0, 0, 0, 0}};

        /* getopt_long stores the option index here. */
        int option_index = 0;
        int c = getopt_long(argc, argv, "b:s:d:gc:e:E:S:P:F:I:X:DU:C:H:h:?", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        case 0:
            break;

            OPT_SIMPLE_STR('b', base_path);
            OPT_SIMPLE_STR('s', source);
            OPT_SIMPLE_STR('d', destination);
            OPT_SIMPLE_NON('g', generate_server_certs);
            OPT_SIMPLE_STR('c', generate_client_cert);
            OPT_SIMPLE_STR('e', encode);
            OPT_SIMPLE_STR('E', encode_test);
            OPT_SIMPLE_INT('S', skip_seconds);
            OPT_SIMPLE_STR('P', esp32_hostpatch);
            OPT_SIMPLE_STR('F', esp32_fixup);
            OPT_SIMPLE_STR('I', esp32_inject);
            OPT_SIMPLE_STR('X', esp32_extract);
            OPT_SIMPLE_NON('D', docker_test);
            OPT_SIMPLE_STR('U', url_test);
            OPT_SIMPLE_STR('C', cloud_test);
            OPT_SIMPLE_STR('H', hash);
            OPT_SIMPLE_STR('h', hostname);
            OPT_SIMPLE_STR(0x100, oldrtnlhost);
            OPT_SIMPLE_STR(0x101, oldapihost);

        case '?':
            print_usage(argv);
            exit(-1);

        default:
            print_usage(argv);
            exit(-1);
        }
    } while (true);

    /* by default autogenerate certificates */
    bool autogen = true;

    /* for these operation modes, we do not need autogenerated certs */
    autogen &= !options.encode;
    autogen &= !options.encode_test;
    autogen &= !options.esp32_hostpatch;
    autogen &= !options.esp32_fixup;
    autogen &= !options.esp32_inject;
    autogen &= !options.esp32_extract;
    autogen &= !options.docker_test;

    /* ok now load settings, autogenerate certs if needed */
    get_settings()->internal.autogen_certs = autogen;
    main_init_settings(cwd, options.base_path);

    toniebox_state_init();
    platform_init();

    cJSON_Hooks hooks = {.malloc_fn = osAllocMem, .free_fn = osFreeMem};
    cJSON_InitHooks(&hooks);

    /* check if user specified some command */
    if (options.generate_client_cert)
    {
        if (!options.destination)
        {
            TRACE_ERROR("Missing --destination\r\n");
            exit(-1);
        }

        if (osStrlen(options.generate_client_cert) != 12)
        {
            TRACE_ERROR("MAC address must be in format 001122334455\r\n");
            exit(-1);
        }
        if (!fsDirExists(options.destination))
        {
            TRACE_ERROR("Destination directory must exist\r\n");
            exit(-1);
        }

        int_t error = cert_generate_mac(options.generate_client_cert, options.destination);
        exit(error);
    }

    if (options.generate_server_certs)
    {
        int_t error = cert_generate_default();
        exit(error);
    }

    if (options.encode)
    {
        options.multisource_size = argc - optind;

        if (options.multisource_size == 0)
        {
            TRACE_ERROR("Missing source files\r\n");
            exit(-1);
        }
        else if (options.multisource_size > 99)
        {
            TRACE_ERROR("Not more than 99 source files allowed!\r\n");
            exit(-1);
        }

        for (size_t i = 0; i < options.multisource_size; i++)
        {
            strncpy(options.multisource[i], argv[optind + i], PATH_LEN - 1);
        }

#if !defined(FFMPEG_DECODING)
        TRACE_ERROR("Feature not available in your build.\r\n");
#else
        TRACE_WARNING("Encode %" PRIuSIZE " files to '%s'\r\n", options.multisource_size, options.encode);
        int_t error = ffmpeg_convert(options.multisource, options.multisource_size, options.encode, options.skip_seconds);
        exit(error);
#endif
    }

    if (options.esp32_hostpatch)
    {
        const char *oldrtnl = "rtnl.bxcl.de";
        const char *oldapi = "prod.de.tbs.toys";

        if (!options.hostname)
        {
            TRACE_ERROR("Missing --hostname\r\n");
            exit(-1);
        }
        if (options.oldrtnlhost)
        {
            oldrtnl = options.oldrtnlhost;
        }
        if (options.oldapihost)
        {
            oldapi = options.oldapihost;
        }

        int_t error = esp32_patch_host(options.esp32_hostpatch, options.hostname, oldrtnl, oldapi);
        if (error == 0)
        {
            error = esp32_fixup(options.esp32_hostpatch, true);
        }
        exit(error);
    }

    if (options.esp32_fixup)
    {
        int_t error = esp32_fixup(options.esp32_fixup, true);
        exit(error);
    }

    if (options.esp32_inject)
    {
        if (!options.source)
        {
            TRACE_ERROR("Missing --source\r\n");
            exit(-1);
        }
        int_t error = esp32_fat_inject(options.esp32_inject, "CERT", options.source);
        exit(error);
    }

    if (options.esp32_extract)
    {
        if (!options.destination)
        {
            TRACE_ERROR("Missing --destination\r\n");
            exit(-1);
        }
        int_t error = esp32_fat_extract(options.esp32_extract, "CERT", options.destination);
        exit(error);
    }

    if (options.url_test)
    {
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("***       Generic URL test     ***\r\n");
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("Request URL: %s\r\n", options.url_test);
        if (options.hash)
        {
            TRACE_WARNING("Hash: %s\r\n", options.hash);
        }
        tls_init();

        char *hostname;
        uint16_t port;
        char *uri;
        Protocol protocol;

        if (!parse_url(options.url_test, &hostname, &port, &uri, &protocol))
        {
            exit(EXIT_FAILURE);
        }

        TRACE_WARNING("Hostname: %s\n", hostname);
        TRACE_WARNING("Port: %u\n", port);
        TRACE_WARNING("URI: %s\n", uri);
        TRACE_WARNING("Protocol: %s\n", protocol == PROT_HTTP ? "HTTP" : "HTTPS");

        settings_set_bool("cloud.enabled", true);

        /* it's getting a bit complicated now */
        client_ctx_t client_ctx = {
            .settings = get_settings()};
        cbr_ctx_t ctx = {
            .client_ctx = &client_ctx};
        req_cbr_t cbr = {
            .ctx = &ctx,
            .header = &cbr_header};

        int_t error = cloud_request(hostname, port, protocol == PROT_HTTPS, uri, "", "GET", NULL, 0, (uint8_t *)options.hash, &cbr);

        free(hostname);
        free(uri);
        exit(error);
    }

    if (options.cloud_test)
    {
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("***       Cloud API test       ***\r\n");
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("Request URL: %s\r\n", options.cloud_test);
        if (options.hash)
        {
            TRACE_WARNING("Hash: %s\r\n", options.hash);
        }

        TRACE_WARNING("\r\n");
        tls_init();

        int_t error = cloud_request_get(NULL, 0, options.cloud_test, "", (uint8_t *)options.hash, NULL);
        exit(error);
    }

    if (options.encode_test)
    {
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("***       Encode test          ***\r\n");
        TRACE_WARNING("**********************************\r\n");
        TRACE_WARNING("File: %s\r\n", options.encode_test);

        toniefile_t *taf = toniefile_create(options.encode_test, 0xDEAFBEEF);

        if (!taf)
        {
            TRACE_ERROR("toniefile_create() failed\r\n");
            exit(-1);
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

        exit(1);
    }

    tls_init();

    mqtt_init();
    server_init(options.docker_test);

    tls_adapter_deinit();
    platform_deinit();
    settings_deinit_all();

    return 0;
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

        "Options:\r\n"
        "\r\n"
        "  --base_path <DIR>\r\n"
        "    Root directory of TeddyCloud data files. Default: '" BASE_PATH "'\r\n"
        "\r\n"
        "Commandline operations:\r\n"
        "\r\n"
        "  --generate-client-cert <MAC>\r\n"
        "    Generate a client certificate. Specify the MAC address in the format '001122334455'.\r\n"
        "    Requires: --destination <DIR> to specify where the encoded file will be saved.\r\n"
        "\r\n"
        "  --generate-server-certs\r\n"
        "    Generate default server certificates.\r\n"
        "\r\n"
        "  --encode <TARGET-FILE> (--skip-seconds <SECONDS>) <SOURCE1> (<SOURCE2>...)\r\n"
#if !defined(FFMPEG_DECODING)
        "    Encode a specified file. <NOT ENABLED IN YOUR BUILD>\r\n"
#else
        "    Encode one or more files.\r\n"
        "    Requires: <SOURCEn> to specify the source file(s). Can be anything ffmpeg can decode (urls).\r\n"
        "    Optional: --skip-seconds <SECONDS> to skip a specified number of seconds at the start of the encoding.\r\n"
#endif
        "\r\n"
        "  --esp32-hostpatch <FILE>\r\n"
        "    Patch hosts in ESP32 image and does a fixup of the image afterwards.\r\n"
        "    Requires: --hostname <NEWHOST> to specify the new host.\r\n"
        "    Optional: --oldrtnlhost <HOST> and --oldapihost <HOST> to specify old hosts to be replaced.\r\n"
        "\r\n"
        "  --esp32-fixup <FILE>\r\n"
        "    Perform a checksum fixup operation on an ESP32 image.\r\n"
        "\r\n"
        "  --esp32-extract <FILE>\r\n"
        "    Extract certificates from an ESP32 image.\r\n"
        "    Requires: --destination <DIR> to specify where the extracted files will be saved.\r\n"
        "\r\n"
        "  --esp32-inject <FILE>\r\n"
        "    Inject certrificates into an ESP32 image.\r\n"
        "    Requires: --source <DIR> to specify the source directory for injection\r\n"
        "\r\n"
        "Testing options:\r\n"
        "\r\n"
        "  --url-test <URL>\r\n"
        "    Perform a generic URL test. Outputs details like hostname, port, URI, and protocol and tries to connect.\r\n"
        "    Optional: --hash <HASH> to specify a hash value used in the test.\r\n"
        "\r\n"
        "  --cloud-test <REQUEST>\r\n"
        "    Perform a cloud API invocation with the specified request.\r\n"
        "    Optional: --hash <HASH> to specify a hash value used in the test.\r\n"
        "\r\n"
        "  --encode-test <FILE>\r\n"
        "    Perform an internal encoding test on the specified file.\r\n"
        "\r\n",

        argv[0]);
}
