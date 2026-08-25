#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "core/net.h"
#include "core/socket.h"
#include "error.h"
#include "debug.h"
#include "settings.h"
#include "mqtt_server.h"
#include "tls.h"
#include "rand.h"
#include "tls_adapter.h"
#include "cJSON.h"
#include "handler.h"
#include "toniebox_state.h"

// Forward declaration of platform-specific function
uint_t tcpWaitForEvents(Socket *socket, uint_t eventMask, systime_t timeout);

#define MQTT_MAX_PACKET_SIZE 4096
#define MQTT_MAX_CONNECTIONS 32
#define MQTT_MAX_SUBSCRIPTIONS 32

typedef struct {
    char topic[256];
    uint8_t qos;
} MqttSubscription;

typedef struct {
    Socket *socket;
    TlsContext *tlsContext;
    bool active;
    uint8_t buffer[MQTT_MAX_PACKET_SIZE];
    size_t buffer_len;
    client_ctx_t client_ctx;
    MqttSubscription subscriptions[MQTT_MAX_SUBSCRIPTIONS];
    size_t subscription_count;
} MqttClientConnection;

typedef enum {
    MQTT_MSG_ANY = 0,
    MQTT_MSG_CONNECT = 0x10,
    MQTT_MSG_PUBLISH = 0x30,
    MQTT_MSG_SUBSCRIBE = 0x80,
    MQTT_MSG_PINGREQ = 0xC0,
    MQTT_MSG_DISCONNECT = 0xE0
} MqttMessageType;

typedef struct {
    MqttMessageType type;
    const char *topic;
    error_t (*handler)(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len);
} MqttHandlerEntry;

static Socket *serverSocket = NULL;
static MqttClientConnection connections[MQTT_MAX_CONNECTIONS];

static bool mqtt_topic_match(const char *filter, const char *topic)
{
    while (*filter && *topic)
    {
        if (*filter == '+')
        {
            filter++;
            while (*topic && *topic != '/')
            {
                topic++;
            }
        }
        else if (*filter == '#')
        {
            return true;
        }
        else if (*filter == *topic)
        {
            filter++;
            topic++;
        }
        else
        {
            return false;
        }
    }
    
    if (*filter == '\0' && *topic == '\0')
    {
        return true;
    }
    if (*filter == '#' && *(filter + 1) == '\0')
    {
        return true;
    }
    if (*filter == '/' && *(filter + 1) == '#' && *(filter + 2) == '\0' && *topic == '\0')
    {
        return true;
    }
    return false;
}

static void mqtt_connection_update_context(MqttClientConnection *conn, const char *topic)
{
    if (strncmp(topic, "toniebox/", 9) == 0)
    {
        const char *mac_start = topic + 9;
        const char *mac_end = strchr(mac_start, '/');
        if (mac_end != NULL)
        {
            size_t mac_len = mac_end - mac_start;
            if (mac_len > 0 && mac_len < 32)
            {
                char mac[32];
                memcpy(mac, mac_start, mac_len);
                mac[mac_len] = '\0';

                if (get_overlay_id(mac) > 0)
                {
                    settings_t *box_settings = get_settings_cn(mac);
                    if (box_settings != NULL && box_settings->internal.config_used)
                    {
                        conn->client_ctx.settings = box_settings;
                        conn->client_ctx.settingsNoOverlay = box_settings;
                        conn->client_ctx.state = get_toniebox_state_id(box_settings->internal.overlayNumber);
                        conn->client_ctx.state->box.id = conn->client_ctx.settings->commonName;
                        conn->client_ctx.state->box.name = conn->client_ctx.settings->boxName;
                    }
                }
            }
        }
    }
}

static char_t *mqtt_server_cert = NULL;
static size_t mqtt_server_cert_len = 0;
static char_t *mqtt_server_key = NULL;
static size_t mqtt_server_key_len = 0;

static char_t *mqtt_server_read_file(const char_t *filename, size_t *length)
{
    *length = 0;
    uint32_t fileSize = 0;
    error_t error = fsGetFileSize(filename, &fileSize);
    if (error != NO_ERROR)
        return NULL;

    char_t *buffer = osAllocMem(fileSize + 1);
    if (buffer == NULL)
        return NULL;

    FsFile *fp = fsOpenFile(filename, FS_FILE_MODE_READ);
    if (fp == NULL)
    {
        osFreeMem(buffer);
        return NULL;
    }

    size_t read = 0;
    error = fsReadFile(fp, buffer, fileSize, &read);
    fsCloseFile(fp);

    if (error != NO_ERROR || read != fileSize)
    {
        osFreeMem(buffer);
        return NULL;
    }

    buffer[fileSize] = '\0';
    *length = fileSize;
    return buffer;
}

error_t mqtt_server_tls_init(TlsContext *tlsContext)
{
    error_t error;

    error = tlsSetConnectionEnd(tlsContext, TLS_CONNECTION_END_SERVER);
    if (error)
        return error;

    error = tlsSetBufferSize(tlsContext, TLS_TX_BUFFER_SIZE, TLS_RX_BUFFER_SIZE);
    if (error)
        return error;

    error = tlsSetPrng(tlsContext, rand_get_algo(), rand_get_context());
    if (error)
        return error;

    error = tlsSetCache(tlsContext, tlsCache);
    if (error)
        return error;

    error = tlsEnableSecureRenegotiation(tlsContext, TRUE);
    if (error)
        return error;

    error = tlsSetClientAuthMode(tlsContext, TLS_CLIENT_AUTH_OPTIONAL);
    if (error)
        return error;

    if (mqtt_server_cert && mqtt_server_key)
    {
        error = tlsLoadCertificate(tlsContext, 0, mqtt_server_cert, mqtt_server_cert_len, mqtt_server_key, mqtt_server_key_len, NULL);
    }
    else
    {
        TRACE_ERROR("Certificates not loaded\r\n");
        error = ERROR_FAILURE;
    }

    return error;
}

void mqtt_server_init() {
    settings_t *settings = get_settings();
    if (!settings->mqtt_server.enabled) return;

    TRACE_INFO("Initializing on port %u\r\n", settings->mqtt_server.port);

    // Load certificates once
    char *cert_path = osAllocMem(256);
    char *key_path = osAllocMem(256);

    settings_resolve_dir(&cert_path, settings->mqtt_server.cert_crt, settings->internal.basedirfull);
    settings_resolve_dir(&key_path, settings->mqtt_server.cert_key, settings->internal.basedirfull);

    mqtt_server_cert = mqtt_server_read_file(cert_path, &mqtt_server_cert_len);
    mqtt_server_key = mqtt_server_read_file(key_path, &mqtt_server_key_len);

    if (!mqtt_server_cert || !mqtt_server_key)
    {
        TRACE_ERROR("Failed to load certificates (cert: %s, key: %s)\r\n", cert_path, key_path);
    }

    osFreeMem(cert_path);
    osFreeMem(key_path);

    serverSocket = socketOpen(SOCKET_TYPE_STREAM, SOCKET_IP_PROTO_TCP);
    if (serverSocket == NULL) {
        TRACE_ERROR("Failed to open socket\r\n");
        return;
    }

    socketSetTimeout(serverSocket, 0); // Non-blocking

    error_t error = socketBind(serverSocket, &IP_ADDR_ANY, settings->mqtt_server.port);
    if (error != NO_ERROR) {
        TRACE_ERROR("Failed to bind socket (port %u)\r\n", settings->mqtt_server.port);
        socketClose(serverSocket);
        serverSocket = NULL;
        return;
    }

    error = socketListen(serverSocket, 5);
    if (error != NO_ERROR) {
        TRACE_ERROR("Failed to listen on socket\r\n");
        socketClose(serverSocket);
        serverSocket = NULL;
        return;
    }

    osMemset(connections, 0, sizeof(connections));
}

static const char *settings_json = "{\n"
"  \"settings_history\": {\n"
"    \"bi_tracking\": 0,\n"
"    \"max_headphone_volume\": 0,\n"
"    \"battery_threshold\": 0,\n"
"    \"scrubbing_enabled\": 0,\n"
"    \"fleet_obs_enabled\": 0,\n"
"    \"bedtime_max_headphone_volume\": 0,\n"
"    \"timezone_transitions\": 0,\n"
"    \"log_level\": 0,\n"
"    \"timezone\": 0,\n"
"    \"bedtime_lightring_color\": 0,\n"
"    \"bedtime_max_volume\": 0,\n"
"    \"skipping_direction\": 0,\n"
"    \"max_volume\": 1773690866874,\n"
"    \"bedtime_schedules\": 0,\n"
"    \"alarms\": 0,\n"
"    \"bedtime_lightring_brightness\": 1773690530304,\n"
"    \"age_mode\": 1773690456997,\n"
"    \"skipping_enabled\": 0,\n"
"    \"lightring_brightness\": 1773306190892\n"
"  },\n"
"  \"settings_applied\": false,\n"
"  \"bi_tracking\": true,\n"
"  \"max_headphone_volume\": 100,\n"
"  \"battery_threshold\": 1,\n"
"  \"scrubbing_enabled\": false,\n"
"  \"fleet_obs_enabled\": true,\n"
"  \"bedtime_max_headphone_volume\": 75,\n"
"  \"timezone_transitions\": [\n"
"    {\n"
"      \"time\": 0,\n"
"      \"offset\": 0\n"
"    }\n"
"  ],\n"
"  \"log_level\": \"info\",\n"
"  \"timezone\": null,\n"
"  \"bedtime_lightring_color\": \"#ffffff\",\n"
"  \"bedtime_max_volume\": 75,\n"
"  \"skipping_direction\": \"right\",\n"
"  \"max_volume\": 100,\n"
"  \"bedtime_schedules\": [],\n"
"  \"alarms\": [],\n"
"  \"bedtime_lightring_brightness\": 75,\n"
"  \"age_mode\": \"3+\",\n"
"  \"skipping_enabled\": true,\n"
"  \"lightring_brightness\": 100\n"
"}";

static bool mqtt_connection_has_sub(MqttClientConnection *conn, const char *topic)
{
    if (conn == NULL || !conn->active)
        return false;
    for (size_t i = 0; i < conn->subscription_count; i++)
    {
        if (mqtt_topic_match(conn->subscriptions[i].topic, topic))
        {
            return true;
        }
    }
    return false;
}

static void mqtt_connection_publish(MqttClientConnection *conn, const char *topic, const char *payload)
{
    if (conn == NULL || !conn->active) return;

    size_t topic_len = strlen(topic);
    size_t payload_len = strlen(payload);
    size_t remaining_len = 2 + topic_len + payload_len;

    // Allocate memory for the packet
    size_t header_len = 1; // 0x30
    uint8_t length_bytes[4];
    size_t length_count = 0;
    size_t temp_len = remaining_len;
    do {
        uint8_t encoded_byte = temp_len % 128;
        temp_len /= 128;
        if (temp_len > 0) {
            encoded_byte |= 128;
        }
        length_bytes[length_count++] = encoded_byte;
    } while (temp_len > 0);

    size_t packet_size = header_len + length_count + remaining_len;
    uint8_t *packet = osAllocMem(packet_size);
    if (packet == NULL)
    {
        TRACE_ERROR("Failed to allocate memory for MQTT PUBLISH packet\r\n");
        return;
    }

    size_t p = 0;
    packet[p++] = 0x30; // PUBLISH (QoS 0)
    
    memcpy(&packet[p], length_bytes, length_count);
    p += length_count;

    packet[p++] = (topic_len >> 8) & 0xFF;
    packet[p++] = topic_len & 0xFF;

    memcpy(&packet[p], topic, topic_len);
    p += topic_len;

    memcpy(&packet[p], payload, payload_len);
    p += payload_len;

    size_t written = 0;
    if (conn->tlsContext)
    {
        tlsWrite(conn->tlsContext, packet, packet_size, &written, 0);
    }
    else
    {
        socketSend(conn->socket, packet, packet_size, &written, 0);
    }

    TRACE_INFO("MQTT PUBLISH: %s -> %s (len %zu)\r\n", topic, payload, payload_len);

    osFreeMem(packet);
}

static void mqtt_server_publish(client_ctx_t *client_ctx, const char *topic, const char *payload)
{
    if (client_ctx != NULL)
    {
        if (client_ctx->mqtt_connection != NULL)
        {
            MqttClientConnection *conn = (MqttClientConnection *)client_ctx->mqtt_connection;
            if (conn->active)
            {
                mqtt_connection_publish(conn, topic, payload);
            }
        }
        else
        {
            TRACE_WARNING("mqtt_server_publish: client_ctx->mqtt_connection is NULL, doing nothing\r\n");
        }
    }
    else
    {
        // Publish to all clients that have a sub
        for (size_t i = 0; i < MQTT_MAX_CONNECTIONS; i++)
        {
            MqttClientConnection *conn = &connections[i];
            if (conn->active && mqtt_connection_has_sub(conn, topic))
            {
                mqtt_connection_publish(conn, topic, payload);
            }
        }
    }
}

static void mqtt_connection_update_context_from_cert(MqttClientConnection *conn)
{
    if (conn->tlsContext != NULL && osStrlen(conn->tlsContext->client_cert_subject) > 0)
    {
        char_t *subject = conn->tlsContext->client_cert_subject;
        char_t *issuer = conn->tlsContext->client_cert_issuer;

        if (osStrstr(issuer, "Boxine Factory SubCA") != NULL || osStrstr(issuer, "Toniebox SubCA") != NULL
            || osStrstr(issuer, "TeddyCloud") != NULL || osStrstr(subject, "TeddyCloud") != NULL || osStrstr(issuer, "Toniebox Root CA") != NULL)
        {
            char_t *commonName = NULL;
            if (osStrlen(subject) == 15 && !osStrncmp(subject, "b'", 2) && subject[14] == '\'') // tonies standard cn with b'[MAC]'
            {
                commonName = strdup(&subject[2]);
                commonName[osStrlen(commonName) - 1] = '\0';
            } else if (osStrlen(subject) == 12) {
                commonName = strdup(subject);
            }

            if (commonName != NULL) {
                settings_t *box_settings = get_settings_cn(commonName);
                if (box_settings != NULL && box_settings->internal.config_used)
                {
                    conn->client_ctx.settings = box_settings;
                    conn->client_ctx.settingsNoOverlay = box_settings;
                    conn->client_ctx.state = get_toniebox_state_id(box_settings->internal.overlayNumber);
                    conn->client_ctx.state->box.id = conn->client_ctx.settings->commonName;
                    conn->client_ctx.state->box.name = conn->client_ctx.settings->boxName;
                }
                osFreeMem(commonName);
            }
        }
    }
}

static error_t handle_mqtt_connect(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    mqtt_connection_update_context_from_cert(conn);
    TRACE_INFO("MQTT: connection established for %s\r\n", conn->client_ctx.settings->commonName);
    
    uint8_t connack[] = {0x20, 0x02, 0x00, 0x00};
    size_t written = 0;
    if (conn->tlsContext)
        return tlsWrite(conn->tlsContext, connack, sizeof(connack), &written, 0);
    else
        return socketSend(conn->socket, connack, sizeof(connack), &written, 0);
}

static error_t handle_mqtt_pingreq(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    TRACE_INFO("PINGREQ received\r\n");
    uint8_t pingresp[] = {0xD0, 0x00};
    size_t written = 0;
    if (conn->tlsContext)
        return tlsWrite(conn->tlsContext, pingresp, sizeof(pingresp), &written, 0);
    else
        return socketSend(conn->socket, pingresp, sizeof(pingresp), &written, 0);
}

static error_t handle_mqtt_disconnect(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    TRACE_INFO("DISCONNECT received\r\n");
    if (conn->tlsContext)
        tlsFree(conn->tlsContext);
    socketClose(conn->socket);
    conn->active = false;
    conn->tlsContext = NULL;
    conn->socket = NULL;
    conn->buffer_len = 0;
    conn->subscription_count = 0;
    return NO_ERROR;
}

static error_t handle_mqtt_subscribe(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    TRACE_INFO("SUBSCRIBE received\r\n");
    if (payload_len < 2)
        return ERROR_INVALID_LENGTH;

    size_t p = 0;
    uint16_t packet_id = (payload[p] << 8) | payload[p + 1];
    p += 2;

    while (p < payload_len)
    {
        if (p + 2 > payload_len)
            break;
        size_t topic_len = (payload[p] << 8) | payload[p + 1];
        p += 2;

        if (p + topic_len > payload_len)
            break;

        char sub_topic[256];
        size_t copy_len = topic_len < sizeof(sub_topic) - 1 ? topic_len : sizeof(sub_topic) - 1;
        memcpy(sub_topic, &payload[p], copy_len);
        sub_topic[copy_len] = '\0';
        p += topic_len;

        if (p >= payload_len)
            break;
        uint8_t qos = payload[p++];
        TRACE_INFO("  Topic='%s', QoS=%u\r\n", sub_topic, qos);

        mqtt_connection_update_context(conn, sub_topic);

        // Store subscription on connection
        bool sub_found = false;
        for (size_t s = 0; s < conn->subscription_count; s++)
        {
            if (strcmp(conn->subscriptions[s].topic, sub_topic) == 0)
            {
                conn->subscriptions[s].qos = qos;
                sub_found = true;
                break;
            }
        }
        if (!sub_found && conn->subscription_count < MQTT_MAX_SUBSCRIPTIONS)
        {
            osStrncpy(conn->subscriptions[conn->subscription_count].topic, sub_topic, sizeof(conn->subscriptions[conn->subscription_count].topic) - 1);
            conn->subscriptions[conn->subscription_count].topic[sizeof(conn->subscriptions[conn->subscription_count].topic) - 1] = '\0';
            conn->subscriptions[conn->subscription_count].qos = qos;
            conn->subscription_count++;
        }

        // Check if this is the fresh-tonies topic subscription
        bool is_fresh_tonies_sub = false;
        char mac[32] = {0};
        if (strncmp(sub_topic, "toniebox/", 9) == 0 && topic_len > 22)
        {
            const char *suffix = "/fresh-tonies";
            size_t suffix_len = strlen(suffix);
            if (strcmp(sub_topic + topic_len - suffix_len, suffix) == 0)
            {
                size_t mac_len = topic_len - 9 - suffix_len;
                if (mac_len < sizeof(mac))
                {
                    memcpy(mac, sub_topic + 9, mac_len);
                    mac[mac_len] = '\0';
                    is_fresh_tonies_sub = true;
                }
            }
        }

        if (is_fresh_tonies_sub)
        {
            settings_t *box_settings = get_settings_cn(mac);
            if (box_settings != NULL && box_settings->internal.config_used)
            {
                mqtt_server_publish_fresh_tonies(&conn->client_ctx);
            }
        }
    }

    // Responding with SUBACK (0x90)
    uint8_t suback[] = {0x90, 0x03, (uint8_t)(packet_id >> 8), (uint8_t)(packet_id & 0xFF), 0x00};
    size_t written = 0;
    if (conn->tlsContext)
        return tlsWrite(conn->tlsContext, suback, sizeof(suback), &written, 0);
    else
        return socketSend(conn->socket, suback, sizeof(suback), &written, 0);
}

static error_t handle_mqtt_publish_logs(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    char payload_str[256];
    size_t copy_len = payload_len < sizeof(payload_str) - 1 ? payload_len : sizeof(payload_str) - 1;
    memcpy(payload_str, payload, copy_len);
    payload_str[copy_len] = '\0';

    TRACE_DEBUG("PUBLISH topic='%s', payload='%s' (QoS 0, len %zu)\r\n", topic, payload_str, payload_len);
    return NO_ERROR;
}

static error_t handle_mqtt_publish_settings_request(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    char mac[32] = {0};
    size_t topic_len = strlen(topic);
    const char *suffix = "/settings/request";
    size_t suffix_len = strlen(suffix);
    size_t mac_len = topic_len - 9 - suffix_len;
    if (mac_len < sizeof(mac))
    {
        memcpy(mac, topic + 9, mac_len);
        mac[mac_len] = '\0';
    }

    char response_topic[128];
    TRACE_INFO("Settings request from mac=%s\r\n", mac);
    osSnprintf(response_topic, sizeof(response_topic), "toniebox/%s/settings/desired", mac);
    mqtt_connection_publish(conn, response_topic, settings_json);
    return NO_ERROR;
}

static error_t handle_mqtt_publish_generic(MqttClientConnection *conn, MqttMessageType type, const char *topic, const uint8_t *payload, size_t payload_len)
{
    char payload_str[256];
    size_t copy_len = payload_len < sizeof(payload_str) - 1 ? payload_len : sizeof(payload_str) - 1;
    memcpy(payload_str, payload, copy_len);
    payload_str[copy_len] = '\0';

    TRACE_INFO("PUBLISH topic='%s', payload='%s' (QoS 0, len %zu)\r\n", topic, payload_str, payload_len);
    return NO_ERROR;
}

static const MqttHandlerEntry mqtt_handlers[] = {
    {MQTT_MSG_CONNECT, NULL, &handle_mqtt_connect},
    {MQTT_MSG_PINGREQ, NULL, &handle_mqtt_pingreq},
    {MQTT_MSG_SUBSCRIBE, NULL, &handle_mqtt_subscribe},
    {MQTT_MSG_DISCONNECT, NULL, &handle_mqtt_disconnect},
    {MQTT_MSG_PUBLISH, "toniebox/+/logs", &handle_mqtt_publish_logs},
    {MQTT_MSG_PUBLISH, "toniebox/+/settings/request", &handle_mqtt_publish_settings_request},
    {MQTT_MSG_PUBLISH, NULL, &handle_mqtt_publish_generic}
};

void mqtt_server_task()
{
    if (serverSocket == NULL)
        return;

    // 1. Process active connections
    for (size_t i = 0; i < MQTT_MAX_CONNECTIONS; i++)
    {
        MqttClientConnection *conn = &connections[i];
        if (conn->active)
        {
            size_t received = 0;
            error_t error = NO_ERROR;

            // Non-blocking check for data
            if (tcpWaitForEvents(conn->socket, SOCKET_EVENT_RX_READY, 0) & SOCKET_EVENT_RX_READY)
            {
                if (conn->tlsContext)
                {
                    error = tlsRead(conn->tlsContext, conn->buffer + conn->buffer_len, MQTT_MAX_PACKET_SIZE - conn->buffer_len, &received, 0);
                }
                else
                {
                    error = socketReceive(conn->socket, conn->buffer + conn->buffer_len, MQTT_MAX_PACKET_SIZE - conn->buffer_len, &received, 0);
                }

                if (error == NO_ERROR && received > 0)
                {
                    conn->buffer_len += received;
                    size_t processed_total = 0;

                    while (processed_total + 2 <= conn->buffer_len)
                    {
                        uint8_t *pkt = &conn->buffer[processed_total];
                        size_t remaining_len = 0;
                        size_t multiplier = 1;
                        size_t pos = 1;
                        uint8_t digit;
                        bool rem_len_complete = false;

                        do
                        {
                            if (processed_total + pos >= conn->buffer_len) break;
                            digit = pkt[pos++];
                            remaining_len += (digit & 127) * multiplier;
                            multiplier *= 128;
                            if ((digit & 128) == 0) rem_len_complete = true;
                        } while (!rem_len_complete && pos < 5);

                        if (!rem_len_complete) break; // Need more bytes for remaining_len

                        size_t packet_size = pos + remaining_len;
                        if (processed_total + packet_size > conn->buffer_len) break; // Incomplete packet

                        // Process full packet using the pointer-based routing system
                        uint8_t cmd_raw = pkt[0];
                        uint8_t cmd = cmd_raw & 0xF0;

                        if (cmd == 0x30) // PUBLISH
                        {
                            uint8_t flags = cmd_raw & 0x0F;
                            uint8_t qos = (flags >> 1) & 0x03;
                            size_t p = pos;

                            size_t topic_len = (pkt[p] << 8) | pkt[p + 1];
                            p += 2;
                            char topic[256];
                            size_t copy_len = topic_len < sizeof(topic) - 1 ? topic_len : sizeof(topic) - 1;
                            memcpy(topic, &pkt[p], copy_len);
                            topic[copy_len] = '\0';
                            p += topic_len;

                            uint16_t packet_id = 0;
                            if (qos > 0)
                            {
                                packet_id = (pkt[p] << 8) | pkt[p + 1];
                                p += 2;
                            }

                            size_t payload_len = remaining_len - (p - pos);
                            const uint8_t *payload = pkt + p;

                            mqtt_connection_update_context(conn, topic);

                            // Find matching handler for this PUBLISH topic
                            bool handled = false;
                            for (size_t h = 0; h < sizeof(mqtt_handlers) / sizeof(mqtt_handlers[0]); h++)
                            {
                                if (mqtt_handlers[h].type == MQTT_MSG_PUBLISH)
                                {
                                    if (mqtt_handlers[h].topic == NULL || mqtt_topic_match(mqtt_handlers[h].topic, topic))
                                    {
                                        mqtt_handlers[h].handler(conn, MQTT_MSG_PUBLISH, topic, payload, payload_len);
                                        handled = true;
                                        break;
                                    }
                                }
                            }

                            if (!handled)
                            {
                                TRACE_WARNING("No handler matched for PUBLISH topic='%s'\r\n", topic);
                            }

                            if (qos == 1)
                            {
                                uint8_t puback[] = {0x40, 0x02, (uint8_t)(packet_id >> 8), (uint8_t)(packet_id & 0xFF)};
                                size_t written = 0;
                                if (conn->tlsContext)
                                    tlsWrite(conn->tlsContext, puback, sizeof(puback), &written, 0);
                                else
                                    socketSend(conn->socket, puback, sizeof(puback), &written, 0);
                            }
                        }
                        else
                        {
                            // Route non-PUBLISH commands (CONNECT, SUBSCRIBE, PINGREQ, DISCONNECT)
                            bool handled = false;
                            for (size_t h = 0; h < sizeof(mqtt_handlers) / sizeof(mqtt_handlers[0]); h++)
                            {
                                if (mqtt_handlers[h].type == (MqttMessageType)cmd)
                                {
                                    mqtt_handlers[h].handler(conn, (MqttMessageType)cmd, NULL, pkt + pos, remaining_len);
                                    handled = true;
                                    break;
                                }
                            }

                            if (!handled)
                            {
                                TRACE_INFO("Unknown or unhandled command 0x%02X received (%zu bytes total)\r\n", cmd_raw, packet_size);
                            }

                            if (cmd == 0xE0) // DISCONNECT
                            {
                                break; // Exit this connection's packet processing loop
                            }
                        }

                        processed_total += packet_size;
                    }

                    if (processed_total > 0 && conn->active)
                    {
                        conn->buffer_len -= processed_total;
                        if (conn->buffer_len > 0)
                        {
                            memmove(conn->buffer, &conn->buffer[processed_total], conn->buffer_len);
                        }
                    }
                }
                else if (error != ERROR_WOULD_BLOCK && error != NO_ERROR && error != ERROR_TIMEOUT)
                {
                    TRACE_INFO("Connection closed (error: %s)\r\n", error2text(error));
                    if (conn->tlsContext)
                    {
                        tlsFree(conn->tlsContext);
                    }
                    socketClose(conn->socket);
                    conn->active = false;
                    conn->tlsContext = NULL;
                    conn->socket = NULL;
                    conn->buffer_len = 0;
                    conn->subscription_count = 0;
                }
            }
        }
    }

    // 2. Non-blocking check for new connections
    if (tcpWaitForEvents(serverSocket, SOCKET_EVENT_ACCEPT, 0) & SOCKET_EVENT_ACCEPT)
    {
        IpAddr clientIpAddr;
        uint16_t clientPort;
        Socket *clientSocket = socketAccept(serverSocket, &clientIpAddr, &clientPort);
        if (clientSocket != NULL)
        {
            TRACE_INFO("Accepted connection from %s:%u\r\n", ipAddrToString(&clientIpAddr, NULL), clientPort);

            MqttClientConnection *conn = NULL;
            for (size_t i = 0; i < MQTT_MAX_CONNECTIONS; i++)
            {
                if (!connections[i].active)
                {
                    conn = &connections[i];
                    break;
                }
            }

            if (conn != NULL)
            {
                osMemset(conn, 0, sizeof(MqttClientConnection));
                conn->socket = clientSocket;
                conn->active = true;
                conn->buffer_len = 0;
                conn->subscription_count = 0;
                socketSetTimeout(conn->socket, 0);

                conn->client_ctx.settings = get_settings();
                conn->client_ctx.settingsNoOverlay = conn->client_ctx.settings;
                conn->client_ctx.state = get_toniebox_state();
                conn->client_ctx.mqtt_connection = conn;

                conn->tlsContext = tlsInit();
                if (conn->tlsContext != NULL)
                {
                    if (mqtt_server_tls_init(conn->tlsContext) == NO_ERROR)
                    {
                        tlsSetSocket(conn->tlsContext, conn->socket);
                    }
                    else
                    {
                        TRACE_ERROR("TLS init failed\r\n");
                        tlsFree(conn->tlsContext);
                        conn->tlsContext = NULL;
                    }
                }
            }
            else
            {
                TRACE_WARNING("No free MQTT connection slots, closing connection\r\n");
                socketClose(clientSocket);
            }
        }
    }
}

void mqtt_server_deinit() {
    if (serverSocket != NULL) {
        socketClose(serverSocket);
        serverSocket = NULL;
    }
    for (size_t i = 0; i < MQTT_MAX_CONNECTIONS; i++)
    {
        if (connections[i].active)
        {
            if (connections[i].tlsContext)
                tlsFree(connections[i].tlsContext);
            socketClose(connections[i].socket);
            connections[i].active = false;
            connections[i].tlsContext = NULL;
            connections[i].socket = NULL;
            connections[i].buffer_len = 0;
            connections[i].subscription_count = 0;
        }
    }

    if (mqtt_server_cert)
    {
        osFreeMem(mqtt_server_cert);
        mqtt_server_cert = NULL;
    }
    if (mqtt_server_key)
    {
        osFreeMem(mqtt_server_key);
        mqtt_server_key = NULL;
    }
}

void mqtt_server_publish_fresh_tonies(client_ctx_t *client_ctx)
{
    if (client_ctx == NULL || client_ctx->state == NULL || client_ctx->settings == NULL || client_ctx->mqtt_connection == NULL)
    {
        return;
    }

    if (!client_ctx->settings->internal.freshnessCacheChanged)
    {
        return;
    }

    settings_set_bool_id("internal.freshnessCacheChanged", false, client_ctx->settings->internal.overlayNumber);

    size_t freshnessCacheLen = 0;
    uint64_t *freshnessCache = settings_get_u64_array_id("internal.freshnessCache", client_ctx->settings->internal.overlayNumber, &freshnessCacheLen);

    for (size_t i = 0; i < freshnessCacheLen; i++)
    {
        char ruidStr[17];
        char uidStr[17];
        osSnprintf(uidStr, sizeof(uidStr), "%016" PRIX64, freshnessCache[i]);
        for (int j = 0; j < 8; j++)
        {
            ruidStr[j * 2] = uidStr[14 - j * 2];
            ruidStr[j * 2 + 1] = uidStr[15 - j * 2];
        }
        ruidStr[16] = '\0';

        cJSON *obj = cJSON_CreateObject();
        if (obj != NULL)
        {
            cJSON_AddStringToObject(obj, "tonie", ruidStr);
            char *payload = cJSON_PrintUnformatted(obj);
            cJSON_Delete(obj);

            if (payload != NULL)
            {
                char topic[128];
                osSnprintf(topic, sizeof(topic), "toniebox/%s/fresh-tonies", client_ctx->state->box.id);
                mqtt_server_publish(client_ctx, topic, payload);
                osFreeMem(payload);
            }
        }
    }
}
