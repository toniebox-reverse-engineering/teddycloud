#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "handler_web_auth.h"
#include "cJSON.h"
#include "debug.h"
#include "fs_ext.h"
#include "fs_port.h"
#include "handler_api.h"
#include "hash/sha256.h"
#include "os_port.h"
#include "rand.h"
#include "server_helpers.h"
#include "settings.h"

#define MAX_WEB_USERS 32
#define MAX_WEB_SESSIONS 64
#define SESSION_TTL_SECONDS (7 * 24 * 60 * 60)
#define USERNAME_MAX 32
#define PASSWORD_MIN 4
#define PASSWORD_MAX 128
#define SALT_BYTES 16
#define TOKEN_BYTES 32
#define LOGIN_FAIL_LIMIT 5
#define LOGIN_LOCK_SECONDS 600
#define LOGIN_BUCKETS 32
#define LOGIN_IP_MAX 48

typedef struct
{
    char username[USERNAME_MAX + 1];
    char salt_hex[(SALT_BYTES * 2) + 1];
    char hash_hex[(SHA256_DIGEST_SIZE * 2) + 1];
} web_user_t;

typedef struct
{
    bool used;
    char token_hex[(TOKEN_BYTES * 2) + 1];
    char username[USERNAME_MAX + 1];
    time_t expires;
} web_session_t;

typedef struct
{
    bool used;
    char ip[LOGIN_IP_MAX];
    int failures;
    time_t locked_until;
} login_limit_t;

static web_user_t users[MAX_WEB_USERS];
static int user_count = 0;
static web_session_t sessions[MAX_WEB_SESSIONS];
static login_limit_t login_limits[LOGIN_BUCKETS];
static OsMutex web_auth_mutex;
static bool mutex_ready = false;
static bool initialized = false;

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    size_t n = 0;
    if (dst == NULL || dst_size == 0)
    {
        return;
    }
    if (src != NULL)
    {
        n = osStrlen(src);
        if (n >= dst_size)
        {
            n = dst_size - 1;
        }
        osMemcpy(dst, src, n);
    }
    dst[n] = '\0';
}

static void lock_auth(void)
{
    if (mutex_ready)
    {
        osAcquireMutex(&web_auth_mutex);
    }
}

static void unlock_auth(void)
{
    if (mutex_ready)
    {
        osReleaseMutex(&web_auth_mutex);
    }
}

static const char *env_override_value(void)
{
    return getenv("TEDDYCLOUD_WEB_AUTH_DISABLE");
}

bool web_auth_env_override(void)
{
    const char *value = env_override_value();
    if (value == NULL || value[0] == '\0')
    {
        return false;
    }
    return osStrcasecmp(value, "1") == 0 || osStrcasecmp(value, "true") == 0 || osStrcasecmp(value, "yes") == 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < len && o + 2 < out_size; i++)
    {
        out[o++] = hex[bytes[i] >> 4];
        out[o++] = hex[bytes[i] & 0x0F];
    }
    out[o] = '\0';
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = osStrlen(hex);
    if (hex_len != out_len * 2)
    {
        return false;
    }
    for (size_t i = 0; i < out_len; i++)
    {
        unsigned int value = 0;
        if (sscanf(hex + (i * 2), "%2x", &value) != 1)
        {
            return false;
        }
        out[i] = (uint8_t)value;
    }
    return true;
}

static bool const_time_equal(const char *a, const char *b)
{
    size_t la = osStrlen(a);
    size_t lb = osStrlen(b);
    size_t n = la < lb ? la : lb;
    unsigned diff = (unsigned)(la ^ lb);
    for (size_t i = 0; i < n; i++)
    {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

static bool valid_username(const char *username)
{
    size_t len = osStrlen(username);
    if (len < 1 || len > USERNAME_MAX)
    {
        return false;
    }
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)username[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
        {
            return false;
        }
    }
    return true;
}

static char *users_path(void)
{
    const char *dir = settings_get_string("internal.configdirfull");
    if (dir == NULL || dir[0] == '\0')
    {
        return NULL;
    }
    return custom_asprintf("%s%c%s", dir, PATH_SEPARATOR, WEB_USERS_JSON_FILE);
}

static void hash_password(const char *password, const uint8_t *salt, char *hash_hex, size_t hash_hex_size)
{
    Sha256Context ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256Init(&ctx);
    sha256Update(&ctx, salt, SALT_BYTES);
    sha256Update(&ctx, password, osStrlen(password));
    sha256Final(&ctx, digest);
    bytes_to_hex(digest, sizeof(digest), hash_hex, hash_hex_size);
}

static web_user_t *find_user_unlocked(const char *username)
{
    for (int i = 0; i < user_count; i++)
    {
        if (osStrcasecmp(users[i].username, username) == 0)
        {
            return &users[i];
        }
    }
    return NULL;
}

static bool verify_password_unlocked(const web_user_t *user, const char *password)
{
    uint8_t salt[SALT_BYTES];
    if (!hex_to_bytes(user->salt_hex, salt, sizeof(salt)))
    {
        return false;
    }
    char hash_hex[(SHA256_DIGEST_SIZE * 2) + 1];
    hash_password(password, salt, hash_hex, sizeof(hash_hex));
    return const_time_equal(user->hash_hex, hash_hex);
}

static bool save_users_unlocked(void)
{
    char *path = users_path();
    if (path == NULL)
    {
        return false;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(root, "users");
    for (int i = 0; i < user_count; i++)
    {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "username", users[i].username);
        cJSON_AddStringToObject(entry, "salt", users[i].salt_hex);
        cJSON_AddStringToObject(entry, "hash", users[i].hash_hex);
        cJSON_AddItemToArray(array, entry);
    }
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    bool ok = false;
    if (body != NULL)
    {
        FsFile *file = fsOpenFile(path, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
        if (file != NULL)
        {
            ok = (fsWriteFile(file, body, osStrlen(body)) == NO_ERROR);
            fsCloseFile(file);
        }
        osFreeMem(body);
    }
    osFreeMem(path);
    return ok;
}

static void load_users_unlocked(void)
{
    user_count = 0;
    osMemset(users, 0, sizeof(users));
    char *path = users_path();
    if (path == NULL)
    {
        return;
    }
    uint32_t length = 0;
    if (fsGetFileSize(path, &length) != NO_ERROR || length == 0 || length > (64 * 1024))
    {
        osFreeMem(path);
        return;
    }
    char *buf = osAllocMem(length + 1);
    if (buf == NULL)
    {
        osFreeMem(path);
        return;
    }
    FsFile *file = fsOpenFile(path, FS_FILE_MODE_READ);
    osFreeMem(path);
    if (file == NULL)
    {
        osFreeMem(buf);
        return;
    }
    size_t n = 0;
    if (fsReadFile(file, buf, length, &n) != NO_ERROR)
    {
        fsCloseFile(file);
        osFreeMem(buf);
        return;
    }
    fsCloseFile(file);
    buf[n] = '\0';
    cJSON *root = cJSON_Parse(buf);
    osFreeMem(buf);
    if (root == NULL)
    {
        return;
    }
    cJSON *array = cJSON_GetObjectItemCaseSensitive(root, "users");
    if (cJSON_IsArray(array))
    {
        cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, array)
        {
            if (user_count >= MAX_WEB_USERS)
            {
                break;
            }
            cJSON *username = cJSON_GetObjectItemCaseSensitive(entry, "username");
            cJSON *salt = cJSON_GetObjectItemCaseSensitive(entry, "salt");
            cJSON *hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
            if (!cJSON_IsString(username) || !cJSON_IsString(salt) || !cJSON_IsString(hash))
            {
                continue;
            }
            copy_str(users[user_count].username, sizeof(users[user_count].username), username->valuestring);
            copy_str(users[user_count].salt_hex, sizeof(users[user_count].salt_hex), salt->valuestring);
            copy_str(users[user_count].hash_hex, sizeof(users[user_count].hash_hex), hash->valuestring);
            user_count++;
        }
    }
    cJSON_Delete(root);
}

static void purge_sessions_unlocked(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (sessions[i].used && sessions[i].expires < now)
        {
            sessions[i].used = false;
        }
    }
}

static bool create_session_unlocked(const char *username, char *token, size_t token_size)
{
    uint8_t bytes[TOKEN_BYTES];
    if (rand_get_bytes(bytes, sizeof(bytes)) != 0)
    {
        return false;
    }
    purge_sessions_unlocked();
    int slot = -1;
    time_t oldest = 0;
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (!sessions[i].used)
        {
            slot = i;
            break;
        }
        if (slot < 0 || sessions[i].expires < oldest)
        {
            slot = i;
            oldest = sessions[i].expires;
        }
    }
    if (slot < 0)
    {
        slot = 0;
    }
    bytes_to_hex(bytes, sizeof(bytes), sessions[slot].token_hex, sizeof(sessions[slot].token_hex));
    copy_str(sessions[slot].username, sizeof(sessions[slot].username), username);
    sessions[slot].expires = time(NULL) + SESSION_TTL_SECONDS;
    sessions[slot].used = true;
    copy_str(token, token_size, sessions[slot].token_hex);
    return true;
}

static bool session_user_unlocked(const char *token, char *username, size_t username_size)
{
    if (token == NULL || token[0] == '\0')
    {
        return false;
    }
    purge_sessions_unlocked();
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (sessions[i].used && const_time_equal(sessions[i].token_hex, token))
        {
            if (username != NULL && username_size > 0)
            {
                copy_str(username, username_size, sessions[i].username);
            }
            return true;
        }
    }
    return false;
}

static void extract_cookie_token(const char *cookie, char *out, size_t out_size)
{
    out[0] = '\0';
#if (HTTP_SERVER_COOKIE_SUPPORT == ENABLED)
    if (cookie == NULL || cookie[0] == '\0')
    {
        return;
    }
    const char *found = osStrstr(cookie, WEB_SESSION_COOKIE "=");
    if (found == NULL)
    {
        return;
    }
    found += osStrlen(WEB_SESSION_COOKIE "=");
    size_t i = 0;
    while (found[i] && found[i] != ';' && found[i] != ' ' && i + 1 < out_size)
    {
        out[i] = found[i];
        i++;
    }
    out[i] = '\0';
#else
    (void)cookie;
    (void)out_size;
#endif
}

static void set_session_cookie(HttpConnection *connection, const char *token, bool clear)
{
#if (HTTP_SERVER_COOKIE_SUPPORT == ENABLED)
    if (clear || token == NULL || token[0] == '\0')
    {
        osSnprintf(connection->response.setCookie, HTTP_SERVER_COOKIE_MAX_LEN,
                   "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s",
                   WEB_SESSION_COOKIE,
                   connection->tlsContext ? "; Secure" : "");
        return;
    }
    osSnprintf(connection->response.setCookie, HTTP_SERVER_COOKIE_MAX_LEN,
               "%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s",
               WEB_SESSION_COOKIE,
               token,
               SESSION_TTL_SECONDS,
               connection->tlsContext ? "; Secure" : "");
#else
    (void)connection;
    (void)token;
    (void)clear;
#endif
}

static error_t send_json_status(HttpConnection *connection, uint_t status, cJSON *json, const char *token, bool clear_cookie)
{
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (body == NULL)
    {
        return ERROR_FAILURE;
    }
    httpPrepareHeader(connection, "application/json; charset=utf-8", osStrlen(body));
    connection->response.statusCode = status;
    if (token != NULL || clear_cookie)
    {
        set_session_cookie(connection, token, clear_cookie);
    }
    return httpWriteResponseString(connection, body, true);
}

static error_t send_message(HttpConnection *connection, uint_t status, const char *error, const char *message)
{
    cJSON *json = cJSON_CreateObject();
    if (error)
    {
        cJSON_AddStringToObject(json, "error", error);
    }
    if (message)
    {
        cJSON_AddStringToObject(json, "message", message);
    }
    return send_json_status(connection, status, json, NULL, false);
}

static error_t read_json_body(HttpConnection *connection, cJSON **outJson)
{
    if (connection->request.byteCount == 0 || connection->request.byteCount > (64 * 1024))
    {
        return ERROR_INVALID_LENGTH;
    }
    size_t bodySize = connection->request.byteCount;
    char *postData = osAllocMem(bodySize + 1);
    if (postData == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    osMemset(postData, 0, bodySize + 1);
    size_t totalRead = 0;
    while (totalRead < bodySize)
    {
        size_t chunkRead = 0;
        error_t error = httpReadStream(connection, postData + totalRead, bodySize - totalRead, &chunkRead, 0x00);
        if (error != NO_ERROR)
        {
            osFreeMem(postData);
            return error;
        }
        if (chunkRead == 0)
        {
            break;
        }
        totalRead += chunkRead;
    }
    postData[totalRead] = '\0';
    *outJson = cJSON_Parse(postData);
    osFreeMem(postData);
    if (*outJson == NULL)
    {
        return ERROR_INVALID_SYNTAX;
    }
    return NO_ERROR;
}

static bool json_string(cJSON *obj, const char *key, char *out, size_t out_size)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL)
    {
        return false;
    }
    if (osStrlen(item->valuestring) >= out_size)
    {
        return false;
    }
    osStrcpy(out, item->valuestring);
    return true;
}

static void client_ip(HttpConnection *connection, char *out, size_t out_size)
{
    out[0] = '\0';
    if (connection == NULL || connection->socket == NULL || out_size == 0)
    {
        return;
    }
    const char *ip = ipAddrToString(&connection->socket->remoteIpAddr, NULL);
    if (ip != NULL)
    {
        copy_str(out, out_size, ip);
    }
}

static login_limit_t *find_login_limit_unlocked(const char *ip, bool create)
{
    if (ip == NULL || ip[0] == '\0')
    {
        return NULL;
    }
    int empty = -1;
    for (int i = 0; i < LOGIN_BUCKETS; i++)
    {
        if (login_limits[i].used && !osStrcmp(login_limits[i].ip, ip))
        {
            return &login_limits[i];
        }
        if (!login_limits[i].used && empty < 0)
        {
            empty = i;
        }
    }
    if (!create)
    {
        return NULL;
    }
    int idx = empty >= 0 ? empty : 0;
    osMemset(&login_limits[idx], 0, sizeof(login_limits[idx]));
    login_limits[idx].used = true;
    copy_str(login_limits[idx].ip, sizeof(login_limits[idx].ip), ip);
    return &login_limits[idx];
}

static bool login_is_locked_unlocked(const char *ip)
{
    login_limit_t *bucket = find_login_limit_unlocked(ip, false);
    if (bucket == NULL)
    {
        return false;
    }
    time_t now = time(NULL);
    if (bucket->locked_until != 0 && now >= bucket->locked_until)
    {
        bucket->failures = 0;
        bucket->locked_until = 0;
        return false;
    }
    return bucket->locked_until != 0 && now < bucket->locked_until;
}

static void login_register_failure_unlocked(const char *ip)
{
    login_limit_t *bucket = find_login_limit_unlocked(ip, true);
    if (bucket == NULL)
    {
        return;
    }
    time_t now = time(NULL);
    if (bucket->locked_until != 0 && now >= bucket->locked_until)
    {
        bucket->failures = 0;
        bucket->locked_until = 0;
    }
    bucket->failures++;
    if (bucket->failures >= LOGIN_FAIL_LIMIT)
    {
        bucket->locked_until = now + LOGIN_LOCK_SECONDS;
        TRACE_WARNING("Web UI login locked for %s after %d failures\r\n", ip, bucket->failures);
    }
}

static void login_register_success_unlocked(const char *ip)
{
    login_limit_t *bucket = find_login_limit_unlocked(ip, false);
    if (bucket != NULL)
    {
        bucket->used = false;
    }
}

static bool add_user_unlocked(const char *username, const char *password)
{
    if (user_count >= MAX_WEB_USERS || !valid_username(username) || osStrlen(password) < PASSWORD_MIN || osStrlen(password) > PASSWORD_MAX)
    {
        return false;
    }
    if (find_user_unlocked(username) != NULL)
    {
        return false;
    }
    uint8_t salt[SALT_BYTES];
    if (rand_get_bytes(salt, sizeof(salt)) != 0)
    {
        return false;
    }
    copy_str(users[user_count].username, sizeof(users[user_count].username), username);
    bytes_to_hex(salt, sizeof(salt), users[user_count].salt_hex, sizeof(users[user_count].salt_hex));
    hash_password(password, salt, users[user_count].hash_hex, sizeof(users[user_count].hash_hex));
    user_count++;
    return save_users_unlocked();
}

void web_auth_init(void)
{
    if (osCreateMutex(&web_auth_mutex))
    {
        mutex_ready = true;
    }
    lock_auth();
    osMemset(sessions, 0, sizeof(sessions));
    osMemset(login_limits, 0, sizeof(login_limits));
    load_users_unlocked();
    initialized = true;
    unlock_auth();
    TRACE_INFO("Web UI auth loaded %d user(s), enabled=%s, envOverride=%s\r\n",
               user_count,
               settings_get_bool("frontend.web_auth_enabled") ? "true" : "false",
               web_auth_env_override() ? "true" : "false");
}

bool web_auth_requires_login(void)
{
    if (web_auth_env_override())
    {
        return false;
    }
    if (!settings_get_bool("frontend.web_auth_enabled"))
    {
        return false;
    }
    lock_auth();
    if (!initialized)
    {
        load_users_unlocked();
        initialized = true;
    }
    int count = user_count;
    unlock_auth();
    return count > 0;
}

bool web_auth_is_public_request(const char_t *uri, const char_t *method)
{
    (void)method;
    if (uri == NULL)
    {
        return false;
    }
    if (!osStrcmp(uri, "/api/auth/login") || !osStrcmp(uri, "/api/auth/status") || !osStrcmp(uri, "/api/auth/logout") || !osStrcmp(uri, "/api/auth/refresh-token"))
    {
        return true;
    }
    /* Login page is part of the SPA and must load before the session exists.
     * The HTTP parser rewrites "/" to the default document "index.shtm" (without leading slash). */
    if (!osStrcmp(uri, "/") || !osStrcmp(uri, "index.shtm") || !osStrcmp(uri, "/index.shtm") || !osStrcmp(uri, "/favicon.ico"))
    {
        return true;
    }
    if (!osStrncmp(uri, "/web", 4) && (uri[4] == '\0' || uri[4] == '/'))
    {
        return true;
    }
    return false;
}

bool web_auth_is_authenticated(HttpConnection *connection, char *username, size_t username_size)
{
    char token[WEB_BEARER_TOKEN_MAX + 1];
    token[0] = '\0';
    if (connection->private.web_bearer_token[0] != '\0')
    {
        copy_str(token, sizeof(token), connection->private.web_bearer_token);
    }
#if (HTTP_SERVER_COOKIE_SUPPORT == ENABLED)
    if (token[0] == '\0')
    {
        extract_cookie_token(connection->request.cookie, token, sizeof(token));
    }
#endif
    lock_auth();
    bool ok = session_user_unlocked(token, username, username_size);
    unlock_auth();
    return ok;
}

error_t web_auth_unauthorized(HttpConnection *connection)
{
    return send_message(connection, 401, "unauthorized", "Login required");
}

error_t handleApiAuthStatus(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    char username[USERNAME_MAX + 1];
    username[0] = '\0';
    bool logged_in = web_auth_is_authenticated(connection, username, sizeof(username));
    bool env = web_auth_env_override();
    lock_auth();
    int count = user_count;
    unlock_auth();
    bool enabled = !env && settings_get_bool("frontend.web_auth_enabled") && count > 0;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "enabled", enabled);
    cJSON_AddBoolToObject(json, "loggedIn", logged_in && enabled);
    cJSON_AddStringToObject(json, "username", logged_in ? username : "");
    cJSON_AddBoolToObject(json, "envOverride", env);
    cJSON_AddNumberToObject(json, "userCount", count);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthLogin(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    error_t error = read_json_body(connection, &body);
    if (error != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid login payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    if (!json_string(body, "username", username, sizeof(username)) || !json_string(body, "password", password, sizeof(password)))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }
    cJSON_Delete(body);

    char ip[LOGIN_IP_MAX];
    client_ip(connection, ip, sizeof(ip));

    char token[WEB_BEARER_TOKEN_MAX + 1];
    token[0] = '\0';
    bool ok = false;
    bool locked = false;
    lock_auth();
    if (login_is_locked_unlocked(ip))
    {
        locked = true;
    }
    else
    {
        web_user_t *user = find_user_unlocked(username);
        if (user != NULL && verify_password_unlocked(user, password))
        {
            copy_str(username, sizeof(username), user->username);
            ok = create_session_unlocked(username, token, sizeof(token));
            if (ok)
            {
                login_register_success_unlocked(ip);
            }
        }
        else
        {
            login_register_failure_unlocked(ip);
        }
    }
    unlock_auth();
    if (locked)
    {
        return send_message(connection, 429, "rate_limited", "Too many login attempts, try again later");
    }
    if (!ok)
    {
        return send_message(connection, 401, "unauthorized", "Invalid username or password");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    cJSON_AddStringToObject(json, "token", token);
    return send_json_status(connection, 200, json, token, false);
}

error_t handleApiAuthLogout(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    char token[WEB_BEARER_TOKEN_MAX + 1];
    token[0] = '\0';
    if (connection->private.web_bearer_token[0] != '\0')
    {
        copy_str(token, sizeof(token), connection->private.web_bearer_token);
    }
#if (HTTP_SERVER_COOKIE_SUPPORT == ENABLED)
    if (token[0] == '\0')
    {
        extract_cookie_token(connection->request.cookie, token, sizeof(token));
    }
#endif
    lock_auth();
    purge_sessions_unlocked();
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (sessions[i].used && const_time_equal(sessions[i].token_hex, token))
        {
            sessions[i].used = false;
        }
    }
    unlock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    return send_json_status(connection, 200, json, NULL, true);
}

error_t handleApiAuthRefreshToken(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    char username[USERNAME_MAX + 1];
    if (!web_auth_is_authenticated(connection, username, sizeof(username)))
    {
        return send_message(connection, 401, "unauthorized", "Login required");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    lock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(json, "users");
    for (int i = 0; i < user_count; i++)
    {
        cJSON_AddItemToArray(array, cJSON_CreateString(users[i].username));
    }
    int count = user_count;
    unlock_auth();
    bool env = web_auth_env_override();
    cJSON_AddBoolToObject(json, "enabled", !env && settings_get_bool("frontend.web_auth_enabled") && count > 0);
    cJSON_AddBoolToObject(json, "envOverride", env);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersCreate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    if (!json_string(body, "username", username, sizeof(username)) || !json_string(body, "password", password, sizeof(password)))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }
    cJSON_Delete(body);
    if (!valid_username(username) || osStrlen(password) < PASSWORD_MIN)
    {
        return send_message(connection, 400, "invalid_user", "Invalid username or password");
    }
    lock_auth();
    if (find_user_unlocked(username) != NULL)
    {
        unlock_auth();
        return send_message(connection, 409, "exists", "User already exists");
    }
    if (user_count >= MAX_WEB_USERS)
    {
        unlock_auth();
        return send_message(connection, 400, "limit", "Maximum number of users reached");
    }
    bool ok = add_user_unlocked(username, password);
    unlock_auth();
    if (!ok)
    {
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    if (!json_string(body, "username", username, sizeof(username)))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "Username required");
    }
    cJSON_Delete(body);

    bool auth_disabled = false;
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user == NULL)
    {
        unlock_auth();
        return send_message(connection, 404, "not_found", "User not found");
    }
    int index = (int)(user - users);
    for (int i = index; i < user_count - 1; i++)
    {
        users[i] = users[i + 1];
    }
    user_count--;
    osMemset(&users[user_count], 0, sizeof(users[user_count]));
    if (!save_users_unlocked())
    {
        unlock_auth();
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    if (user_count == 0)
    {
        auth_disabled = true;
    }
    unlock_auth();
    if (auth_disabled)
    {
        settings_set_bool("frontend.web_auth_enabled", false);
        settings_save();
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddBoolToObject(json, "authDisabled", auth_disabled);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersPassword(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    if (!json_string(body, "username", username, sizeof(username)) || !json_string(body, "password", password, sizeof(password)))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }
    cJSON_Delete(body);
    if (osStrlen(password) < PASSWORD_MIN)
    {
        return send_message(connection, 400, "invalid_user", "Invalid password");
    }
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user == NULL)
    {
        unlock_auth();
        return send_message(connection, 404, "not_found", "User not found");
    }
    uint8_t salt[SALT_BYTES];
    if (rand_get_bytes(salt, sizeof(salt)) != 0)
    {
        unlock_auth();
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    bytes_to_hex(salt, sizeof(salt), user->salt_hex, sizeof(user->salt_hex));
    hash_password(password, salt, user->hash_hex, sizeof(user->hash_hex));
    bool ok = save_users_unlocked();
    unlock_auth();
    if (!ok)
    {
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthEnabled(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    cJSON *enabled_item = cJSON_GetObjectItemCaseSensitive(body, "enabled");
    if (!cJSON_IsBool(enabled_item))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "enabled required");
    }
    bool enabled = cJSON_IsTrue(enabled_item);
    cJSON_Delete(body);
    if (web_auth_env_override())
    {
        return send_message(connection, 400, "env_override", "Login protection is disabled by TEDDYCLOUD_WEB_AUTH_DISABLE");
    }
    lock_auth();
    int count = user_count;
    unlock_auth();
    if (enabled && count == 0)
    {
        return send_message(connection, 400, "no_users", "Create a user before enabling login protection");
    }
    if (!settings_set_bool("frontend.web_auth_enabled", enabled) || settings_save() != NO_ERROR)
    {
        return send_message(connection, 500, "save_failed", "Could not update login setting");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddBoolToObject(json, "enabled", enabled);
    return send_json_status(connection, 200, json, NULL, false);
}
