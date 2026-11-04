#include "content_download.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "date_time.h"
#include "error_text.h"
#include "fs_ext.h"
#include "mutex_manager.h"
#include "platform.h"
#include "toniebox_state.h"
#include "server_helpers.h"
#include "settings.h"
#include "http/http_client.h"

/* The cloud's answer is published to the readers in steps (and at the end): one flush and one wake-up per step
   instead of per 4 KB read from the cloud. 64 KB keep a reader that caught up with the download at most about
   10 ms behind a cloud sending 6 MB/s; a slow cloud is published at least every CONTENT_DOWNLOAD_PUBLISH_MS. */
#define CONTENT_DOWNLOAD_PUBLISH_STEP (64 * 1024)
#define CONTENT_DOWNLOAD_PUBLISH_MS 250
/* how often a request looks whether a failed download is gone, see contentDownloadJoin */
#define CONTENT_DOWNLOAD_POLL_MS 50
/* how often a request that waits checks its box is still there: one that hung up and asks again would keep a
   connection of the server for as long as the wait, and a few such boxes all of them */
#define CONTENT_DOWNLOAD_ALIVE_MS 1000
/* what is kept of the cloud's header lines and of an answer that is not the content, to give them to every
   request. A box takes about 350 bytes of header (tests/sim/profiles.py) and the cloud's errors are short, the
   bounds only keep a broken answer from taking memory: further header lines and a longer body are dropped. */
#define CONTENT_DOWNLOAD_HEADERS_MAX 2048
#define CONTENT_DOWNLOAD_ANSWER_MAX (16 * 1024)
/* A reader gives up when the download did not move for this many core.server.http_client_timeout (60 s by
   default). The download fails on its own once the cloud is silent for one; a new connection takes a few (name,
   TCP, TLS, header) before data comes. This only bounds the wait for a download that hangs. */
#define CONTENT_DOWNLOAD_STALL_TIMEOUTS 30
/* Checking an answer that ended with the connection reads the whole TAF, at the speed of the drive. That is no
   stall: requests coming in meanwhile wait for it up to this long. 10 min read a TAF of several hundred MB on the
   slowest drives. */
#define CONTENT_DOWNLOAD_FILE_MAX_MS (10 * 60 * 1000)
/* A failed download goes away once its readers have stopped; one in a send to a box that does not read gives up
   after the server's socket timeout. */
#define CONTENT_DOWNLOAD_GONE_MS (HTTP_SERVER_TIMEOUT + 5000)

typedef enum
{
    CONTENT_DOWNLOAD_RUNNING,    /* the cloud's answer is coming in */
    CONTENT_DOWNLOAD_CHECKING,   /* it ended with the connection, the TAF check tells whether it is all there */
    CONTENT_DOWNLOAD_DONE,       /* the cloud's answer is complete: in the .tmp (validated, then copied into the
                                    cache meanwhile), or in answer if it is not a 200 */
    CONTENT_DOWNLOAD_FAILED,     /* no usable answer: readers stop, nobody joins */
    CONTENT_DOWNLOAD_CACHED,     /* path is the cached file, new readers read that one */
} content_download_state_t;

/* A request reading from a download. The OS port's events wake one waiter, so every reader has its own, which the
   download sets whenever it moves (contentDownloadWake). */
typedef struct content_download_reader_s
{
    struct content_download_reader_s *next;
    OsEvent moved;
    systime_t aliveChecked; /* when it last looked whether its box is still there, see contentDownloadWait */
    bool_t onTmp;           /* it reads the .tmp, see tmpReaders */
} content_download_reader_t;

/*
 * One download per content file, owned by its task. It stays registered until the task is done with it, so a
 * request for the same file always finds it and there is never a second writer to the same .tmp.
 *
 * A complete, valid download goes into the cache at once, not when its readers are done: overlapping requests (a
 * slow box, its retries, another box, the web player) would put that off for as long as they keep coming. The .tmp
 * is renamed into the cache (and moved into the library from there) when nobody reads it. Else it stays for the
 * requests reading it: the cached file is a hard link to it, or a copy where there are none or the link would not
 * help (FAT; on Windows a file another handle has open can be neither renamed nor deleted, by any of its names).
 * Readers that have the .tmp finish on it, requests coming in after that read the cached file, and the .tmp is
 * deleted once its last reader is gone.
 */
typedef struct content_download_s
{
    struct content_download_s *next; /* MUTEX_CONTENT_DOWNLOAD */
    OsMutex lock;                    /* the fields from state to idle */
    content_download_state_t state;
    uint32_t statusCode; /* of the cloud's answer, 0 until its header is in */
    char *contentType;   /* the answer's Content-Type, NULL without */
    char *headers;       /* the answer's other header lines the boxes get too, CRLF ended, NULL without */
    size_t length;       /* Content-Length of the cloud's answer, CONTENT_LENGTH_UNKNOWN without */
    bool_t chunked;      /* without Content-Length: chunked, else it ended with the connection */
    uint8_t *answer;     /* the body of an answer that is not a 200, answerLength bytes */
    size_t answerLength;
    size_t written;      /* bytes in the .tmp, flushed: readers read up to here */
    bool_t passThrough;  /* failed here, not at the cloud (the .tmp not writable): requests that have not answered
                            yet pass the request through to the cloud */
    char *path;          /* the file readers open: tmpPath, or contentPath once renamed; once CACHED the cached file */
    uint32_t readers;    /* requests reading from it */
    uint32_t tmpReaders; /* those of them that read the .tmp */
    bool_t uncached;     /* complete but not cached: takes no new readers, see contentDownloadEnd */
    content_download_reader_t *waiting; /* their wake-ups */
    OsEvent idle;        /* set when the last reader, or the last one of the .tmp, is gone */

    /* fixed once registered */
    char *contentPath; /* the cache file in the content directory */
    char *tmpPath;     /* <contentPath>.tmp */
    systime_t stallMs; /* how long its readers wait when it does not move, see CONTENT_DOWNLOAD_STALL_TIMEOUTS */

    /* the cloud request, only used by the task */
    char *uri;
    char *userAgent;
    uint8_t token[TONIE_AUTH_TOKEN_LENGTH];
    char *overlay; /* the requesting box's overlay, its settings are looked up by it, see contentDownloadSettings */
    FsFile *file;
    char *connectionNamed; /* the cloud's Connection header, while its header comes in */
    bool_t contentCoded;   /* the cloud's answer has a Content-Encoding, see contentDownloadHeader */
    size_t unpublished; /* written to the .tmp, not yet flushed and counted in written */
    systime_t published;
} content_download_t;

/* the list, protected by MUTEX_CONTENT_DOWNLOAD; taken before the lock of an entry, never while holding one */
static content_download_t *contentDownloads = NULL;

static void contentDownloadFree(content_download_t *dl)
{
    if (dl->path != dl->tmpPath && dl->path != dl->contentPath)
    {
        osFreeMem(dl->path);
    }
    osDeleteEvent(&dl->idle);
    osDeleteMutex(&dl->lock);
    osFreeMem(dl->contentType);
    osFreeMem(dl->headers);
    osFreeMem(dl->answer);
    osFreeMem(dl->contentPath);
    osFreeMem(dl->tmpPath);
    osFreeMem(dl->uri);
    osFreeMem(dl->userAgent);
    osFreeMem(dl->overlay);
    osFreeMem(dl->connectionNamed);
    osFreeMem(dl);
}

/* Tells the readers the download moved: more data, another state. With the entry's lock. */
static void contentDownloadWake(content_download_t *dl)
{
    for (content_download_reader_t *reader = dl->waiting; reader != NULL; reader = reader->next)
    {
        osSetEvent(&reader->moved);
    }
}

/* The settings of the box that started the download, looked up when they are used. The download outlives the
   request (a slow box keeps it for many minutes), and keeping the request's settings would mean: an overlay that
   a reload re-assigned (a box removed before it in the list), and settings memory a reload replaced, which is only
   kept for a grace period (settings_free_later). So nothing here keeps them, or a string of them, across a wait.
   What is called with them can take long as well (cloud_request_get the whole download, moveTAF2Lib a copy to
   another drive); it reads a string where it uses it (host name and certificates while connecting). A string
   kept across such an operation would outlast the grace period: that limit stays until settings are reference-
   counted snapshots (settings.c). */
static settings_t *contentDownloadSettings(content_download_t *dl)
{
    mutex_lock(MUTEX_SETTINGS); /* not halfway through a reload */
    uint8_t overlayNumber = get_overlay_id(dl->overlay);
    mutex_unlock(MUTEX_SETTINGS);
    return get_settings_id(overlayNumber);
}

static void contentDownloadRelease(content_download_t *dl, content_download_reader_t *reader)
{
    osAcquireMutex(&dl->lock);
    content_download_reader_t **link = &dl->waiting;
    while (*link != reader)
    {
        link = &(*link)->next;
    }
    *link = reader->next;
    bool_t lastOnTmp = reader->onTmp && --dl->tmpReaders == 0;
    reader->onTmp = FALSE;
    if (--dl->readers == 0 || lastOnTmp)
    {
        osSetEvent(&dl->idle);
    }
    osReleaseMutex(&dl->lock);
}

/* Returns with the entry's lock held once no request reads from the download, or only from the .tmp (onlyTmp). */
static void contentDownloadWaitIdle(content_download_t *dl, bool_t onlyTmp)
{
    osAcquireMutex(&dl->lock);
    while ((onlyTmp ? dl->tmpReaders : dl->readers) > 0)
    {
        osReleaseMutex(&dl->lock);
        osWaitForEvent(&dl->idle, 1000);
        osAcquireMutex(&dl->lock);
    }
}

/* Sets the state of the download, waking its readers. */
static void contentDownloadSetState(content_download_t *dl, content_download_state_t state)
{
    osAcquireMutex(&dl->lock);
    dl->state = state;
    contentDownloadWake(dl);
    osReleaseMutex(&dl->lock);
}

/* Puts the complete, valid .tmp into the cache like the pass-through did: at the content path, moved into the library
   from there. Renamed if nobody reads it, else a hard link to it or a copy (see content_download_t). Returns where the
   cached file is, NULL if it could not be cached. */
static char *contentDownloadCache(content_download_t *dl)
{
    char *path = NULL;
    char *copyPath = custom_asprintf("%s.copy", dl->contentPath);

    fsDeleteFile(dl->contentPath); /* an outdated copy, the tonie was marked as updated by the freshness check */
    fsDeleteFile(copyPath);        /* left by a server stopped while it copied, whichever way this one is cached */
    /* renamed with the lock held, so nobody opens the .tmp meanwhile; later requests read it at the content path */
    osAcquireMutex(&dl->lock);
    bool_t renamed = (dl->tmpReaders == 0 && fsRenameFile(dl->tmpPath, dl->contentPath) == NO_ERROR);
    if (renamed)
    {
        dl->path = dl->contentPath;
    }
    osReleaseMutex(&dl->lock);
    error_t error = renamed ? NO_ERROR : fsLinkFile(dl->tmpPath, dl->contentPath);
    bool_t copied = (error != NO_ERROR);
    if (copied)
    {
        /* copied aside first: a partial copy at the content path would be served as the tonie. Compared as fsMoveFile
           does: the .tmp was validated, the copy was not */
        error = fsCopyFile(dl->tmpPath, copyPath, true);
        if (error == NO_ERROR)
        {
            error = fsCompareFiles(dl->tmpPath, copyPath, NULL);
        }
        if (error == NO_ERROR)
        {
            error = fsRenameFile(copyPath, dl->contentPath);
        }
        if (error != NO_ERROR)
        {
            fsDeleteFile(copyPath);
        }
    }
    osFreeMem(copyPath);
    if (error != NO_ERROR || !fsFileExists(dl->contentPath))
    {
        TRACE_ERROR(">> Error caching %s, error=%s\r\n", dl->contentPath, error2text(error));
        return NULL;
    }
    TRACE_INFO(">> Successfully cached %s (%s)\r\n", dl->contentPath, renamed ? "renamed" : copied ? "copied" : "linked");

    path = strdup(dl->contentPath);
    settings_t *settings = contentDownloadSettings(dl); /* after a copy, which takes as long as the drive needs */
    if (settings->cloud.cacheToLibrary)
    {
        /* no second full validation, also with core.full_taf_validation: these are the bytes validated right before */
        tonie_info_t *tonieInfo = getTonieInfoV2(dl->contentPath, true, TAF_VALIDATION_HEADER, settings);
        if (moveTAF2Lib(tonieInfo, settings, false) == NO_ERROR && tonieInfo->json.source != NULL)
        {
            /* where moveTAF2Lib put it (lib://, next to another TAF of the same audio id with a hash suffix), with
               settings looked up again: copying it to another drive can take minutes */
            osFreeMem(path);
            path = strdup(tonieInfo->json.source);
            resolveSpecialPathPrefix(&path, contentDownloadSettings(dl));
        }
        freeTonieInfo(tonieInfo);
    }
    return path;
}

/* The end of a download, once the cloud's answer is in and a valid one is cached: deletes the .tmp once nobody reads
   it any more and unregisters the download. */
static void contentDownloadEnd(content_download_t *dl, bool_t fileCreated, bool_t cached)
{
    if (fileCreated)
    {
        if (cached)
        {
            /* new requests read the cached file: only those on the .tmp still need it */
            contentDownloadWaitIdle(dl, TRUE);
        }
        else
        {
            /* failed, no valid TAF, or not cached: its readers finish on it. Requests coming meanwhile are passed
               through, else they would get the .tmp, and the cloud would not be asked again, for as long as they keep
               overlapping. Nobody joins a failed one, so no new download can open the .tmp before it is gone. */
            osAcquireMutex(&dl->lock);
            dl->uncached = TRUE;
            osReleaseMutex(&dl->lock);
            contentDownloadWaitIdle(dl, FALSE);
            dl->state = CONTENT_DOWNLOAD_FAILED;
        }
        osReleaseMutex(&dl->lock);
        fsDeleteFile(dl->tmpPath);
    }

    /* unregistered with nobody reading: a request joins under the list's lock */
    while (true)
    {
        mutex_lock(MUTEX_CONTENT_DOWNLOAD);
        osAcquireMutex(&dl->lock);
        if (dl->readers == 0)
        {
            break;
        }
        osReleaseMutex(&dl->lock);
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        contentDownloadWaitIdle(dl, FALSE);
        osReleaseMutex(&dl->lock);
    }
    content_download_t **link = &contentDownloads;
    while (*link != dl)
    {
        link = &(*link)->next;
    }
    *link = dl->next;
    osReleaseMutex(&dl->lock);
    mutex_unlock(MUTEX_CONTENT_DOWNLOAD);

    contentDownloadFree(dl);
}

/* Header fields of the cloud's answer the boxes do not get, however often it sends them:
   - the framing and the connection, the server's own (hop-by-hop, RFC 9110 7.6.1, also what the cloud's Connection
     names, see contentDownloadDropNamed), and the Content-Type, which is kept apart;
   - what the server says of itself or sets itself: Accept-Ranges, Access-Control-Allow-Origin (as the pass-through
     did), Strict-Transport-Security, Alt-Svc, Server, and for the content the caching policy (Cache-Control, Pragma,
     Expires), which the answer from the cache does not have either. Another answer keeps the cloud's: a browser
     asking through the web UI would otherwise keep a 404 it was told not to;
   - what belongs to the one answer the cloud gave, not to the requests given it later or by other boxes: Date, Age,
     Set-Cookie, and the digests of its body (Content-MD5, Content-Digest), as a Range or skip_header gets another.
   Content-Encoding stays with the bytes it describes; a 200 with one is passed through, see contentDownloadHeader. */
static bool_t contentDownloadOwnHeader(const char *name, bool_t content)
{
    static const char *const own[] = {
        "Content-Length", "Transfer-Encoding", "Content-Range", "Content-Type", "Connection", "Keep-Alive",
        "Proxy-Connection", "TE", "Trailer", "Upgrade", "Accept-Ranges", "Access-Control-Allow-Origin",
        "Strict-Transport-Security", "Alt-Svc", "Server", "Date", "Age", "Set-Cookie", "Content-MD5", "Content-Digest"};
    static const char *const caching[] = {"Cache-Control", "Pragma", "Expires"};
    for (size_t i = 0; i < sizeof(own) / sizeof(own[0]); i++)
    {
        if (osStrcasecmp(name, own[i]) == 0)
        {
            return TRUE;
        }
    }
    for (size_t i = 0; content && i < sizeof(caching) / sizeof(caching[0]); i++)
    {
        if (osStrcasecmp(name, caching[i]) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* Drops the header lines with the names in a comma separated list: those the cloud's Connection header names, which
   are hop-by-hop too, or those that describe a body that was dropped. */
static void contentDownloadDropNamed(char *headers, const char *connection)
{
    char *line = headers;
    while (line != NULL && *line != '\0')
    {
        char *next = osStrstr(line, "\r\n");
        next = (next != NULL) ? next + 2 : line + osStrlen(line);
        const char *colon = osStrchr(line, ':');
        size_t nameLength = (colon != NULL && colon < next) ? (size_t)(colon - line) : 0;

        bool_t named = FALSE;
        const char *token = connection;
        while (nameLength > 0 && *token != '\0')
        {
            while (*token == ' ' || *token == '\t' || *token == ',')
            {
                token++;
            }
            size_t tokenLength = 0;
            while (token[tokenLength] != '\0' && token[tokenLength] != ',' && token[tokenLength] != ' ' && token[tokenLength] != '\t')
            {
                tokenLength++;
            }
            if (tokenLength == nameLength && osStrncasecmp(token, line, nameLength) == 0)
            {
                named = TRUE;
                break;
            }
            token += tokenLength;
        }

        if (named)
        {
            osMemmove(line, next, osStrlen(next) + 1);
        }
        else
        {
            line = next;
        }
    }
}

static void contentDownloadHeader(void *src_ctx, HttpClientContext *cloud_ctx, const char *header, const char *value)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    content_download_t *dl = (content_download_t *)ctx->customData;

    /* kept for the boxes; nobody reads them before the status is set below */
    if (header != NULL)
    {
        if (value == NULL)
        {
            value = "";
        }
        if (osStrcasecmp(header, "Content-Encoding") == 0 && osStrcasecmp(value, "identity") != 0)
        {
            dl->contentCoded = TRUE;
        }
        if (osStrcasecmp(header, "Content-Type") == 0)
        {
            osFreeMem(dl->contentType);
            dl->contentType = strdup(value);
        }
        else if (osStrcasecmp(header, "Connection") == 0)
        {
            /* several of them are one list */
            char *named = (dl->connectionNamed != NULL) ? custom_asprintf("%s, %s", dl->connectionNamed, value) : strdup(value);
            osFreeMem(dl->connectionNamed);
            dl->connectionNamed = named;
        }
        else if (!contentDownloadOwnHeader(header, cloud_ctx->statusCode == 200))
        {
            size_t used = (dl->headers != NULL) ? osStrlen(dl->headers) : 0;
            size_t line = osStrlen(header) + 2 + osStrlen(value) + 2;
            char *headers = (used + line < CONTENT_DOWNLOAD_HEADERS_MAX) ? realloc(dl->headers, used + line + 1) : NULL;
            if (headers != NULL)
            {
                osSprintf(&headers[used], "%s: %s\r\n", header, value);
                dl->headers = headers;
            }
            else
            {
                TRACE_WARNING(">> Header %s of the cloud's answer for %s dropped, too many\r\n", header, dl->uri);
            }
        }
        return;
    }

    if (dl->headers != NULL && dl->connectionNamed != NULL)
    {
        contentDownloadDropNamed(dl->headers, dl->connectionNamed);
    }

    bool_t passThrough = FALSE;
    if (cloud_ctx->statusCode == 200 && dl->contentCoded)
    {
        /* the download takes the bytes as they come for the TAF: it checks and caches them, and cuts them for a Range
           or skip_header. Coded (gzip, ...), they are not; the boxes get them as before, through the pass-through. */
        TRACE_WARNING(">> Cloud's content for %s is content-coded, passed through\r\n", dl->uri);
        passThrough = TRUE;
    }
    else if (cloud_ctx->statusCode == 200)
    {
        char *dir = strdup(dl->contentPath);
        dir[osStrlen(dir) - 8] = '\0';
        fsCreateDir(dir);
        osFreeMem(dir);

        /* a new file: a .tmp left behind (the server stopped before it was deleted) can be a hard link to a cached
           tonie, which truncating it would destroy. Nobody reads it, a download of it would be registered. */
        fsDeleteFile(dl->tmpPath);
        dl->file = fsOpenFile(dl->tmpPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
        if (dl->file == NULL)
        {
            TRACE_ERROR(">> Could not open file %s\r\n", dl->tmpPath);
            passThrough = TRUE;
        }
    }
    /* anything else than a 200 is kept in answer, see contentDownloadBody */
    ctx->cancel = passThrough;
    dl->published = osGetSystemTime();

    osAcquireMutex(&dl->lock);
    dl->statusCode = cloud_ctx->statusCode;
    dl->length = (cloud_ctx->chunkedEncoding || cloud_ctx->bodyLen == UINT_MAX) ? CONTENT_LENGTH_UNKNOWN : cloud_ctx->bodyLen;
    dl->chunked = cloud_ctx->chunkedEncoding;
    dl->passThrough = passThrough;
    if (passThrough)
    {
        dl->state = CONTENT_DOWNLOAD_FAILED;
    }
    contentDownloadWake(dl);
    osReleaseMutex(&dl->lock);
}

/* Hands what was written to the .tmp to the readers. A failed write ends the download, its requests that have not
   answered yet pass the request through. */
static void contentDownloadPublish(cbr_ctx_t *ctx, content_download_t *dl, error_t writeError)
{
    if (writeError == NO_ERROR && dl->unpublished > 0)
    {
        /* flushed, as the readers read the file with handles of their own */
        writeError = fsFlushFile(dl->file);
    }

    osAcquireMutex(&dl->lock);
    if (writeError == NO_ERROR)
    {
        dl->written += dl->unpublished;
    }
    else
    {
        dl->passThrough = TRUE;
        dl->state = CONTENT_DOWNLOAD_FAILED;
    }
    contentDownloadWake(dl);
    osReleaseMutex(&dl->lock);
    dl->unpublished = 0;
    dl->published = osGetSystemTime();

    if (writeError != NO_ERROR)
    {
        TRACE_ERROR(">> fsWriteFile Error: %s\r\n", error2text(writeError));
        fsCloseFile(dl->file);
        dl->file = NULL;
        ctx->cancel = TRUE;
    }
}

/* Drops the body of an answer that is not the content (too long, or it did not come in whole), with the header lines
   that describe it: they do not hold for the empty body given on instead. Content-Range is never given on. */
static void contentDownloadDropAnswer(content_download_t *dl)
{
    osFreeMem(dl->answer);
    dl->answer = NULL;
    dl->answerLength = 0;
    if (dl->headers != NULL)
    {
        contentDownloadDropNamed(dl->headers, "Content-Encoding, Content-MD5, Content-Digest");
    }
}

/* The body of an answer that is not the content, for every request; nobody reads it before it is complete. */
static void contentDownloadAnswer(cbr_ctx_t *ctx, content_download_t *dl, const char *payload, size_t length)
{
    if (dl->answerLength + length > CONTENT_DOWNLOAD_ANSWER_MAX)
    {
        TRACE_WARNING(">> Cloud's %" PRIu32 " answer for %s longer than %u bytes, given on without its body\r\n", dl->statusCode, dl->uri,
                      CONTENT_DOWNLOAD_ANSWER_MAX);
        contentDownloadDropAnswer(dl);
        ctx->cancel = TRUE;
        return;
    }
    uint8_t *answer = realloc(dl->answer, dl->answerLength + length);
    if (answer == NULL)
    {
        ctx->cancel = TRUE;
        return;
    }
    osMemcpy(&answer[dl->answerLength], payload, length);
    dl->answer = answer;
    dl->answerLength += length;
}

static void contentDownloadBody(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    content_download_t *dl = (content_download_t *)ctx->customData;

    if (length == 0)
    {
        return;
    }
    if (cloud_ctx->statusCode != 200)
    {
        contentDownloadAnswer(ctx, dl, payload, length);
        return;
    }
    if (dl->file == NULL)
    {
        return;
    }

    error_t writeError = fsWriteFile(dl->file, (void *)payload, length);
    dl->unpublished += length;
    if (writeError != NO_ERROR || dl->unpublished >= CONTENT_DOWNLOAD_PUBLISH_STEP || osGetSystemTime() - dl->published >= CONTENT_DOWNLOAD_PUBLISH_MS)
    {
        contentDownloadPublish(ctx, dl, writeError);
    }
}

static void contentDownloadTask(void *param)
{
    content_download_t *dl = (content_download_t *)param;

    client_ctx_t client_ctx;
    osMemset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.settings = contentDownloadSettings(dl);
    client_ctx.settingsNoOverlay = client_ctx.settings;
    client_ctx.state = get_toniebox_state_id(client_ctx.settings->internal.overlayNumber);

    cbr_ctx_t ctx;
    fillBaseCtx(NULL, dl->uri, "", V2_CONTENT, &ctx, &client_ctx);
    ctx.user_agent = dl->userAgent;
    /* the bytes as they are: the download checks, caches and cuts them as the TAF (a coded answer is still passed
       through, see contentDownloadHeader) */
    ctx.accept_encoding = "identity";
    ctx.customData = dl;
    req_cbr_t cbr = {
        .ctx = &ctx,
        .response = NULL,
        .header = &contentDownloadHeader,
        .body = &contentDownloadBody,
        .disconnect = NULL};

    TRACE_INFO(">> Start caching uri=%s\r\n", dl->uri);
    /* no query string: the download is shared, what a request asks for in its own (skip_header) is applied
       when it is answered */
    error_t error = cloud_request_get(NULL, 0, dl->uri, "", dl->token, &cbr);
    if (dl->file != NULL)
    {
        contentDownloadPublish(&ctx, dl, NO_ERROR); /* the rest; a failed flush closes the file, NULL is ignored */
        fsCloseFile(dl->file);
        dl->file = NULL;
    }

    osAcquireMutex(&dl->lock);
    uint32_t statusCode = dl->statusCode;
    size_t written = dl->written;
    size_t length = dl->length;
    bool_t passThrough = dl->passThrough; /* logged where it was decided */
    bool_t content = statusCode == 200;
    /* another answer is complete with its header, every request gets it; its body only if it came in whole */
    bool_t complete = content ? (error == NO_ERROR && dl->state == CONTENT_DOWNLOAD_RUNNING && (length == CONTENT_LENGTH_UNKNOWN || written == length))
                              : statusCode != 0;
    osReleaseMutex(&dl->lock);
    if (!content && complete && error != NO_ERROR)
    {
        contentDownloadDropAnswer(dl);
    }

    bool_t valid = FALSE;
    if (content && complete)
    {
        /* Complete for the readers before the validation, which reads the whole file. Except an answer without
           Content-Length and chunks: only the cloud closing the connection ends it, and the HTTP client takes a
           connection that breaks for that too, so only a valid TAF tells it is all there. Until then nobody takes
           it for complete, and a broken one is not given on with a length that looks right. */
        bool_t closeDelimited = (length == CONTENT_LENGTH_UNKNOWN && !dl->chunked);
        contentDownloadSetState(dl, closeDelimited ? CONTENT_DOWNLOAD_CHECKING : CONTENT_DOWNLOAD_DONE);
        valid = isValidTaf(dl->tmpPath, true);
        if (!valid && closeDelimited)
        {
            TRACE_ERROR(">> Download of %s ended without a valid TAF after %" PRIuSIZE " bytes, taken as broken off\r\n", dl->uri, written);
        }
        else if (!valid)
        {
            TRACE_ERROR(">> Error caching %s, not a valid TAF\r\n", dl->contentPath);
        }
        if (closeDelimited)
        {
            contentDownloadSetState(dl, valid ? CONTENT_DOWNLOAD_DONE : CONTENT_DOWNLOAD_FAILED);
        }
    }
    else
    {
        contentDownloadSetState(dl, complete ? CONTENT_DOWNLOAD_DONE : CONTENT_DOWNLOAD_FAILED);
        if (statusCode == 200 && !passThrough)
        {
            TRACE_ERROR(">> Download of %s failed after %" PRIuSIZE " of %" PRIuSIZE " bytes, error=%s\r\n", dl->uri, written, length, error2text(error));
        }
        else if (statusCode == 0)
        {
            TRACE_ERROR(">> Download of %s failed, error=%s\r\n", dl->uri, error2text(error));
        }
        else
        {
            TRACE_INFO(">> Cloud answered %" PRIu32 " for %s, giving that on\r\n", statusCode, dl->uri);
        }
    }

    /* into the cache right away, whoever still reads the .tmp */
    bool_t cached = FALSE;
    if (valid)
    {
        char *path = contentDownloadCache(dl);
        if (path != NULL)
        {
            osAcquireMutex(&dl->lock);
            dl->path = path;
            dl->state = CONTENT_DOWNLOAD_CACHED;
            contentDownloadWake(dl);
            osReleaseMutex(&dl->lock);
            cached = TRUE;
        }
    }

    contentDownloadEnd(dl, statusCode == 200, cached);
    osDeleteTask((OsTaskId)OS_SELF_TASK_ID);
}

/* Starts a download of contentPath with the caller as its first reader and registers it. Called with
   MUTEX_CONTENT_DOWNLOAD held, returns with it released. */
static content_download_t *contentDownloadStart(HttpConnection *connection, const char_t *uri, const uint8_t *token, const char *contentPath,
                                                client_ctx_t *client_ctx, content_download_reader_t *reader)
{
    content_download_t *dl = osAllocMem(sizeof(content_download_t));
    if (dl == NULL)
    {
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        return NULL;
    }
    osMemset(dl, 0, sizeof(content_download_t));
    if (!osCreateMutex(&dl->lock))
    {
        osFreeMem(dl);
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        return NULL;
    }
    if (!osCreateEvent(&dl->idle))
    {
        osDeleteMutex(&dl->lock);
        osFreeMem(dl);
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        return NULL;
    }
    dl->contentPath = strdup(contentPath);
    dl->tmpPath = custom_asprintf("%s.tmp", contentPath);
    dl->path = dl->tmpPath;
    dl->state = CONTENT_DOWNLOAD_RUNNING;
    dl->length = CONTENT_LENGTH_UNKNOWN;
    dl->readers = 1;
    reader->next = NULL;
    dl->waiting = reader;
    dl->stallMs = (systime_t)CONTENT_DOWNLOAD_STALL_TIMEOUTS * client_ctx->settings->core.http_client_timeout;
    dl->uri = strdup(uri);
    if (client_ctx->settings->internal.overlayNumber > 0) /* as fillBaseCtx does */
    {
        dl->userAgent = strdup(connection->request.userAgent);
    }
    dl->overlay = strdup(client_ctx->settings->internal.overlayUniqueId != NULL ? client_ctx->settings->internal.overlayUniqueId : "");
    if (dl->contentPath == NULL || dl->tmpPath == NULL || dl->uri == NULL || dl->overlay == NULL)
    {
        contentDownloadFree(dl);
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        return NULL;
    }
    osMemcpy(dl->token, token, TONIE_AUTH_TOKEN_LENGTH);

    /* registered only once its task exists, so nobody joins a download that never runs: a request that cannot
       start one passes the request through, the next one tries again. The task waits for the lock before it
       touches the entry, and cannot end before the caller, a reader, has let go. */
    OsTaskParameters taskParams = OS_TASK_DEFAULT_PARAMS;
    OsTaskId taskId = osCreateTask("contentDownload", &contentDownloadTask, dl, &taskParams);
    if (taskId == (OsTaskId)OS_INVALID_TASK_ID)
    {
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        TRACE_ERROR(">> Could not start the download of %s, passing it through\r\n", uri);
        contentDownloadFree(dl);
        return NULL;
    }
    dl->next = contentDownloads;
    contentDownloads = dl;
    mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
    TRACE_INFO(" >> downloading %s in the background\r\n", uri);
    return dl;
}

/* The download of contentPath to read from, with reader registered: the running one, or a new one (*started).
   NULL if there is none: *error is NO_ERROR if none could be started or the one there was not cached (the request is
   to be passed through), set if the box hung up meanwhile (nothing to pass through). */
static content_download_t *contentDownloadJoin(HttpConnection *connection, const char_t *uri, const uint8_t *token, const char *contentPath,
                                               client_ctx_t *client_ctx, content_download_reader_t *reader, bool_t *started, error_t *error)
{
    *error = NO_ERROR;
    systime_t start = osGetSystemTime();

    while (true)
    {
        mutex_lock(MUTEX_CONTENT_DOWNLOAD);
        content_download_t *dl = contentDownloads;
        while (dl != NULL && osStrcmp(dl->contentPath, contentPath) != 0)
        {
            dl = dl->next;
        }
        if (dl == NULL)
        {
            *started = TRUE;
            return contentDownloadStart(connection, uri, token, contentPath, client_ctx, reader);
        }
        osAcquireMutex(&dl->lock);
        /* not a failed one, nor an answer that is not the content once it is complete: that is given to the requests
           that came while it came in, later ones are passed through and ask anew rather than get an old answer for
           as long as requests keep overlapping. Nor one that was not cached, see contentDownloadEnd. Nor a cached one:
           a request for a tonie that is cached is served from the cache before it gets here, so its cached file is
           gone or outdated, and the request starts a new download once this one is gone.
           The cloud is asked with the token of the request that started the download, a joining one's is not looked
           at. The token belongs to the tag (it is on the tag, or the content's cloud_auth), so it is the same one; a
           request with another gets no more than the cache gives it once the content is in. An answer that is not
           the content (403, 404) is the cloud's answer for this tag, given to them all alike. */
        bool_t uncached = (dl->uncached && dl->state != CONTENT_DOWNLOAD_FAILED);
        bool_t answered = (dl->state == CONTENT_DOWNLOAD_DONE && dl->statusCode != 200);
        bool_t joined = (!uncached && !answered && dl->state != CONTENT_DOWNLOAD_FAILED && dl->state != CONTENT_DOWNLOAD_CACHED);
        if (joined)
        {
            dl->readers++;
            reader->next = dl->waiting;
            dl->waiting = reader;
        }
        osReleaseMutex(&dl->lock);
        mutex_unlock(MUTEX_CONTENT_DOWNLOAD);
        if (joined)
        {
            TRACE_INFO(" >> joining the running download of %s\r\n", contentPath);
            return dl;
        }
        if (uncached || answered)
        {
            TRACE_INFO(" >> the download of %s %s, passing the request through\r\n", contentPath, uncached ? "was not cached" : "got no content");
            return NULL;
        }

        /* A failed or cached one goes away as soon as its readers have stopped. Looked at again and again: waiting for a wake-up
           would need a reference, which would keep it from going away; and it is rare and short. */
        if (osGetSystemTime() - start > CONTENT_DOWNLOAD_GONE_MS)
        {
            TRACE_ERROR(">> The last download of %s does not go away\r\n", contentPath);
            return NULL;
        }
        osDelayTask(CONTENT_DOWNLOAD_POLL_MS);
        if (socketPeerClosed(connection->socket))
        {
            TRACE_INFO(">> Box hung up while waiting for %s\r\n", uri);
            *error = ERROR_CONNECTION_CLOSING;
            return NULL;
        }
    }
}

/* The audio id in the TAF header at the start of file; FALSE if there is none. */
static bool_t contentDownloadAudioId(FsFile *file, uint32_t *audioId)
{
    if (fsSeekFile(file, 0, FS_SEEK_SET) != NO_ERROR)
    {
        return FALSE;
    }
    TonieboxAudioFileHeader *tafHeader = tafReadHeader(file, NULL);
    if (tafHeader == NULL)
    {
        return FALSE;
    }
    *audioId = tafHeader->audio_id;
    toniebox_audio_file_header__free_unpacked(tafHeader, NULL);
    return TRUE;
}

/* The header lines of an answer from the download: the cloud's, and a Date of its own, as the cloud's Date belongs
   to the one answer it gave (RFC 9110 6.6.1: a proxy that forwards an answer without Date adds one). The calendar is
   cyclone's, the IMF-fixdate names are not the C library's, which follow the locale. */
static void contentDownloadHeaderLines(content_download_t *dl, char *lines, size_t size)
{
    static const char *const weekdays[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}; /* dayOfWeek 1-7 */
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    DateTime date;
    getCurrentDate(&date);

    osSnprintf(lines, size, "Date: %s, %02u %s %04u %02u:%02u:%02u GMT\r\n%s", weekdays[(date.dayOfWeek + 6) % 7], date.day,
               months[(date.month + 11) % 12], date.year, date.hours, date.minutes, date.seconds, (dl->headers != NULL) ? dl->headers : "");
}

/* The cloud's answer that is not the content, as it came, to every request that asked meanwhile. */
static error_t contentDownloadSendAnswer(HttpConnection *connection, content_download_t *dl)
{
    char headerLines[CONTENT_DOWNLOAD_HEADERS_MAX + 64];
    contentDownloadHeaderLines(dl, headerLines, sizeof(headerLines));
    httpPrepareHeader(connection, dl->contentType, dl->answerLength);
    connection->response.statusCode = dl->statusCode;
    connection->response.extraHeaders = headerLines;
    error_t error = httpWriteResponse(connection, dl->answer, dl->answerLength, false);
    connection->response.extraHeaders = NULL;
    return error;
}

/* Waits until the download moves, until limit ms after since passed, or CONTENT_DOWNLOAD_ALIVE_MS. FALSE if the box
   hung up. */
static bool_t contentDownloadWait(HttpConnection *connection, const char_t *uri, content_download_reader_t *reader, systime_t since,
                                  systime_t limit)
{
    systime_t waited = osGetSystemTime() - since;
    osWaitForEvent(&reader->moved, MIN((waited < limit) ? limit - waited : 0, CONTENT_DOWNLOAD_ALIVE_MS));
    /* woken for every step of the download: the box is looked at once in a while only */
    if (osGetSystemTime() - reader->aliveChecked < CONTENT_DOWNLOAD_ALIVE_MS)
    {
        return TRUE;
    }
    reader->aliveChecked = osGetSystemTime();
    if (socketPeerClosed(connection->socket))
    {
        TRACE_INFO(">> Box hung up while waiting for %s\r\n", uri);
        return FALSE;
    }
    return TRUE;
}

/* Answers the request from the download: the status and length once the cloud's answer is known, then the data
   as it comes in, with the cloud's header lines. Like local content (httpSendResponseStream): Range gets a 206,
   skip_header the audio only. The box resumes with If-Range: <audio id>; for another audio id it gets the whole
   file, as the cloud's content changed since it got its part. */
static error_t contentDownloadSend(HttpConnection *connection, const char_t *uri, content_download_t *dl, content_download_reader_t *reader,
                                   bool_t *served, bool_t *failedBeforeAnswer)
{
    systime_t lastChange = osGetSystemTime();
    content_download_state_t state = CONTENT_DOWNLOAD_RUNNING;
    uint32_t statusCode = 0;
    size_t written = 0;
    size_t size = 0;
    const char *path = NULL;
    FsFile *file = NULL;
    /* with If-Range the decision needs the TAF header */
    bool_t ifRange = connection->request.Range.start > 0 && connection->request.ifRange[0] != '\0';
    size_t needed = ifRange ? TONIE_HEADER_LENGTH : 1;

    /* wait for the cloud's answer: its status and the first data written */
    while (true)
    {
        content_download_state_t lastState = state;
        size_t lastWritten = written;
        bool_t open = FALSE;
        osAcquireMutex(&dl->lock);
        state = dl->state;
        statusCode = dl->statusCode;
        written = dl->written;
        bool_t passThrough = dl->passThrough;
        size_t length = dl->length;
        if (statusCode == 200 && (state == CONTENT_DOWNLOAD_DONE || state == CONTENT_DOWNLOAD_CACHED))
        {
            size = written;
            open = TRUE;
        }
        else if (state == CONTENT_DOWNLOAD_RUNNING && statusCode == 200 && length != CONTENT_LENGTH_UNKNOWN && written >= MIN(needed, length))
        {
            size = length;
            open = TRUE;
        }
        else if (state == CONTENT_DOWNLOAD_RUNNING && statusCode == 200 && length == CONTENT_LENGTH_UNKNOWN && written > 0)
        {
            size = CONTENT_LENGTH_UNKNOWN;
            open = TRUE;
        }
        if (open)
        {
            /* the file it opens, decided with the lock held: one that reads the .tmp keeps it from being deleted
               until it is done; once it is cached, new readers get the cached file */
            path = dl->path;
            reader->onTmp = (path == dl->tmpPath);
            dl->tmpReaders += reader->onTmp ? 1 : 0;
        }
        osReleaseMutex(&dl->lock);
        if (state != lastState || written != lastWritten)
        {
            lastChange = osGetSystemTime();
        }

        if (open)
        {
            file = fsOpenFile(path, FS_FILE_MODE_READ);
            if (file != NULL)
            {
                break;
            }
            /* renamed into the cache and moved on into the library just now: open where it is once it is cached */
            osAcquireMutex(&dl->lock);
            bool_t moved = (dl->state == CONTENT_DOWNLOAD_DONE && path == dl->contentPath && dl->path == path);
            osReleaseMutex(&dl->lock);
            if (!moved)
            {
                TRACE_ERROR(">> Could not open file %s\r\n", path);
                *served = FALSE;
                return NO_ERROR;
            }
            if (!contentDownloadWait(connection, uri, reader, osGetSystemTime(), CONTENT_DOWNLOAD_FILE_MAX_MS))
            {
                return ERROR_CONNECTION_CLOSING;
            }
            continue;
        }
        if (state == CONTENT_DOWNLOAD_DONE)
        {
            /* not the content: the fields of a complete answer stay as they are */
            return contentDownloadSendAnswer(connection, dl);
        }
        if (state == CONTENT_DOWNLOAD_FAILED)
        {
            if (passThrough)
            {
                /* nothing sent yet: the box gets the content without caching */
                *served = FALSE;
                return NO_ERROR;
            }
            /* no answer, or it broke off */
            *failedBeforeAnswer = TRUE;
            return ERROR_ABORTED;
        }
        /* being checked: that takes as long as the drive needs */
        bool_t checking = (state == CONTENT_DOWNLOAD_CHECKING);
        systime_t limit = checking ? CONTENT_DOWNLOAD_FILE_MAX_MS : dl->stallMs;
        if (osGetSystemTime() - lastChange > limit)
        {
            TRACE_ERROR(">> %s for %s\r\n", checking ? "Checking takes too long" : "No answer from the download", uri);
            return ERROR_TIMEOUT;
        }
        if (!contentDownloadWait(connection, uri, reader, lastChange, limit))
        {
            return ERROR_CONNECTION_CLOSING;
        }
    }

    bool_t lengthKnown = (size != CONTENT_LENGTH_UNKNOWN);
    char contentRange[64];
    bool_t useRange = TRUE;
    uint32_t first = 0;
    if (lengthKnown)
    {
        if (ifRange)
        {
            uint32_t audioId = 0;
            char *end = NULL;
            unsigned long expected = strtoul(connection->request.ifRange, &end, 10);
            if (!contentDownloadAudioId(file, &audioId) || *end != '\0' || expected != audioId)
            {
                TRACE_INFO(">> If-Range %s is not audio id %" PRIu32 " of %s, sending the whole file\r\n", connection->request.ifRange, audioId, uri);
                useRange = FALSE;
            }
        }
        /* as for local content: skip_header serves the file behind its TAF header, Range gets a 206 */
        uint32_t total = httpExtTafServedLength(connection, (uint32_t)size);
        first = httpExtPrepareRangeResponse(connection, total, total, useRange, contentRange, sizeof(contentRange));
        connection->response.chunkedEncoding = FALSE;
    }
    else
    {
        /* still coming in without Content-Length: framed as the cloud did, chunked or until the connection is
           closed. A Range needs the length, so the box gets it all, as through the pass-through */
        connection->response.statusCode = 200;
        connection->response.chunkedEncoding = dl->chunked;
        if (!dl->chunked)
        {
            connection->response.keepAlive = FALSE;
            connection->response.contentLength = CONTENT_LENGTH_UNKNOWN;
        }
    }
    /* as the cloud sent them, like the pass-through did; complete since the status was set */
    char headerLines[CONTENT_DOWNLOAD_HEADERS_MAX + 64];
    contentDownloadHeaderLines(dl, headerLines, sizeof(headerLines));
    connection->response.contentType = dl->contentType;
    connection->response.extraHeaders = headerLines;

    error_t error = httpWriteHeader(connection);
    connection->response.contentRange = NULL;
    connection->response.extraHeaders = NULL;

    size_t offset = connection->private.client_ctx.skip_taf_header ? TONIE_HEADER_LENGTH : 0;
    size_t pos = offset + first;
    size_t end = lengthKnown ? pos + connection->response.contentLength : SIZE_MAX;
    bool_t seek = TRUE;
    while (error == NO_ERROR && pos < end)
    {
        size_t lastWritten = written;
        osAcquireMutex(&dl->lock);
        state = dl->state;
        written = dl->written;
        osReleaseMutex(&dl->lock);
        if (written != lastWritten)
        {
            lastChange = osGetSystemTime();
        }

        if (state == CONTENT_DOWNLOAD_FAILED)
        {
            /* ends the response early, the box asks for the rest and gets a new download */
            TRACE_ERROR(">> Download of %s failed, ending the response at %" PRIuSIZE " bytes\r\n", uri, pos - offset);
            error = ERROR_ABORTED;
            break;
        }
        if (written > pos)
        {
            size_t n = MIN(MIN(written, end) - pos, HTTP_SERVER_BUFFER_SIZE);
            if (seek)
            {
                /* also clears the end of file stdio may have noted while waiting */
                fsSeekFile(file, pos, FS_SEEK_SET);
                seek = FALSE;
            }
            error = fsReadFile(file, connection->buffer, n, &n);
            if (error != NO_ERROR)
            {
                TRACE_ERROR(">> Could not read %s at %" PRIuSIZE ", error=%s\r\n", path, pos, error2text(error));
                break;
            }
            error = httpWriteStream(connection, connection->buffer, n);
            if (error != NO_ERROR)
            {
                TRACE_INFO(">> Box left at %" PRIuSIZE " bytes of %s, the download goes on\r\n", pos - offset, uri);
            }
            pos += n;
            continue;
        }
        if (state != CONTENT_DOWNLOAD_RUNNING && state != CONTENT_DOWNLOAD_CHECKING)
        {
            /* all of it without a length, else shorter than announced */
            error = lengthKnown ? ERROR_UNEXPECTED_END_OF_FILE : NO_ERROR;
            break;
        }
        /* an answer that ended with the connection is all there once the check says so */
        systime_t limit = (state == CONTENT_DOWNLOAD_CHECKING) ? CONTENT_DOWNLOAD_FILE_MAX_MS : dl->stallMs;
        if (osGetSystemTime() - lastChange > limit)
        {
            TRACE_ERROR(">> Download of %s stalled, ending the response\r\n", uri);
            error = ERROR_TIMEOUT;
            break;
        }
        if (!contentDownloadWait(connection, uri, reader, lastChange, limit))
        {
            error = ERROR_CONNECTION_CLOSING;
            break;
        }
        seek = TRUE;
    }
    fsCloseFile(file);

    if (error == NO_ERROR)
    {
        error = httpCloseStream(connection);
    }
    else
    {
        /* Cut short. The box can tell from how the connection ends, also without Content-Length: without TLS's
           close_notify, which the server sends when it closes the connection, unless it cannot send any more. */
        socketShutdown(connection->socket, SOCKET_SD_SEND);
    }
    return error;
}

error_t contentDownloadServe(HttpConnection *connection, const char_t *uri, const uint8_t *token, const char *contentPath,
                             client_ctx_t *client_ctx, bool_t *served)
{
    *served = FALSE;
    content_download_reader_t reader = {.next = NULL};
    if (!osCreateEvent(&reader.moved))
    {
        return NO_ERROR;
    }
    error_t error = NO_ERROR;
    /* A download this request joined that fails before it answered was most likely asked for long before; it tries
       a new one once (which waits for the failed one to go away). One it started itself it does not ask again: the
       box tries again on its own. */
    for (bool_t retried = FALSE;; retried = TRUE)
    {
        bool_t started = FALSE;
        error_t joinError;
        content_download_t *dl = contentDownloadJoin(connection, uri, token, contentPath, client_ctx, &reader, &started, &joinError);
        if (dl == NULL)
        {
            /* no download: passed through, unless the box hung up. Not from what an earlier try returned */
            *served = (joinError != NO_ERROR);
            error = joinError;
            break;
        }

        *served = TRUE;
        bool_t failedBeforeAnswer = FALSE;
        error = contentDownloadSend(connection, uri, dl, &reader, served, &failedBeforeAnswer);
        contentDownloadRelease(dl, &reader);
        if (!failedBeforeAnswer || started || retried)
        {
            if (failedBeforeAnswer)
            {
                TRACE_ERROR(">> No content from the cloud for %s\r\n", uri);
            }
            break;
        }
        TRACE_INFO(" >> The download of %s failed before this request got anything, trying a new one\r\n", uri);
        osResetEvent(&reader.moved);
    }
    osDeleteEvent(&reader.moved);
    return error;
}
