#pragma once

#include "handler.h"

/**
 * Serves cloud content (/v1/content, /v2/content) that is not cached yet from a download in the background.
 *
 * The first request for a content file starts one task that downloads it from the cloud as fast as the cloud
 * sends into <contentPath>.tmp and then caches it like the pass-through did (cache file, library). Every request
 * for that file meanwhile - another box, or the box's retry with Range - is served from the growing file and
 * waits where it caught up with the download. A box going away does not stop the download.
 *
 * Before, the box's response was the pass-through of the cloud's: the cloud was read only as fast as the box took
 * the data, and a slow box made the cloud drop the stalled connection; every retry started over.
 *
 * @param connection  the box's connection, nothing sent on it yet
 * @param uri         URI for the cloud (/v2/content/<ruid>, with the alternative rUID of cloud_override)
 * @param token       auth token for the cloud, TONIE_AUTH_TOKEN_LENGTH bytes
 * @param contentPath the cache file in the content directory, identifies the download
 * @param client_ctx  the box's context, its settings are used for the download
 * @param[out] served FALSE if nothing was sent and the request is to be passed through to the cloud instead: no
 *                    download could be started (also while one that was not cached is still read), its file not
 *                    be written or read, or the cloud's content is content-coded. An answer that is not a 200 is
 *                    given on like the content, to every request that asked while it came in
 * @return NO_ERROR, or the error that ended the response early or before it began (the cloud did not answer,
 *         the download broke off): the connection is to be closed, the box tries again or continues with Range
 */
error_t contentDownloadServe(HttpConnection *connection, const char_t *uri, const uint8_t *token, const char *contentPath,
                             client_ctx_t *client_ctx, bool_t *served);
