#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/net.h"
#include "http/http_client.h"
#include "http/http_server.h"
#include "str.h"
#include "debug.h"
#include "http/http_server_misc.h"
#include "http/mime.h"
#include "http_ext.h"
#include "pcaplog.h"

void httpExtParseRequestHeaderField(HttpConnection *connection, const char *name, char *value)
{
    if (osStrcasecmp(name, "Range") == 0)
    {
        /* "bytes=N-" and "bytes=N-M"; a suffix range ("bytes=-N") is ignored, scanf would read it as a huge start */
        if (osStrncasecmp(value, "bytes=", 6) == 0 && isdigit((unsigned char)value[6]))
        {
            char *rest = NULL;
            unsigned long long start = strtoull(value + 6, &rest, 10);
            bool has_end = (*rest == '-' && isdigit((unsigned char)rest[1]));
            unsigned long long end = has_end ? strtoull(rest + 1, NULL, 10) : 0;
            /* values that do not fit 32 bits are not a usable range */
            if (*rest == '-' && start <= UINT32_MAX && end <= UINT32_MAX)
            {
                connection->request.Range.start = (uint32_t)start;
                connection->request.Range.end = (uint32_t)end;
                connection->request.Range.valid = true;
                connection->request.Range.has_end = has_end;
            }
        }
    }
    else if (osStrcasecmp(name, "If-Range") == 0)
    {
        strSafeCopy(connection->request.ifRange, value, HTTP_SERVER_IFRANGE_MAX_LEN);
    }
    else if (osStrcasecmp(name, "User-Agent") == 0)
    {
        strSafeCopy(connection->request.userAgent, value, sizeof(connection->request.userAgent));
    }
}

size_t httpExtFormatResponseHeader(HttpConnection *connection, char *p)
{
    char *start = p;

    p += osSprintf(p, "Accept-Ranges: bytes\r\n");

    char_t *allowOrigin = connection->serverContext->settings.allowOrigin;
    if (allowOrigin != NULL && osStrlen(allowOrigin) > 0)
    {
        p += osSprintf(p, "Access-Control-Allow-Origin: %s\r\n", allowOrigin);
    }

    if (connection->response.contentRange != NULL)
    {
        p += osSprintf(p, "Content-Range: %s\r\n", connection->response.contentRange);
    }

    return p - start;
}


/*
 * Response sending with Range, TAF header skip / chapter split and streaming of a TAF that is
 * still being written. Cyclone's own httpSendResponse() stays in the vendored server untouched;
 * its default file handler calls httpExtSendResponse() instead.
 */

error_t httpExtSendResponse(HttpConnection *connection, const char_t *uri)
{
   return httpExtSendResponseStream(connection, uri, false);
}
error_t httpExtSendResponseUnsafe(HttpConnection *connection, const char_t *uri, const char_t *absolutePath)
{
   return httpExtSendResponseStreamUnsafe(connection, uri, absolutePath, false);
}
error_t httpExtSendResponseStream(HttpConnection *connection, const char_t *uri, bool_t isStream)
{
   // Retrieve the full pathname
   httpGetAbsolutePath(connection, uri, connection->buffer, HTTP_SERVER_BUFFER_SIZE);
   return httpExtSendResponseStreamUnsafe(connection, uri, connection->buffer, isStream);
}
error_t httpExtSendResponseStreamUnsafe(HttpConnection *connection, const char_t *uri, const char_t *absolutePath, bool_t isStream)
{
   if (connection->buffer != absolutePath)
   {
      osStrcpy(connection->buffer, absolutePath);
   }
#if (HTTP_SERVER_FS_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint32_t file_length;
   uint32_t length;
   FsFile *file;

#if (HTTP_SERVER_GZIP_TYPE_SUPPORT == ENABLED)
   // Check whether gzip compression is supported by the client
   if (connection->request.acceptGzipEncoding)
   {
      // Calculate the length of the pathname
      n = osStrlen(connection->buffer);

      // Sanity check
      if (n < (HTTP_SERVER_BUFFER_SIZE - 4))
      {
         // Append gzip extension
         osStrcpy(connection->buffer + n, ".gz");
         // Retrieve the size of the compressed resource, if any
         error = fsGetFileSize(connection->buffer, &length);
      }
      else
      {
         // Report an error
         error = ERROR_NOT_FOUND;
      }

      // Check whether the gzip-compressed file exists
      if (!error)
      {
         // Use gzip format
         connection->response.gzipEncoding = TRUE;
      }
      else
      {
         // Strip the gzip extension
         connection->buffer[n] = '\0';

         // Retrieve the size of the non-compressed resource
         error = fsGetFileSize(connection->buffer, &length);
         // The specified URI cannot be found?
         if (error)
            return ERROR_NOT_FOUND;
      }
   }
   else
#endif
   {
      // Retrieve the size of the specified file
      error = fsGetFileSize(connection->buffer, &length);
      // The specified URI cannot be found?
      if (error)
         return ERROR_NOT_FOUND;
   }

   // Open the file for reading
   file = fsOpenFile(connection->buffer, FS_FILE_MODE_READ);
   // Failed to open the file?
   if (file == NULL)
      return ERROR_NOT_FOUND;
#else
   error_t error;
   size_t length;
   const uint8_t *data;

#if (HTTP_SERVER_GZIP_TYPE_SUPPORT == ENABLED)
   // Check whether gzip compression is supported by the client
   if (connection->request.acceptGzipEncoding)
   {
      size_t n;

      // Calculate the length of the pathname
      n = osStrlen(connection->buffer);

      // Sanity check
      if (n < (HTTP_SERVER_BUFFER_SIZE - 4))
      {
         // Append gzip extension
         osStrcpy(connection->buffer + n, ".gz");
         // Get the compressed resource data associated with the URI, if any
         error = resGetData(connection->buffer, &data, &length);
      }
      else
      {
         // Report an error
         error = ERROR_NOT_FOUND;
      }

      // Check whether the gzip-compressed resource exists
      if (!error)
      {
         // Use gzip format
         connection->response.gzipEncoding = TRUE;
      }
      else
      {
         // Strip the gzip extension
         connection->buffer[n] = '\0';

         // Get the non-compressed resource data associated with the URI
         error = resGetData(connection->buffer, &data, &length);
         // The specified URI cannot be found?
         if (error)
            return error;
      }
   }
   else
#endif
   {
      // Get the resource data associated with the URI
      error = resGetData(connection->buffer, &data, &length);
      // The specified URI cannot be found?
      if (error)
         return error;
   }
#endif

   if (connection->private.client_ctx.taf_chapter_split)
   {
      uint32_t header_size = connection->private.client_ctx.taf_chapter_header_size;
      uint32_t start_off = connection->private.client_ctx.taf_chapter_start_offset;
      uint32_t end_off = connection->private.client_ctx.taf_chapter_end_offset;
      length = header_size + (end_off - start_off);
   }
   else if (connection->private.client_ctx.skip_taf_header)
   {
      /* Guard against a content file shorter than the TAF header, which would
         underflow length to a huge value and be sent as the Content-Length. */
      if (length >= TONIE_HEADER_LENGTH)
      {
         length -= TONIE_HEADER_LENGTH;
      }
      else
      {
         length = 0;
      }
   }
   file_length = length;
   if (isStream)
   {
      length = connection->private.client_ctx.settings->encode.stream_max_size; //CONTENT_LENGTH_MAX
      if (!connection->private.client_ctx.settings->encode.ffmpeg_stream_restart)
      {
         file_length = length;
      }
   }

   // Format HTTP response header
   uint32_t first = 0, last = 0;
   connection->request.Range.size = file_length;
   // An unsatisfiable range (start behind the data, empty resource) falls back to the full content
   // A stream that is still growing only honours a range that starts behind its beginning, as before:
   // "bytes=0-" would otherwise cut it off at the size it has right now
   HttpRangeResult range = (isStream && connection->request.Range.start == 0) ? HTTP_RANGE_FULL
                                                                              : httpExtResolveRange(&connection->request.Range, file_length, &first, &last);
   if (range == HTTP_RANGE_PARTIAL && connection->response.contentRange == NULL)
   {
      connection->response.contentRange = osAllocMem(255);
      if (connection->response.contentRange == NULL)
      {
         range = HTTP_RANGE_FULL;
      }
   }

   if (range == HTTP_RANGE_PARTIAL)
   {
      osSprintf((char *)connection->response.contentRange, "bytes %" PRIu32 "-%" PRIu32 "/%" PRIu32, first, last, file_length);
      connection->response.statusCode = 206;
      connection->response.contentLength = last - first + 1;
      TRACE_DEBUG("Added response range %s\r\n", connection->response.contentRange);
   }
   else
   {
      first = 0;
      connection->response.statusCode = 200;
      connection->response.contentLength = length;
   }

   if (connection->response.contentType == NULL || osStrlen(connection->response.contentType) == 0 || osStrcmp(connection->response.contentType, "application/octet-stream") == 0)
   {
      connection->response.contentType = mimeGetType(uri);
   }
   if (connection->response.contentType == NULL || osStrlen(connection->response.contentType) == 0 || osStrcmp(connection->response.contentType, "application/octet-stream") == 0)
   {
      connection->response.contentType = mimeGetType(absolutePath);
   }

   connection->response.contentType = mimeGetType(uri);
   connection->response.chunkedEncoding = FALSE;
   length = connection->response.contentLength;

   // Send the header to the client
   error = httpWriteHeader(connection);
   // The Content-Range string has now been serialized into the header; free it
   // here so it does not leak (the response struct is zeroed per request).
   if (connection->response.contentRange != NULL)
   {
      osFreeMem((void *)connection->response.contentRange);
      connection->response.contentRange = NULL;
   }
   // Any error to report?
   if (error)
   {
#if (HTTP_SERVER_FS_SUPPORT == ENABLED)
      // Close the file
      fsCloseFile(file);
#endif
      // Return status code
      return error;
   }

   bool taf_chapter_split = connection->private.client_ctx.taf_chapter_split;
   uint32_t taf_virtual_pos = first;

   if (!taf_chapter_split)
   {
      // the range counts in the file without the TAF header, if that is skipped
      uint32_t position = first + (connection->private.client_ctx.skip_taf_header ? TONIE_HEADER_LENGTH : 0);
      if (position > 0)
      {
         TRACE_DEBUG("Seeking file to %" PRIu32 "\r\n", position);
         fsSeekFile(file, position, FS_SEEK_SET);
      }
      else
      {
         TRACE_DEBUG("No seeking, sending from beginning\r\n");
      }
   }

#if (HTTP_SERVER_FS_SUPPORT == ENABLED)
   // Send response body
   while (length > 0)
   {
      // Limit the number of bytes to read at a time
      n = MIN(length, HTTP_SERVER_BUFFER_SIZE);

      if (taf_chapter_split)
      {
         uint32_t header_size = connection->private.client_ctx.taf_chapter_header_size;
         uint32_t start_off = connection->private.client_ctx.taf_chapter_start_offset;
         
         if (taf_virtual_pos < header_size)
         {
            n = MIN(n, header_size - taf_virtual_pos);
            uint32_t physical_pos = 4096 + taf_virtual_pos;
            fsSeekFile(file, physical_pos, FS_SEEK_SET);
         }
         else
         {
            uint32_t physical_pos = start_off + (taf_virtual_pos - header_size);
            fsSeekFile(file, physical_pos, FS_SEEK_SET);
         }
      }

      // Read data from the specified file
      error = fsReadFile(file, connection->buffer, n, &n);
      // End of input stream?
      if (isStream && error == ERROR_END_OF_FILE && connection->private.client_ctx.state->box.stream_ctx.active)
      {
         osDelayTask(100);
         error = httpCloseStream(connection); // Test connection??? won't work TODO: exit after some seconds
         if (error)
            break;
         // Clear the sticky stdio EOF indicator so the next read sees appended blocks
         fsSeekFile(file, 0, FS_SEEK_CUR);
         continue;
      }
      if (error)
         break;

      // Send data to the client
      error = httpWriteStream(connection, connection->buffer, n);
      // Any error to report?
      if (error)
         break;

      if (taf_chapter_split)
      {
         taf_virtual_pos += n;
      }

      // Decrement the count of remaining bytes to be transferred
      length -= n;
   }

   // Close the file
   fsCloseFile(file);

   // Successful file transfer?
   if (error == NO_ERROR || error == ERROR_END_OF_FILE)
   {
      if (length == 0)
      {
         // Properly close the output stream
         error = httpCloseStream(connection);
      }
   }
#else
   // Send response body
   error = httpWriteStream(connection, data, length);
   // Any error to report?
   if (error)
      return error;

   // Properly close output stream
   error = httpCloseStream(connection);
#endif

   // Return status code
   return error;
}


void httpExtPcapServerWrite(HttpConnection *connection, bool is_tx, const void *data, size_t length)
{
    pcaplog_ctx_t ctx;
    ctx.local_endpoint.ipv4 = connection->settings->ipAddr.ipv4Addr;
    ctx.local_endpoint.port = connection->settings->port;
    ctx.remote_endpoint.ipv4 = connection->socket->remoteIpAddr.ipv4Addr;
    ctx.remote_endpoint.port = connection->socket->remotePort;
    ctx.pcap_data = &connection->private.pcap_data;
    pcaplog_write(&ctx, is_tx, (const uint8_t *)data, length);
}

static void pcap_client_ctx(HttpClientContext *context, pcaplog_ctx_t *ctx)
{
    ctx->local_endpoint.ipv4 = 0;
    ctx->local_endpoint.port = context->socket->localPort;
    ctx->remote_endpoint.ipv4 = context->socket->remoteIpAddr.ipv4Addr;
    ctx->remote_endpoint.port = context->socket->remotePort;
    ctx->pcap_data = &context->private.pcap_data;
}

void httpExtPcapClientReset(HttpClientContext *context)
{
    pcaplog_ctx_t ctx;
    pcap_client_ctx(context, &ctx);
    pcaplog_reset(&ctx);
}

void httpExtPcapClientWrite(HttpClientContext *context, bool is_tx, const void *data, size_t length)
{
    pcaplog_ctx_t ctx;
    pcap_client_ctx(context, &ctx);
    pcaplog_write(&ctx, is_tx, (const uint8_t *)data, length);
}
