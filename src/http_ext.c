#include <inttypes.h>
#include <stdio.h>

#include "core/net.h"
#include "http/http_server.h"
#include "str.h"
#include "debug.h"
#include "http/http_server_misc.h"
#include "http/mime.h"
#include "http_ext.h"

void httpExtParseRequestHeaderField(HttpConnection *connection, const char *name, char *value)
{
    if (osStrcasecmp(name, "Range") == 0)
    {
        sscanf(value, "bytes=%" PRIu32 "-%" PRIu32, &connection->request.Range.start, &connection->request.Range.end);
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
   if (connection->request.Range.start > 0)
   {
      connection->request.Range.size = file_length;

      uint32_t rangeStart = connection->request.Range.start;
      uint32_t rangeEnd = connection->request.Range.end;
      /* open-ended ("bytes=N-") or oversized end -> last byte */
      if (rangeEnd == 0 || rangeEnd >= file_length)
         rangeEnd = (file_length > 0) ? file_length - 1 : 0;

      /* Reject an unsatisfiable range (start past the data, start after end,
         or empty resource) instead of computing end-start+1, which would
         underflow to a ~4 GB contentLength and desync the connection. Fall
         back to serving the full content. */
      if (file_length == 0 || rangeStart >= file_length || rangeStart > rangeEnd ||
          (connection->response.contentRange == NULL &&
           (connection->response.contentRange = osAllocMem(255)) == NULL))
      {
         connection->request.Range.start = 0;
         connection->response.statusCode = 200;
         connection->response.contentLength = length;
      }
      else
      {
         connection->request.Range.end = rangeEnd;
         osSprintf((char *)connection->response.contentRange, "bytes %" PRIu32 "-%" PRIu32 "/%" PRIu32, rangeStart, rangeEnd, connection->request.Range.size);
         connection->response.statusCode = 206;
         connection->response.contentLength = rangeEnd - rangeStart + 1;
         TRACE_DEBUG("Added response range %s\r\n", connection->response.contentRange);
      }
   }
   else
   {
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
   uint32_t taf_virtual_pos = connection->request.Range.start;

   if (!taf_chapter_split)
   {
      if (connection->private.client_ctx.skip_taf_header)
      {
         if (connection->request.Range.start > 0)
         {
            connection->request.Range.start += TONIE_HEADER_LENGTH;
         }
         else
         {
            fsSeekFile(file, TONIE_HEADER_LENGTH, FS_SEEK_SET);
         }
      }
      if (connection->request.Range.start > 0 && connection->request.Range.start < connection->request.Range.size)
      {
         TRACE_DEBUG("Seeking file to %" PRIu32 "\r\n", connection->request.Range.start);
         fsSeekFile(file, connection->request.Range.start, FS_SEEK_SET);
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
