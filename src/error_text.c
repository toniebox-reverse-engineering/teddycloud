#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error_text.h"

/* Keyed by the enumerators, so the texts stay right when Cyclone renumbers its error codes.
   The numbers shown in the text are taken from the enum as well. */
#define ERROR_COUNT 1024

static char *error_text[ERROR_COUNT];

static const struct
{
    error_t code;
    const char *text;
} error_texts[] = {
    {NO_ERROR, "Success"},
    {ERROR_FAILURE, "Generic error code"},
    {ERROR_INVALID_PARAMETER, "Invalid parameter"},
    {ERROR_PARAMETER_OUT_OF_RANGE, "Specified parameter is out of range"},
    {ERROR_BAD_CRC, "Bad CRC detected"},
    {ERROR_BAD_BLOCK, "Bad block detected"},
    {ERROR_INVALID_RECIPIENT, "Invalid recipient"},
    {ERROR_INVALID_INTERFACE, "Invalid interface"},
    {ERROR_INVALID_ENDPOINT, "Invalid endpoint"},
    {ERROR_INVALID_ALT_SETTING, "Alternate setting does not exist"},
    {ERROR_UNSUPPORTED_REQUEST, "Unsupported request"},
    {ERROR_UNSUPPORTED_CONFIGURATION, "Unsupported configuration"},
    {ERROR_UNSUPPORTED_FEATURE, "Unsupported feature"},
    {ERROR_ENDPOINT_BUSY, "Endpoint already in use"},
    {ERROR_USB_RESET, "USB reset"},
    {ERROR_ABORTED, "Operation aborted"},
    {ERROR_OUT_OF_MEMORY, "Out of memory"},
    {ERROR_OUT_OF_RESOURCES, "Out of resources"},
    {ERROR_INVALID_REQUEST, "Invalid request"},
    {ERROR_NOT_IMPLEMENTED, "Not implemented"},
    {ERROR_VERSION_NOT_SUPPORTED, "Version not supported"},
    {ERROR_INVALID_SYNTAX, "Invalid syntax"},
    {ERROR_AUTHENTICATION_FAILED, "Authentication failed"},
    {ERROR_UNEXPECTED_RESPONSE, "Unexpected response"},
    {ERROR_INVALID_RESPONSE, "Invalid response"},
    {ERROR_UNEXPECTED_VALUE, "Unexpected value"},
    {ERROR_WAIT_CANCELED, "Wait canceled"},
    {ERROR_OPEN_FAILED, "Open failed"},
    {ERROR_CONNECTION_FAILED, "Connection failed"},
    {ERROR_CONNECTION_REFUSED, "Connection refused"},
    {ERROR_CONNECTION_CLOSING, "Connection closing"},
    {ERROR_CONNECTION_RESET, "Connection reset"},
    {ERROR_NOT_CONNECTED, "Not connected"},
    {ERROR_ALREADY_CLOSED, "Already closed"},
    {ERROR_ALREADY_CONNECTED, "Already connected"},
    {ERROR_INVALID_SOCKET, "Invalid socket"},
    {ERROR_PROTOCOL_UNREACHABLE, "Protocol unreachable"},
    {ERROR_PORT_UNREACHABLE, "Port unreachable"},
    {ERROR_INVALID_FRAME, "Invalid frame"},
    {ERROR_INVALID_HEADER, "Invalid header"},
    {ERROR_WRONG_CHECKSUM, "Wrong checksum"},
    {ERROR_WRONG_IDENTIFIER, "Wrong identifier"},
    {ERROR_WRONG_CLIENT_ID, "Wrong client ID"},
    {ERROR_WRONG_SERVER_ID, "Wrong server ID"},
    {ERROR_WRONG_COOKIE, "Wrong cookie"},
    {ERROR_NO_RESPONSE, "No response received"},
    {ERROR_RECEIVE_QUEUE_FULL, "Receive queue full"},
    {ERROR_TIMEOUT, "Timeout"},
    {ERROR_WOULD_BLOCK, "Operation would block"},
    {ERROR_INVALID_NAME, "Invalid name"},
    {ERROR_INVALID_OPTION, "Invalid option"},
    {ERROR_UNEXPECTED_STATE, "Unexpected state"},
    {ERROR_INVALID_COMMAND, "Invalid command"},
    {ERROR_INVALID_PROTOCOL, "Invalid protocol"},
    {ERROR_INVALID_STATUS, "Invalid status"},
    {ERROR_INVALID_ADDRESS, "Invalid address"},
    {ERROR_INVALID_PORT, "Invalid port"},
    {ERROR_INVALID_MESSAGE, "Invalid message"},
    {ERROR_INVALID_KEY, "Invalid key"},
    {ERROR_INVALID_KEY_LENGTH, "Invalid key length"},
    {ERROR_INVALID_EPOCH, "Invalid epoch"},
    {ERROR_INVALID_SEQUENCE_NUMBER, "Invalid sequence number"},
    {ERROR_INVALID_CHARACTER, "Invalid character"},
    {ERROR_INVALID_LENGTH, "Invalid length"},
    {ERROR_INVALID_PADDING, "Invalid padding"},
    {ERROR_INVALID_MAC, "Invalid MAC"},
    {ERROR_INVALID_TAG, "Invalid tag"},
    {ERROR_INVALID_TYPE, "Invalid type"},
    {ERROR_INVALID_VALUE, "Invalid value"},
    {ERROR_INVALID_CLASS, "Invalid class"},
    {ERROR_INVALID_VERSION, "Invalid version"},
    {ERROR_INVALID_PIN_CODE, "Invalid PIN code"},
    {ERROR_WRONG_LENGTH, "Wrong length"},
    {ERROR_WRONG_TYPE, "Wrong type"},
    {ERROR_WRONG_ENCODING, "Wrong encoding"},
    {ERROR_WRONG_VALUE, "Wrong value"},
    {ERROR_INCONSISTENT_VALUE, "Inconsistent value"},
    {ERROR_UNSUPPORTED_TYPE, "Unsupported type"},
    {ERROR_UNSUPPORTED_ALGO, "Unsupported algorithm"},
    {ERROR_UNSUPPORTED_CIPHER_SUITE, "Unsupported cipher suite"},
    {ERROR_UNSUPPORTED_CIPHER_MODE, "Unsupported cipher mode"},
    {ERROR_UNSUPPORTED_CIPHER_ALGO, "Unsupported cipher algorithm"},
    {ERROR_UNSUPPORTED_HASH_ALGO, "Unsupported hash algorithm"},
    {ERROR_UNSUPPORTED_KEY_EXCH_ALGO, "Unsupported key exchange algorithm"},
    {ERROR_UNSUPPORTED_SIGNATURE_ALGO, "Unsupported signature algorithm"},
    {ERROR_UNSUPPORTED_ELLIPTIC_CURVE, "Unsupported elliptic curve"},
    {ERROR_INVALID_ELLIPTIC_CURVE, "Invalid elliptic curve"},
    {ERROR_INVALID_SIGNATURE_ALGO, "Invalid signature algorithm"},
    {ERROR_CERTIFICATE_REQUIRED, "Certificate required"},
    {ERROR_MESSAGE_TOO_LONG, "Message too long"},
    {ERROR_OUT_OF_RANGE, "Out of range"},
    {ERROR_MESSAGE_DISCARDED, "Message discarded"},
    {ERROR_INVALID_PACKET, "Invalid packet"},
    {ERROR_BUFFER_EMPTY, "Buffer is empty"},
    {ERROR_BUFFER_OVERFLOW, "Buffer overflow"},
    {ERROR_BUFFER_UNDERFLOW, "Buffer underflow"},
    {ERROR_INVALID_RESOURCE, "Invalid resource"},
    {ERROR_INVALID_PATH, "Invalid path"},
    {ERROR_NOT_FOUND, "Not found"},
    {ERROR_ACCESS_DENIED, "Access denied"},
    {ERROR_NOT_WRITABLE, "Not writable"},
    {ERROR_AUTH_REQUIRED, "Authentication required"},
    {ERROR_TRANSMITTER_BUSY, "Transmitter is busy"},
    {ERROR_NO_RUNNING, "No running operation"},
    {ERROR_INVALID_FILE, "Invalid file"},
    {ERROR_FILE_NOT_FOUND, "File not found"},
    {ERROR_FILE_OPENING_FAILED, "File opening failed"},
    {ERROR_FILE_READING_FAILED, "File reading failed"},
    {ERROR_END_OF_FILE, "End of file reached"},
    {ERROR_UNEXPECTED_END_OF_FILE, "Unexpected end of file"},
    {ERROR_UNKNOWN_FILE_FORMAT, "Unknown file format"},
    {ERROR_INVALID_DIRECTORY, "Invalid directory"},
    {ERROR_DIRECTORY_NOT_FOUND, "Directory not found"},
    {ERROR_FILE_SYSTEM_NOT_SUPPORTED, "File system not supported"},
    {ERROR_UNKNOWN_FILE_SYSTEM, "Unknown file system"},
    {ERROR_INVALID_FILE_SYSTEM, "Invalid file system"},
    {ERROR_INVALID_BOOT_SECTOR_SIGNATURE, "Invalid boot sector signature"},
    {ERROR_INVALID_SECTOR_SIZE, "Invalid sector size"},
    {ERROR_INVALID_CLUSTER_SIZE, "Invalid cluster size"},
    {ERROR_INVALID_FILE_RECORD_SIZE, "Invalid file record size"},
    {ERROR_INVALID_INDEX_BUFFER_SIZE, "Invalid index buffer size"},
    {ERROR_INVALID_VOLUME_DESCRIPTOR_SIGNATURE, "Invalid volume descriptor signature"},
    {ERROR_INVALID_VOLUME_DESCRIPTOR, "Invalid volume descriptor"},
    {ERROR_INVALID_FILE_RECORD, "Invalid file record"},
    {ERROR_INVALID_INDEX_BUFFER, "Invalid index buffer"},
    {ERROR_INVALID_DATA_RUNS, "Invalid data runs"},
    {ERROR_WRONG_TAG_IDENTIFIER, "Wrong tag identifier"},
    {ERROR_WRONG_TAG_CHECKSUM, "Wrong tag checksum"},
    {ERROR_WRONG_MAGIC_NUMBER, "Wrong magic number"},
    {ERROR_WRONG_SEQUENCE_NUMBER, "Wrong sequence number"},
    {ERROR_DESCRIPTOR_NOT_FOUND, "Descriptor not found"},
    {ERROR_ATTRIBUTE_NOT_FOUND, "Attribute not found"},
    {ERROR_RESIDENT_ATTRIBUTE, "Resident attribute"},
    {ERROR_NOT_RESIDENT_ATTRIBUTE, "Not resident attribute"},
    {ERROR_INVALID_SUPER_BLOCK, "Invalid super block"},
    {ERROR_INVALID_SUPER_BLOCK_SIGNATURE, "Invalid super block signature"},
    {ERROR_INVALID_BLOCK_SIZE, "Invalid block size"},
    {ERROR_UNSUPPORTED_REVISION_LEVEL, "Unsupported revision level"},
    {ERROR_INVALID_INODE_SIZE, "Invalid inode size"},
    {ERROR_INODE_NOT_FOUND, "Inode not found"},
    {ERROR_UNEXPECTED_MESSAGE, "Unexpected message"},
    {ERROR_URL_TOO_LONG, "URL is too long"},
    {ERROR_QUERY_STRING_TOO_LONG, "Query string is too long"},
    {ERROR_NO_ADDRESS, "No address"},
    {ERROR_NO_BINDING, "No binding"},
    {ERROR_NOT_ON_LINK, "Not on link"},
    {ERROR_USE_MULTICAST, "Use multicast"},
    {ERROR_NAK_RECEIVED, "NAK received"},
    {ERROR_EXCEPTION_RECEIVED, "Exception received"},
    {ERROR_NO_CARRIER, "No carrier"},
    {ERROR_INVALID_LEVEL, "Invalid level"},
    {ERROR_WRONG_STATE, "Wrong state"},
    {ERROR_END_OF_STREAM, "End of stream"},
    {ERROR_LINK_DOWN, "Link down"},
    {ERROR_INVALID_OPTION_LENGTH, "Invalid option length"},
    {ERROR_IN_PROGRESS, "Operation in progress"},
    {ERROR_NO_ACK, "No acknowledgment received"},
    {ERROR_INVALID_METADATA, "Invalid metadata"},
    {ERROR_NOT_CONFIGURED, "Not configured"},
    {ERROR_ALREADY_CONFIGURED, "Already configured"},
    {ERROR_NAME_RESOLUTION_FAILED, "Name resolution failed"},
    {ERROR_NO_ROUTE, "No route to destination"},
    {ERROR_WRITE_FAILED, "Write failed"},
    {ERROR_READ_FAILED, "Read failed"},
    {ERROR_UPLOAD_FAILED, "Upload failed"},
    {ERROR_READ_ONLY_ACCESS, "Read-only access"},
    {ERROR_INVALID_SIGNATURE, "Invalid signature"},
    {ERROR_INVALID_TICKET, "Invalid ticket"},
    {ERROR_NO_TICKET, "No ticket"},
    {ERROR_BAD_RECORD_MAC, "Bad record MAC"},
    {ERROR_RECORD_OVERFLOW, "Record overflow"},
    {ERROR_HANDSHAKE_FAILED, "Handshake failed"},
    {ERROR_NO_CERTIFICATE, "No certificate"},
    {ERROR_BAD_CERTIFICATE, "Bad certificate"},
    {ERROR_UNSUPPORTED_CERTIFICATE, "Unsupported certificate"},
    {ERROR_UNKNOWN_CERTIFICATE, "Unknown certificate"},
    {ERROR_CERTIFICATE_EXPIRED, "Certificate expired"},
    {ERROR_CERTIFICATE_REVOKED, "Certificate revoked"},
    {ERROR_UNKNOWN_CA, "Unknown certificate authority"},
    {ERROR_DECODING_FAILED, "Decoding failed"},
    {ERROR_DECRYPTION_FAILED, "Decryption failed"},
    {ERROR_ILLEGAL_PARAMETER, "Illegal parameter"},
    {ERROR_MISSING_EXTENSION, "Missing extension"},
    {ERROR_UNSUPPORTED_EXTENSION, "Unsupported extension"},
    {ERROR_INAPPROPRIATE_FALLBACK, "Inappropriate fallback"},
    {ERROR_NO_APPLICATION_PROTOCOL, "No application protocol"},
    {ERROR_MORE_DATA_REQUIRED, "More data required"},
    {ERROR_TLS_NOT_SUPPORTED, "TLS not supported"},
    {ERROR_PRNG_NOT_READY, "PRNG not ready"},
    {ERROR_SERVICE_CLOSING, "Service closing"},
    {ERROR_INVALID_TIMESTAMP, "Invalid timestamp"},
    {ERROR_NO_DNS_SERVER, "No DNS server"},
    {ERROR_OBJECT_NOT_FOUND, "Object not found"},
    {ERROR_INSTANCE_NOT_FOUND, "Instance not found"},
    {ERROR_ADDRESS_NOT_FOUND, "Address not found"},
    {ERROR_UNKNOWN_IDENTITY, "Unknown identity"},
    {ERROR_UNKNOWN_ENGINE_ID, "Unknown engine ID"},
    {ERROR_UNKNOWN_USER_NAME, "Unknown user name"},
    {ERROR_UNKNOWN_CONTEXT, "Unknown context"},
    {ERROR_UNAVAILABLE_CONTEXT, "Unavailable context"},
    {ERROR_UNSUPPORTED_SECURITY_LEVEL, "Unsupported security level"},
    {ERROR_NOT_IN_TIME_WINDOW, "Not in time window"},
    {ERROR_AUTHORIZATION_FAILED, "Authorization failed"},
    {ERROR_INVALID_FUNCTION_CODE, "Invalid function code"},
    {ERROR_DEVICE_BUSY, "Device busy"},
    {ERROR_REQUEST_REJECTED, "Request rejected"},
    {ERROR_INVALID_CHANNEL, "Invalid channel"},
    {ERROR_INVALID_GROUP, "Invalid group"},
    {ERROR_UNKNOWN_SERVICE, "Unknown service"},
    {ERROR_UNKNOWN_REQUEST, "Unknown request"},
    {ERROR_FLOW_CONTROL, "Flow control"},
    {ERROR_INVALID_PASSWORD, "Invalid password"},
    {ERROR_INVALID_HANDLE, "Invalid handle"},
    {ERROR_BAD_NONCE, "Bad nonce"},
    {ERROR_UNEXPECTED_STATUS, "Unexpected status"},
    {ERROR_RESPONSE_TOO_LARGE, "Response too large"},
    {ERROR_INVALID_SESSION, "Invalid session"},
    {ERROR_TICKET_EXPIRED, "Ticket expired"},
    {ERROR_INVALID_ENTRY, "Invalid entry"},
    {ERROR_TABLE_FULL, "Table full"},
    {ERROR_END_OF_TABLE, "End of table"},
    {ERROR_ALREADY_RUNNING, "Already running"},
    {ERROR_UNKOWN_KEY, "Unkown key"},
    {ERROR_UNKNOWN_TYPE, "Unknown type"},
    {ERROR_UNSUPPORTED_OPTION, "Unsupported option"},
    {ERROR_INVALID_SPI, "Invalid spi"},
    {ERROR_RETRY, "Retry"},
    {ERROR_POLICY_FAILURE, "Policy failure"},
    {ERROR_INVALID_PROPOSAL, "Invalid proposal"},
    {ERROR_INVALID_SELECTOR, "Invalid selector"},
    {ERROR_WRONG_NONCE, "Wrong nonce"},
    {ERROR_WRONG_ISSUER, "Wrong issuer"},
    {ERROR_RESPONSE_EXPIRED, "Response expired"},
    {ERROR_CRL_EXPIRED, "Crl expired"},
    {ERROR_INVALID_CSR, "Invalid csr"},
    {ERROR_REQUEST_PENDING, "Request pending"},
    {ERROR_RESEED_REQUIRED, "Reseed required"},
    {ERROR_KEY_EXCH_FAILED, "Key exch failed"},
    {ERROR_TTL_EXCEEDED, "Ttl exceeded"},
    {ERROR_NO_MATCH, "No match"},
    {ERROR_PARTIAL_MATCH, "Partial match"},
};

char *error2text(error_t error)
{
    if (error < 0 || error >= ERROR_COUNT || !error_text[error])
    {
        return "";
    }
    return error_text[error];
}

void error_text_init()
{
    for (size_t i = 0; i < sizeof(error_texts) / sizeof(error_texts[0]); i++)
    {
        int code = error_texts[i].code;
        if (code < 0 || code >= ERROR_COUNT || error_text[code])
        {
            continue;
        }
        size_t len = strlen(error_texts[i].text) + 16;
        char *text = malloc(len);
        if (text)
        {
            snprintf(text, len, "%s [%d]", error_texts[i].text, code);
            error_text[code] = text;
        }
    }
}

const char *httpstatus2text(error_t error)
{
    switch (error)
    {
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 418:
        return "I'm a teapot";
    case 426:
        return "Upgrade Required";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Unknown HTTP Status Code";
    }
}
