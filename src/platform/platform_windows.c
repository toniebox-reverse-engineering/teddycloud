

/* prevents conflicts due to multiple definitions */
#define _WINERROR_

#include <locale.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>

#include <time.h>

#include "platform.h"
#include "tls.h"
#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "debug.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

const IpAddr IP_ADDR_ANY = {0};
const IpAddr IP_ADDR_UNSPECIFIED = {0};

typedef struct
{
    size_t buffer_used;
    size_t buffer_size;
    char *buffer;
} socket_buffer_t;

void platform_init()
{
    WSADATA wsaData;
    HCRYPTPROV hProvider;

    // Winsock initialization
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    // Any error to report?
    if (ret)
    {
        // Debug message
        TRACE_ERROR("Error: Winsock initialization failed (%d)\r\n", ret);
        // Exit immediately
        return;
    }
    setlocale(LC_ALL, ".UTF8");
}

void platform_deinit()
{
}

size_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    int_t ret;
    HCRYPTPROV hProvider;

    // Acquire cryptographic context
    ret = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Cannot acquire cryptographic context (%d)\r\n", GetLastError());
        // Exit immediately
        return -1;
    }

    // Generate a random seed
    ret = CryptGenRandom(hProvider, buflen, buf);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", GetLastError());
        // Exit immediately
        return -1;
    }

    // Release cryptographic context
    CryptReleaseContext(hProvider, 0);

    return 0;
}

Socket *socketOpen(uint_t type, uint_t protocol)
{
    int ret = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (ret < 0)
    {
        return NULL;
    }
    Socket *info = osAllocMem(sizeof(Socket));

    info->descriptor = ret;
    info->interface = NULL;

    return info;
}

error_t socketBind(Socket *socket, const IpAddr *localIpAddr,
                   uint16_t localPort)
{
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(localPort);
    sa->sin_addr.s_addr = localIpAddr->ipv4Addr;

    int enable = 1;
    if (setsockopt(socket->descriptor, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        return ERROR_FAILURE;
    }

    int ret = bind(socket->descriptor, &addr, sizeof(addr));

    if (ret < 0)
    {
        return ERROR_FAILURE;
    }

    // printf("socketBind done %d %s\n", ret, strerror(errno));

    return NO_ERROR;
}

error_t socketListen(Socket *socket, uint_t backlog)
{
    if (listen(socket->descriptor, backlog) < 0)
    {
        perror("listen failed\n");
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}

Socket *socketAccept(Socket *socket, IpAddr *clientIpAddr,
                     uint16_t *clientPort)
{
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);

    int ret = 0;
    do
    {
        ret = accept(socket->descriptor, &addr, &addr_len);
        if (ret < 0)
        {
            if (errno != EINTR)
            {
                perror("accept failed\n");
            }
            return NULL;
        }
    } while (0);

    struct sockaddr_in *sa = (struct sockaddr_in *)&addr;

    *clientPort = sa->sin_port;
    clientIpAddr->ipv4Addr = sa->sin_addr.s_addr;
    clientIpAddr->length = sizeof(clientIpAddr->ipv4Addr);

    Socket *newsock = osAllocMem(sizeof(Socket));

    newsock->descriptor = ret;
    newsock->interface = NULL;

    return newsock;
}

error_t socketSetTimeout(Socket *socket, systime_t timeout)
{
    int timeout_ms = (int)timeout;

    if (setsockopt(socket->descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout_ms, sizeof(int)) < 0)
    {
        int errCode = WSAGetLastError();
        TRACE_ERROR("setsockopt() for SO_RCVTIMEO failed with errorcode %d\r\n", errCode);
    }

    if (setsockopt(socket->descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout_ms, sizeof(int)) < 0)
    {
        int errCode = WSAGetLastError();
        TRACE_ERROR("setsockopt() for SO_SNDTIMEO failed with errorcode %d\r\n", errCode);
    }

    socket->timeout = timeout;

    return NO_ERROR;
}

void socketClose(Socket *socket)
{
    if (socket->descriptor)
    {
        closesocket(socket->descriptor);
        socket->descriptor = 0;
    }

    free(socket);
}

error_t socketShutdown(Socket *socket, uint_t how)
{
    shutdown(socket->descriptor, how);
    return NO_ERROR;
}

error_t socketSetInterface(Socket *socket, NetInterface *interface)
{
    return NO_ERROR;
}

error_t socketConnect(Socket *socket, const IpAddr *remoteIpAddr,
                      uint16_t remotePort)
{
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(remotePort);
    sa->sin_addr.s_addr = remoteIpAddr->ipv4Addr;

    int ret = connect(socket->descriptor, &addr, sizeof(addr));

    return ret != -1 ? NO_ERROR : ERROR_ACCESS_DENIED;
}

error_t socketSend(Socket *socket, const void *data, size_t length,
                   size_t *written, uint_t flags)
{
    int_t n;
    error_t error;

    /* this is meant as a flush. not needed/possible? */
    if (!length)
    {
        return NO_ERROR;
    }
    // Send data
    n = send(socket->descriptor, data, length, 0);

    // Check return value
    if (n > 0)
    {
        // Total number of data that have been written
        if (written)
        {
            *written = n;
        }
        // Successful write operation
        error = NO_ERROR;
    }
    else
    {
        // Timeout error?
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            error = ERROR_TIMEOUT;
        }
        else
        {
            error = ERROR_WRITE_FAILED;
        }
    }

    return error;
}

error_t socketReceive(Socket *socket, void *data_in,
                      size_t size, size_t *received, uint_t flags)
{
    char *data = (char *)data_in;

    *received = 0;
    if (!size)
    {
        return NO_ERROR;
    }

    /* annoying part. the lib shall implement CRLF-breaking read. so we have to buffer data somewhere */
    socket_buffer_t *buff = (socket_buffer_t *)socket->interface;
    if (!buff)
    {
        buff = osAllocMem(sizeof(socket_buffer_t));
        buff->buffer_used = 0;
        buff->buffer_size = 512;
        buff->buffer = osAllocMem(buff->buffer_size);
        socket->interface = (NetInterface *)buff;
    }

    do
    {
        size_t max_size = buff->buffer_size - buff->buffer_used;
        size_t return_count = 0;

        if (max_size > size)
        {
            max_size = size;
        }

        if ((flags & SOCKET_FLAG_BREAK_CHAR) && buff->buffer_used)
        {
            /* warning: searches outside buffer if binary */
            const char *ptr = strchr(buff->buffer, flags & 0xFF);

            if (ptr)
            {
                return_count = 1 + (intptr_t)ptr - (intptr_t)buff->buffer;
            }
            else if (!max_size)
            {
                return_count = buff->buffer_used;
            }
        }

        if (buff->buffer_used >= size)
        {
            return_count = size;
        }

        if (!(flags & SOCKET_FLAG_WAIT_ALL) && !(flags & SOCKET_FLAG_BREAK_CHAR))
        {
            if (buff->buffer_used > 0)
            {
                return_count = buff->buffer_used;
            }
        }

        /* we shall return that many bytes and have them in buffer */
        if (return_count > 0)
        {
            /* just make sure we have enough in buffer */
            if (return_count > buff->buffer_used)
            {
                return_count = buff->buffer_used;
            }

            *received = return_count;
            memcpy(data, &buff->buffer[0], return_count);
            buff->buffer_used -= return_count;
            memmove(&buff->buffer[0], &buff->buffer[return_count], buff->buffer_used);

            return NO_ERROR;
        }

        if (max_size > 0)
        {
            uint32_t posix_flags = 0;

            posix_flags |= (flags & SOCKET_FLAG_PEEK) ? MSG_PEEK : 0;
            posix_flags |= (flags & SOCKET_FLAG_WAIT_ALL) ? MSG_WAITALL : 0;

            int_t n = recv(socket->descriptor, &buff->buffer[buff->buffer_used], max_size, posix_flags);

            if (n <= 0)
            {
                /* receive failed, purge buffered content */
                if ((flags & SOCKET_FLAG_BREAK_CHAR) && buff->buffer_used)
                {
                    int copy_size = size;

                    if (copy_size > buff->buffer_used)
                    {
                        copy_size = buff->buffer_used;
                    }

                    *received = copy_size;
                    memcpy(data, buff->buffer, copy_size);
                    buff->buffer_used -= copy_size;
                    memmove(buff->buffer, &buff->buffer[copy_size], buff->buffer_used);

                    return NO_ERROR;
                }

                /* connection closed and obviously nothing left in buffer */
                if (n == 0)
                {
                    return ERROR_END_OF_STREAM;
                }

                int err = WSAGetLastError();
                /* would block, nothing in buffer */
                if (err == EWOULDBLOCK || err == EAGAIN || err == WSAETIMEDOUT)
                {
                    return ERROR_TIMEOUT;
                }

                return ERROR_CONNECTION_FAILED;
            }

            buff->buffer_used += n;
        }
    } while (1);
}

void *resolve_host(const char *hostname)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
    {
        TRACE_ERROR("getaddrinfo %s\n", gai_strerror(status));
        return NULL;
    }

    return res;
}

bool resolve_get_ip(void *ctx, int pos, IpAddr *ipAddr)
{
    struct addrinfo *res = (struct addrinfo *)ctx;
    struct addrinfo *p = res;

    while (p)
    {
        if (!pos)
        {
            if (p->ai_family == AF_INET)
            {
                // ai_addr is a pointer to a sockaddr, which we know is a sockaddr_in because ai_family == AF_INET.
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                memcpy(&ipAddr->ipv4Addr, &(ipv4->sin_addr), sizeof(struct in_addr));
                return true;
            }
            // Handle the case of an IPv6 address
            else if (p->ai_family == AF_INET6)
            {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                memcpy(&ipAddr->ipv6Addr, &(ipv6->sin6_addr), sizeof(struct in6_addr));
                return true;
            }
        }
        pos--;
        p = p->ai_next;
    }
    return false;
}

void resolve_free(void *res)
{
    freeaddrinfo(res);
}

struct tm *localtime_r(const time_t *timer, struct tm *result)
{
    if (localtime_s(result, timer) == 0)
        return result;
    else
        return NULL;
}

/**
 * @brief Wait for a particular TCP event
 * @param[in] socket Handle referencing the socket
 * @param[in] eventMask Logic OR of all the TCP events that will complete the wait
 * @param[in] timeout Maximum time to wait
 * @return Logic OR of all the TCP events that satisfied the wait
 **/

uint_t tcpWaitForEvents(Socket *socket, uint_t eventMask, systime_t timeout)
{
    fd_set read_fds;
    struct timeval tv;

    if (socket == NULL)
        return 0;

    // Initialize the file descriptor set.
    FD_ZERO(&read_fds);
    FD_SET(socket->descriptor, &read_fds);

    // Set timeout.
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    // Wait for the event.
    int result = select(socket->descriptor + 1, &read_fds, NULL, NULL, &tv);

    // Check if socket is ready for reading.
    if (result > 0 && FD_ISSET(socket->descriptor, &read_fds))
    {
        return eventMask;
    }

    return 0;
}