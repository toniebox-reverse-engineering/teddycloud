
#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "platform.h"
#include "tls.h"
#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "debug.h"

// Special IP addresses
const IpAddr IP_ADDR_ANY = {0};
const IpAddr IP_ADDR_UNSPECIFIED = {0};

typedef struct
{
    int sockfd;
    size_t buffer_used;
    size_t buffer_size;
    char *buffer;
} socket_info_t;

void platform_init()
{
}

void platform_deinit()
{
}

Socket *socketOpen(uint_t type, uint_t protocol)
{
    int ret = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (ret < 0)
    {
        return NULL;
    }
    socket_info_t *info = malloc(sizeof(socket_info_t));

    info->sockfd = ret;
    info->buffer = NULL;

    return (Socket *)info;
}

error_t socketBind(Socket *socket, const IpAddr *localIpAddr,
                   uint16_t localPort)
{
    socket_info_t *sock = (socket_info_t *)socket;
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(localPort);
    sa->sin_addr.s_addr = localIpAddr->ipv4Addr;

    int enable = 1;
    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        return ERROR_FAILURE;
    }

    int ret = bind(sock->sockfd, &addr, sizeof(addr));

    if (ret < 0)
    {
        return ERROR_FAILURE;
    }

    // printf("socketBind done %d %s\n", ret, strerror(errno));

    return NO_ERROR;
}

error_t socketListen(Socket *socket, uint_t backlog)
{
    // printf("socketListen\n");
    socket_info_t *sock = (socket_info_t *)socket;

    if (listen(sock->sockfd, backlog) < 0)
    {
        perror("listen failed\n");
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}

Socket *socketAccept(Socket *socket, IpAddr *clientIpAddr,
                     uint16_t *clientPort)
{
    socket_info_t *sock = (socket_info_t *)socket;
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);

    int ret = 0;
    do
    {
        ret = accept(sock->sockfd, &addr, &addr_len);
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

    socket_info_t *info = malloc(sizeof(socket_info_t));

    info->sockfd = ret;
    info->buffer = NULL;

    return (Socket *)info;
}

error_t socketSetTimeout(Socket *socket, systime_t timeout)
{
    socket_info_t *sock = (socket_info_t *)socket;
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv,
                   sizeof(tv)) < 0)
    {
        perror("setsockopt failed\n");
    }

    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv,
                   sizeof(tv)) < 0)
    {
        perror("setsockopt failed\n");
    }

    return NO_ERROR;
}

void socketClose(Socket *socket)
{
    socket_info_t *sock = (socket_info_t *)socket;

    if (sock->buffer)
    {
        free(sock->buffer);
        sock->buffer = NULL;
    }

    if (sock->sockfd)
    {
        close(sock->sockfd);
        sock->sockfd = 0;
    }

    free(sock);
}

error_t socketShutdown(Socket *socket, uint_t how)
{
    socket_info_t *sock = (socket_info_t *)socket;

    shutdown(sock->sockfd, how);
    return NO_ERROR;
}

error_t socketSetInterface(Socket *socket, NetInterface *interface)
{
    return NO_ERROR;
}

error_t socketConnect(Socket *socket, const IpAddr *remoteIpAddr,
                      uint16_t remotePort)
{
    socket_info_t *sock = (socket_info_t *)socket;
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(remotePort);
    sa->sin_addr.s_addr = remoteIpAddr->ipv4Addr;

    int ret = connect(sock->sockfd, &addr, sizeof(addr));

    return ret != -1 ? NO_ERROR : ERROR_ACCESS_DENIED;
}

error_t socketSend(Socket *socket, const void *data, size_t length,
                   size_t *written, uint_t flags)
{
    socket_info_t *sock = (socket_info_t *)socket;
    int_t n;
    error_t error;

    // Send data
    n = send(sock->sockfd, data, length, MSG_NOSIGNAL);

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
            error = ERROR_TIMEOUT;
        else
            error = ERROR_WRITE_FAILED;
    }

    return error;
}

error_t socketReceive(Socket *socket, void *data_in,
                      size_t size, size_t *received, uint_t flags)
{
    char *data = (char *)data_in;
    socket_info_t *sock = (socket_info_t *)socket;

    *received = 0;
    if (!size)
    {
        return NO_ERROR;
    }

    /* annoying part. the lib shall implement CRLF-breaking read. so we have to buffer data */
    if (!sock->buffer)
    {
        sock->buffer_used = 0;
        sock->buffer_size = 512;
        sock->buffer = malloc(sock->buffer_size);
    }

    do
    {
        size_t max_size = sock->buffer_size - sock->buffer_used;
        size_t return_count = 0;

        if (max_size > size)
        {
            max_size = size;
        }

        if ((flags & SOCKET_FLAG_BREAK_CHAR) && sock->buffer_used)
        {
            const char *ptr = strchr(sock->buffer, flags & 0xFF);

            if (ptr)
            {
                return_count = 1 + (intptr_t)ptr - (intptr_t)sock->buffer;
            }
            else if (!max_size)
            {
                return_count = sock->buffer_used;
            }
        }

        if (sock->buffer_used >= size)
        {
            return_count = size;
        }

        if (!(flags & SOCKET_FLAG_WAIT_ALL) && !(flags & SOCKET_FLAG_BREAK_CHAR))
        {
            if (sock->buffer_used > 0)
            {
                return_count = sock->buffer_used;
            }
        }

        /* we shall return that many bytes and have them in buffer */
        if (return_count > 0)
        {
            /* just make sure we have enough in buffer */
            if (return_count > sock->buffer_used)
            {
                return_count = sock->buffer_used;
            }

            *received = return_count;
            memcpy(data, &sock->buffer[0], return_count);
            sock->buffer_used -= return_count;
            memmove(&sock->buffer[0], &sock->buffer[return_count], sock->buffer_used);

            return NO_ERROR;
        }

        if (max_size > 0)
        {
            uint32_t posix_flags = 0;

            posix_flags |= (flags & SOCKET_FLAG_PEEK) ? MSG_PEEK : 0;
            posix_flags |= (flags & SOCKET_FLAG_WAIT_ALL) ? MSG_WAITALL : 0;

            int_t n = recv(sock->sockfd, &sock->buffer[sock->buffer_used], max_size, posix_flags);

            if (n <= 0)
            {
                /* receive failed, purge buffered content */
                if ((flags & SOCKET_FLAG_BREAK_CHAR) && sock->buffer_used)
                {
                    int copy_size = size;

                    if (copy_size > sock->buffer_used)
                    {
                        copy_size = sock->buffer_used;
                    }

                    *received = copy_size;
                    memcpy(data, sock->buffer, copy_size);
                    sock->buffer_used -= copy_size;
                    memmove(sock->buffer, &sock->buffer[copy_size], sock->buffer_used);

                    return NO_ERROR;
                }

                /* connection closed and obviously nothing left in buffer */
                if (n == 0)
                {
                    return ERROR_END_OF_STREAM;
                }

                /* would block, nothing in buffer */
                if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                {
                    return NO_ERROR;
                }

                return ERROR_CONNECTION_FAILED;
            }

            sock->buffer_used += n;
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
