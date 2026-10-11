#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/net.h"
#include "core/socket.h"
#include "tests.h"

/* The HTTP server reads its request line with this size (HTTP_SERVER_BUFFER_SIZE - 1). */
#define LINE_READ_SIZE 32767

static const char HEAD[] = "POST /api/fileUpload HTTP/1.1\r\n"
                           "Content-Length: 100000\r\n"
                           "\r\n";

/* a socket whose peer has already sent the header plus more body than one read takes */
static Socket *socket_with_waiting_request(void)
{
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    static char request[LINE_READ_SIZE * 2];
    memset(request, 'x', sizeof(request));
    memcpy(request, HEAD, strlen(HEAD));
    assert(write(fds[1], request, sizeof(request)) == (ssize_t)sizeof(request));
    close(fds[1]);

    Socket *socket = calloc(1, sizeof(Socket));
    assert(socket != NULL);
    socket->descriptor = fds[0];
    return socket;
}

static void expect_line(Socket *socket, size_t size, const char *expected)
{
    static char line[LINE_READ_SIZE];
    size_t received = 0;
    assert(socketReceive(socket, line, size, &received, SOCKET_FLAG_BREAK_CRLF) == NO_ERROR);
    assert(received == strlen(expected));
    assert(memcmp(line, expected, received) == 0);
}

/*
 * When the first read of a connection already fills the whole buffer, the
 * line read must still end at the first line feed. Returning the full buffer
 * instead makes the request line swallow the header and the start of the body.
 */
void test_socket_receive_line_from_full_buffer(void)
{
    Socket *socket = socket_with_waiting_request();

    expect_line(socket, LINE_READ_SIZE, "POST /api/fileUpload HTTP/1.1\r\n");
    expect_line(socket, LINE_READ_SIZE, "Content-Length: 100000\r\n");
    expect_line(socket, LINE_READ_SIZE, "\r\n");

    socketClose(socket);
}

/* a buffered line end beyond the caller's size still yields only that size */
void test_socket_receive_line_capped_at_size(void)
{
    Socket *socket = socket_with_waiting_request();

    expect_line(socket, LINE_READ_SIZE, "POST /api/fileUpload HTTP/1.1\r\n");
    expect_line(socket, 10, "Content-Le");
    expect_line(socket, LINE_READ_SIZE, "ngth: 100000\r\n");

    socketClose(socket);
}
