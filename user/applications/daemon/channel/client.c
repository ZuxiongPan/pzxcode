#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "core/evloop.h"
#include "core/bus.h"
#include "channel/tcp.h"

typedef struct tcp_connect {
    fd_event_t fev;
    char buf[TCP_RECV_BUF_SIZE];
    int len;
} tcp_connect_t;

static int set_option(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_CLOEXEC);
}

static void http_send(int fd, const char *body)
{
    char resp[1024];

    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(body),
        body);

    send(fd, resp, len, 0);
}

static void http_handle_request(int fd, const char *req)
{
    if (strncmp(req, "GET /cpu", 8) == 0)
    {
        http_send(fd, "cpu: 12%");
    }
    else if (strncmp(req, "GET /mem", 8) == 0)
    {
        http_send(fd, "mem: 45%");
    }
    else if (strncmp(req, "GET /", 5) == 0)
    {
        http_send(fd, "armd http server running");
    }
    else
    {
        http_send(fd, "404 not found");
    }
}

static void tcp_client_cb(int fd, uint32_t events, void *arg)
{
    (void)events;
    tcp_connect_t *conn = (tcp_connect_t *)arg;

    while (1)
    {
        ssize_t n = recv(fd, conn->buf + conn->len,
            sizeof(conn->buf) - conn->len - 1, 0);

        if (n <= 0)
        {
            if (errno == EAGAIN)
            {
                break;
            }
            close(fd);
            free(conn);
            return ;
        }

        conn->len += n;
        conn->buf[conn->len] = '\0';

        if (strstr(conn->buf, "\r\n\r\n"))
        {
            printf("HTTP REQ:\n%s\n", conn->buf);

            http_handle_request(fd, conn->buf);

            close(fd);
            free(conn);
            return ;
        }
    }
}

bool tcp_add_new_client(int fd)
{
    // fd is checked before, so fd is always valid
    tcp_connect_t *conn = malloc(sizeof(tcp_connect_t));
    if (conn == NULL)
    {
        printf("malloc tcp_connect_t failed\n");
        return false;
    }

    set_option(fd);
    conn->fev.fd = fd;
    conn->fev.cb = tcp_client_cb;
    conn->fev.arg = conn;
    conn->len = 0;

    if (evloop_add(EPOLLIN | EPOLLET, &conn->fev) < 0)
    {
        printf("evloop_add failed\n");
        free(conn);
        return false;
    }

    return true;
}