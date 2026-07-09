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
#include "modules/msgid.h"
#include "channel/dnet.h"

typedef struct tcp_connect {
    uint16_t tid;
    fd_event_t fev;
    char buf[DNET_RECV_BUF_SIZE];
    int len;
    struct tcp_connect *next;
} tcp_connect_t;

static tcp_connect_t *tcp_conn_list = NULL;
static uint16_t tcp_conn_tid = 0;

static int set_option(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_CLOEXEC);
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
        bus_post_msg("tcp", "parser", MSG_TYPE_TCP_START + conn->tid, conn->len, conn->buf);
    }
}

int tcp_send(const message_t *msg)
{
    tcp_connect_t *conn = tcp_conn_list;
    uint16_t tid = msg_event(msg->msg_id);

    while(conn != NULL)
    {
        if (conn->tid == tid)
        {
            break;
        }
        conn = conn->next;
    }

    if (conn == NULL)
    {
        printf("tcp_send: tid %d not found\n", tid);
        return -1;
    }

    return send(conn->fev.fd, msg->payload, msg->payload_len, 0);

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
    conn->tid = tcp_conn_tid++;
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
    conn->next = tcp_conn_list;
    tcp_conn_list = conn;

    return true;
}