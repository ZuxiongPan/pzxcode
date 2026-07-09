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
#include "channel/dnet.h"

static fd_event_t g_server_fev;

static void tcp_server_cb(int fd, uint32_t events, void *arg)
{
    (void)events;
    (void)arg;
    int client_fd = -1;

    while (1)
    {
        client_fd = accept(fd, NULL, NULL);

        if (client_fd < 0)
        {
            if (errno == EAGAIN)
            {
                break;
            }
            return ;
        }

        if (!tcp_add_new_client(client_fd))
        {
            close(client_fd);
            continue;
        }
    }
}

int tcp_init(void)
{
    memset(&g_server_fev, 0, sizeof(g_server_fev));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    g_server_fev.cb = tcp_server_cb;
    g_server_fev.arg = NULL;
    g_server_fev.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_server_fev.fd < 0)
    {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_server_fev.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(TCP_PORT);

    if (bind(g_server_fev.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind server");
        close(g_server_fev.fd);
        return -1;
    }

    if (listen(g_server_fev.fd, TCP_MAX_CONNECT) < 0)
    {
        perror("listen clients");
        close(g_server_fev.fd);
        return -1;
    }

    if (evloop_add(EPOLLIN, &g_server_fev) < 0)
    {
        printf("evloop_add failed\n");
        close(g_server_fev.fd);
        return -1;
    }

    return 0;
}