#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "core/evloop.h"
#include "channel/uds.h"

static fd_event_t g_uds_fev;

static void uds_server_ep_callback(int fd, uint32_t events, void *arg)
{
    (void)events;
    (void)arg;
    char buf[UDS_RECV_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = recvfrom(fd, buf, sizeof(buf) - 1, 0, NULL, NULL);
    if (len < 0)
    {
        perror("receive uds message");
        return;
    }

    buf[len] = '\0';
    printf("uds receive message: %s\n", buf);

    return ;
}

int uds_init(void)
{
    memset(&g_uds_fev, 0, sizeof(g_uds_fev));
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    g_uds_fev.cb = uds_server_ep_callback;
    g_uds_fev.arg = NULL;
    g_uds_fev.fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_uds_fev.fd < 0)
    {
        perror("socket create uds");
        return -1;
    }

    unlink(UDS_PATH);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    if (bind(g_uds_fev.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind uds");
        close(g_uds_fev.fd);
        return -1;
    }

    if (evloop_add(EPOLLIN, &g_uds_fev) < 0)
    {
        printf("evloop_add failed\n");
        close(g_uds_fev.fd);
        return -1;
    }

    return 0;
}