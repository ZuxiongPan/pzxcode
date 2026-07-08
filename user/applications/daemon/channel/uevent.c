#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "common.h"
#include "core/bus.h"
#include "core/evloop.h"
#include "modules/msgid.h"
#include "channel/uevent.h"

static fd_event_t g_uevent_fev;

static void uevent_ep_callback(int fd, uint32_t events, void *arg)
{
    char buf[UEVENT_RECV_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = 0;
    int batch = 0;

    (void)events;
    (void)arg;

    while (batch < NET_MSG_MAX_BATCH)
    {
        len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("uevent message is empty, recv batch: %d\n", batch);
                break;
            }

            perror("receive uevent message");
            return;
        }
        bus_post_msg("uevent", "parser", MSG_UEVENT, len, buf);
        batch++;
    }
}

int uevent_init(void)
{
    struct sockaddr_nl addr;

    memset(&addr, 0, sizeof(addr));
    memset(&g_uevent_fev, 0, sizeof(fd_event_t));
    g_uevent_fev.cb = uevent_ep_callback;
    g_uevent_fev.arg = NULL;
    g_uevent_fev.fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_KOBJECT_UEVENT);
    if (g_uevent_fev.fd < 0)
    {
        perror("socket create uevent");
        return -1;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 1;
    if (bind(g_uevent_fev.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind uevent");
        close(g_uevent_fev.fd);
        return -1;
    }

    if (evloop_add(EPOLLIN, &g_uevent_fev) < 0)
    {
        printf("evloop_add failed\n");
        close(g_uevent_fev.fd);
        return -1;
    }

    return 0;
}
