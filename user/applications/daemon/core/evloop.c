#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/epoll.h>

#include "core/evloop.h"

typedef struct fd_event {
    int fd;
    fd_event_f cb;
    void *arg;
} fd_event_t;

static int g_epfd = -1;
static volatile bool g_running = false;

int evloop_init(void)
{
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0)
    {
        perror("epoll_create1");
    }

    return g_epfd < 0 ? -1 : 0;
}

int evloop_add(int fd, uint32_t events, fd_event_f cb, void *arg)
{
    struct epoll_event ev;
    fd_event_t *fev = calloc(1, sizeof(fd_event_t));
    if (fev == NULL)
    {
        return -1;
    }
    fev->fd = fd;
    fev->cb = cb;
    fev->arg = arg;

    ev.events = events;
    ev.data.ptr = (void *)fev;
    return epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev);
}

int evloop_mod(int fd, uint32_t events)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;
    return epoll_ctl(g_epfd, EPOLL_CTL_MOD, fd, &ev);
}

int evloop_del(int fd)
{
    return epoll_ctl(g_epfd, EPOLL_CTL_DEL, fd, NULL);
}

int evloop_run(void)
{
    struct epoll_event events[MAX_EPOLL_EVENTS];
    g_running = true;

    while (g_running)
    {
        int nfds = epoll_wait(g_epfd, events, MAX_EPOLL_EVENTS, -1);
        if (nfds < 0)
        {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < nfds; i++)
        {
            fd_event_t *fev = (fd_event_t *)events[i].data.ptr;
            if (fev == NULL)
            {
                continue;
            }
            fev->cb(fev->fd, events[i].events, fev->arg);
        }
    }

    return 0;
}

int evloop_stop(void)
{
    g_running = false;
    return 0;
}
