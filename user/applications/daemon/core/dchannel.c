#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dcommon.h"
#include "core/context.h"
#include "core/evloop.h"

int evloop_add(uint32_t events, fd_event_t *fev)
{
    if (fev == NULL)
    {
        return Fail;
    }

    struct epoll_event ev;
    dctx_t *ctx = dctx_instance();
    ev.events = events;
    ev.data.ptr = (void *)fev;
    return epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, fev->fd, &ev);
}

int evloop_del(fd_event_t *fev)
{
    if (fev == NULL)
    {
        return Fail;
    }

    
    dctx_t *ctx = dctx_instance();
    return epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, fev->fd, NULL);
}

int evloop_run(void)
{
    struct epoll_event events[EPOLL_EVENTS];
    dctx_t *ctx = dctx_instance();

    while (atomic_load(&ctx->status))
    {
        int nfds = epoll_wait(ctx->epfd, events, EPOLL_EVENTS, -1);
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
