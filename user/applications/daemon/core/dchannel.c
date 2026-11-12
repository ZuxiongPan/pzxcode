#include <stdlib.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "core/dcontext.h"
#include "core/dchannel.h"

int dchannel_register(uint32_t events, struct dchannel *ch)
{
    if (NULL == ch)
    {
        derror("channel to register is NULL\n");
        return Fail;
    }

    int ret = dcomp_record_add(&ch->comp);
    if (unlikely(ret != Success))
    {
        derror("failed to add channel[%s] to record\n",
            ch->comp.name == NULL ? "no name" : ch->comp.name);
        return Fail;
    }

    struct dctx *ctx = dctx_instance();
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = (void *)ch;

    ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ch->fd, &ev);
    if (ret != 0)
    {
        derror("failed to add channel[%s] to epoll\n",
            ch->comp.name == NULL ? "no name" : ch->comp.name);
        dcomp_record_del(&ch->comp);
        return Fail;
    }

    return Success;
}

void dchannel_unregister(struct dchannel *ch)
{
    if (NULL == ch)
    {
        return ;
    }

    dcomp_record_del(&ch->comp);
    struct dctx *ctx = dctx_instance();
    epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, ch->fd, NULL);

    return ;
}
