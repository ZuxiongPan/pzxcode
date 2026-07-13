#include <stdlib.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "core/context.h"
#include "core/dchannel.h"

int dchannel_register(uint32_t events, dchannel_t *ch)
{
    if (ch == NULL)
    {
        derror("dchannel_register: channel is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&ch->dcomp);
    if (ret != Success)
    {
        derror("dchannel_register: failed to add channel[%s] to record\n",
            ch->dcomp.name == NULL ? "no name" : ch->dcomp.name);
        return Fail;
    }

    dctx_t *ctx = dctx_instance();
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = (void *)ch;

    ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ch->fd, &ev);
    if (ret != 0)
    {
        derror("dchannel_register: failed to add channel[%s] to epoll\n",
            ch->dcomp.name == NULL ? "no name" : ch->dcomp.name);
        dcomponent_record_del(&ch->dcomp);
        return Fail;
    }

    return Success;
}

void dchannel_unregister(dchannel_t *ch)
{
    if (ch == NULL)
    {
        derror("dchannel_unregister: channel is NULL\n");
        return;
    }
    
    dctx_t *ctx = dctx_instance();
    dcomponent_record_del(&ch->dcomp);
    epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, ch->fd, NULL);
}

void dchannel_handle(void *arg)
{
    dchannel_t *ch = (dchannel_t *)arg;
    if (ch == NULL)
    {
        return ;
    }

    ch->cb(ch);

    return ;
}