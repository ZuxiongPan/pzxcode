#include <stdlib.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dchannel.h"

int dchannel_register(uint32_t events, dchannel_t *chnl)
{
    if (chnl == NULL)
    {
        derror("channel is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&chnl->dcomp, Layer_Channel);
    if (ret != Success)
    {
        derror("failed to add channel[%s] to record\n",
            chnl->dcomp.name == NULL ? "no name" : chnl->dcomp.name);
        return Fail;
    }
    dprint("channel[%s] id[0x%x]\n", chnl->dcomp.name ? chnl->dcomp.name : "no name", chnl->dcomp.dcomp_id);

    dctx_t *ctx = dctx_instance();
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = (void *)chnl;

    ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, chnl->fd, &ev);
    if (ret != 0)
    {
        derror("failed to add channel[%s] to epoll\n",
            chnl->dcomp.name == NULL ? "no name" : chnl->dcomp.name);
        dcomponent_record_del(&chnl->dcomp, Layer_Channel);
        return Fail;
    }

    return Success;
}

void dchannel_unregister(dchannel_t *chnl)
{
    if (chnl == NULL)
    {
        derror("channel is NULL\n");
        return;
    }
    
    dctx_t *ctx = dctx_instance();
    dcomponent_record_del(&chnl->dcomp, Layer_Channel);
    epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, chnl->fd, NULL);
}

void dchannel_handle(void *arg)
{
    dchannel_t *chnl = (dchannel_t *)arg;
    if (chnl == NULL)
    {
        return ;
    }

    chnl->ops->callback(chnl);

    return ;
}

int dchannel_write_to_outer(void *arg)
{
    int ret = Success;
    dtask_t *task = (dtask_t *)arg;
    if (task == NULL)
    {
        derror("task is NULL\n");
        return Fail;
    }
    
    dcomp_t *dst = find_dcomponent_by_id(task->dst_compid, Layer_Channel);
    if (NULL != dst)
    {
        dchannel_t *chnl = (dchannel_t *)dst;
        if (NULL != chnl->ops->write_to_outer)
        {
            ret = chnl->ops->write_to_outer(task);
        }
    }
    else
    {
        derror("dst is NULL\n");
        ret = Fail;
    }

    return ret;
}