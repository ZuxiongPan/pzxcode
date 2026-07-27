#include <stdlib.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dchannel.h"

int dchannel_register(uint32_t events, dchannel_t *chnl)
{
    if (chnl == NULL)
    {
        derror("dchannel_register: channel is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&chnl->dcomp, Layer_Channel);
    if (ret != Success)
    {
        derror("dchannel_register: failed to add channel[%s] to record\n",
            chnl->dcomp.name == NULL ? "no name" : chnl->dcomp.name);
        return Fail;
    }
    dprint("dchannel_register: channel[%s] id[0x%x]\n", chnl->dcomp.name ? chnl->dcomp.name : "no name", chnl->dcomp.dcomp_id);

    dctx_t *ctx = dctx_instance();
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = (void *)chnl;

    ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, chnl->fd, &ev);
    if (ret != 0)
    {
        derror("dchannel_register: failed to add channel[%s] to epoll\n",
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
        derror("dchannel_unregister: channel is NULL\n");
        return;
    }
    
    dctx_t *ctx = dctx_instance();
    dcomponent_record_del(&chnl->dcomp, Layer_Channel);
    epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, chnl->fd, NULL);
}

void dchannel_create_task(dchannel_t *chnl, unsigned int data_size, const char *data)
{
    if (chnl == NULL || data == NULL)
    {
        derror("dchannel_create_task: channel/data is invalid\n");
        return ;
    }
    
    int ret = Success;
    const dpdata_t *pdata = (dpdata_t *)data;
    ret = task_enqueue(TaskCodec, chnl->dcomp.dcomp_id, DCOMPID_NONE,
        0, data_size, (char *)pdata);
    
    dprint("dchannel_create_task: ret = %d\n", ret);
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
