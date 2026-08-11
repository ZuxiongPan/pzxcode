#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dproto.h"
#include "core/dworker.h"

int dproto_register(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("proto is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&proto->dcomp, Layer_Proto);
    if (ret != Success)
    {
        derror("failed to add proto[%s] to record\n",
            proto->dcomp.name == NULL ? "no name" : proto->dcomp.name);
        return Fail;
    }
    dprint("proto[%s] id[0x%x]\n", proto->dcomp.name ? proto->dcomp.name : "no name", proto->dcomp.dcomp_id);

    return Success;
}

void dproto_unregister(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("proto is NULL\n");
        return;
    }
    
    dcomponent_record_del(&proto->dcomp, Layer_Proto);
}

int dproto_handle(void *arg)
{
    int ret = Success;
    dtask_t *task = (dtask_t *)arg;
    const dcomp_t *comp = find_dcomponent_by_id(task->dst_compid, Layer_Proto);
    if (comp == NULL)
    {
        derror("failed to find proto[%d] in record\n", task->dst_compid);
        return Fail;
    }

    dproto_t *proto = (dproto_t *)comp;
    if (task->type == TaskDecode && proto->ops->decode != NULL)
    {
        ret = proto->ops->decode(proto, task);
        if (ret != Success)
        {
            derror("failed to decode proto[%s]\n", comp->name ? comp->name : "no name");
        }
    }
    else if (task->type == TaskEncode && proto->ops->encode != NULL)
    {
        // todo
    }

    return ret;
}
