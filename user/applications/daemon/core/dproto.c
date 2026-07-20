#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dproto.h"
#include "core/dworker.h"

static const char *dproto_name[] = {
    [ProtoUnused] = "unused",
    [ProtoUevent] = "duevent",
};

const char *dproto_get_name(dproto_type_e proto)
{
    if (proto >= ProtoInvalid)
    {
        derror("dproto_get_name: invalid proto type\n");
        proto = ProtoUnused;
    }
    
    return dproto_name[proto];
}

int dproto_register(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("dproto_register: proto is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&proto->dcomp, Layer_Proto);
    if (ret != Success)
    {
        derror("dproto_register: failed to add proto[%s] to record\n",
            proto->dcomp.name == NULL ? "no name" : proto->dcomp.name);
        return Fail;
    }
    dprint("dproto_register: proto[%s] id[0x%x]\n", proto->dcomp.name ? proto->dcomp.name : "no name", proto->dcomp.dcomp_id);

    return Success;
}

void dproto_unregister(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("dproto_unregister: proto is NULL\n");
        return;
    }
    
    dcomponent_record_del(&proto->dcomp, Layer_Proto);
}

int dproto_handle(void *arg)
{
    int ret = Success;
    char buf[TASK_DATA_MAXSIZE];
    dtask_t *task = (dtask_t *)arg;
    dpdata_t *pdata = (dpdata_t *)task->data;
    const char *proto_name = dproto_get_name(pdata->type);
    dcomp_t *comp = find_dcomponent_by_name(proto_name, Layer_Proto);
    if (comp == NULL)
    {
        derror("dproto_handle: failed to find proto[%s] in record\n", proto_name);
        return Fail;
    }

    dproto_t *proto = (dproto_t *)comp;
    proto->task_tmp = task;
    if (pdata->op == PROTO_OP_DECODE && proto->ops->decode != NULL)
    {
        ret = proto->ops->decode(proto, buf, TASK_DATA_MAXSIZE, pdata);
        if (ret != Success)
        {
            derror("dproto_handle: failed to decode proto[%s]\n", proto_name);
        }
        else
        {
            ret = task_enqueue(TaskInform, comp->dcomp_id, DCOMPID_NONE, TASK_DATA_MAXSIZE, buf);
            dprint("dproto_handle: enqueue inform task ret = %d\n", ret);
        }
    }
    else if (pdata->op == PROTO_OP_ENCODE && proto->ops->encode != NULL)
    {
        // todo
    }
    proto->task_tmp = NULL;

    return ret;
}
