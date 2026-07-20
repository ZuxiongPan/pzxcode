#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "core/dcontext.h"
#include "core/dmodule.h"

static const char *dmodule_name[] = {
    [ModUnused] = "unused",
    [ModBlock] = "dblock",
};

const char *dmodule_get_name(dmod_id_e modid)
{
    if (proto >= ModInvalid)
    {
        derror("dmodule_get_name: invalid mod id\n");
        proto = ModInvalid;
    }
    
    return dmodule_name[modid];
}

int dmodule_register(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("dmodule_register: mod is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&mod->dcomp, Layer_Module);
    if (ret != Success)
    {
        derror("dmodule_register: failed to add mod[%s] to record\n",
            mod->dcomp.name == NULL ? "no name" : mod->dcomp.name);
        return Fail;
    }

    return Success;
}

void dmodule_unregister(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("dmodule_unregister: mod is NULL\n");
        return;
    }
    
    dcomponent_record_del(&mod->dcomp, Layer_Module);
}

int dmodule_handle(void *arg)
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
