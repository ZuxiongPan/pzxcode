#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dmodule.h"
#include "core/dworker.h"

int dmodule_register(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("mod is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&mod->dcomp, Layer_Module);
    if (ret != Success)
    {
        derror("failed to add mod[%s] to record\n",
            mod->dcomp.name == NULL ? "no name" : mod->dcomp.name);
        return Fail;
    }
    dprint("module[%s] id[0x%x]\n", mod->dcomp.name ? mod->dcomp.name : "no name", mod->dcomp.dcomp_id);

    return Success;
}

void dmodule_unregister(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("mod is NULL\n");
        return;
    }
    
    dcomponent_record_del(&mod->dcomp, Layer_Module);
}

int dmodule_handle(void *arg)
{
    int ret = Success;
    dtask_t *task = (dtask_t *)arg;
    dcomp_t *dst = find_dcomponent_by_id(task->dst_compid, Layer_Module);
    if (NULL != dst)
    {
        dmod_t *mod = (dmod_t *)dst;
        if (NULL != mod->ops->ontask)
        {
            ret = mod->ops->ontask(mod, task);
            //dprint("dmodule_handle ret %d\n", ret);
        }
    }

    return ret;
}
