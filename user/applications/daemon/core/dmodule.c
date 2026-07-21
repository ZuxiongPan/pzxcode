#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dmodule.h"
#include "core/dworker.h"

static const char *dmodule_name[] = {
    [ModUnused] = "unused",
    [ModBlock] = "dblock",
};

const char *dmodule_get_name(dmod_id_e modid)
{
    if (modid >= ModInvalid)
    {
        derror("dmodule_get_name: invalid mod id\n");
        modid = ModInvalid;
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
    dprint("dmodule_register: module[%s] id[0x%x]\n", mod->dcomp.name ? mod->dcomp.name : "no name", mod->dcomp.dcomp_id);

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
    dmsg_t *msg = (dmsg_t *)task->data;

    return ret;
}
