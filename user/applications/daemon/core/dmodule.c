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

    int ret = dcomponent_record_add(&mod->dcomp);
    if (ret != Success)
    {
        derror("failed to add mod[%s] to record\n",
            mod->dcomp.name == NULL ? "no name" : mod->dcomp.name);
        return Fail;
    }
    dprint("module[%s] id[0x%x]\n", mod->dcomp.name ? mod->dcomp.name : "no name", mod->dcomp.dcompid);

    return Success;
}

void dmodule_unregister(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("mod is NULL\n");
        return;
    }
    
    dcomponent_record_del(&mod->dcomp);
}

int dmodule_handle(int src_compid, int dst_compid, unsigned int msgid, void *data)
{
    int ret = Success;
    dcomp_t *dst = find_dcomponent_by_id(dst_compid);
    if (NULL != dst)
    {
        dmod_t *mod = (dmod_t *)dst;
        if (NULL != mod->ops->ontask)
        {
            ret = mod->ops->ontask(mod, src_compid, msgid, data);
            (void)ret;
            // dprint("dmodule_handle ret %d\n", ret);
        }
    }

    return ret;
}
