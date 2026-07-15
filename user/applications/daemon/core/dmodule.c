#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "core/dcontext.h"
#include "core/dmodule.h"

int dmodule_register(dmod_t *mod)
{
    if (mod == NULL)
    {
        derror("dmodule_register: mod is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&mod->dcomp);
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
    
    dcomponent_record_del(&mod->dcomp);
}
