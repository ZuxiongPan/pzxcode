#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dproto.h"

int dproto_register(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("dproto_register: proto is NULL\n");
        return Fail;
    }

    int ret = dcomponent_record_add(&proto->dcomp);
    if (ret != Success)
    {
        derror("dproto_register: failed to add proto[%s] to record\n",
            proto->dcomp.name == NULL ? "no name" : proto->dcomp.name);
        return Fail;
    }

    return Success;
}

void dproto_unregister(dproto_t *proto)
{
    if (proto == NULL)
    {
        derror("dproto_unregister: proto is NULL\n");
        return;
    }
    
    dcomponent_record_del(&proto->dcomp);
}
