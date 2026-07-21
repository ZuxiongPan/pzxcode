#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"

static dmod_t blkmod;

static int blkmod_start(dmod_t *m)
{
    (void)m;
    dprint("block module started\n");

    return Success;
}

static void blkmod_stop(dmod_t *m)
{
    (void)m;
    dprint("block module stopped\n");

    return ;
}

static int blkmod_onmsg(dmod_t *m, const dmsg_t *msg)
{

    return Success;
}

static const mod_ops_t blkmod_ops = {
    .start = blkmod_start,
    .stop = blkmod_stop,
    .onmsg = blkmod_onmsg,
};

int blkmod_init(void)
{
    int ret = Success;
    memset(&blkmod, 0, sizeof(dmod_t));
    dcomponent_init(&blkmod.dcomp, dmodule_get_name(ModBlock));
    blkmod.ops = &blkmod_ops;

    ret = dmodule_register(&blkmod);
    if (ret != Success)
    {
        derror("blkmod_init: block module register failed\n");
        return Fail;
    }

    dprint("blkmod_init: ret = %d\n", ret);
    return ret;
}

void blkmod_exit(void)
{
    dmodule_unregister(&blkmod);
    dprint("blkmod_exit: block module unregister done\n");
}