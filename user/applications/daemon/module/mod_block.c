#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "module/dmsgid.h"
#include "module/mod_data.h"

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

static int blkmod_onmsg(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("blk_onmsg: invalid task\n");
        return Fail;
    }

    dtask_t *task = (dtask_t *)arg;
    blk_info_t *info = (blk_info_t *)task->data;
    dprint("receive task from %d\n", task->src_compid);

    switch (task->msgid)
    {
        case MSGID_BLKDEV_ADD:
            dprint("add a new block %s\n", info->blkdev_name);
            break;
        case MSGID_BLKDEV_REMOVE:
            dprint("remove block %s\n", info->blkdev_name);
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

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
    dcomponent_init(&blkmod.dcomp, ModuleIDBlock, "mod_block");
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