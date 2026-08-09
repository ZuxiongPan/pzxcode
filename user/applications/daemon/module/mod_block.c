#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "module/dmsgid.h"
#include "module/mod_data.h"
#include "proto/proto_api.h"

static dmod_t blkmod;

static int blkdev_handle_add(const dtask_t *task)
{
    int ret = Success;
    const blk_info_t *info = (const blk_info_t *)task->data;
    if (NULL == info)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    dprint("add a new block %s\n", info->blkdev_name);

    return ret;
}

static int blkdev_handle_remove(const dtask_t *task)
{
    int ret = Success;
    const blk_info_t *info = (const blk_info_t *)task->data;
    if (NULL == info)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    dprint("remove block %s\n", info->blkdev_name);

    return ret;
}

static int blkdev_handle_json(const dtask_t *task)
{
    int ret = Success;
    const dproto_data_t *data = (const dproto_data_t *)task->data;
    if (NULL == data)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    dprint("json request: %s\n", data->json_data);

    return ret;
}

static int blkmod_onmsg(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Fail;
    dtask_t *task = (dtask_t *)arg;

    switch (task->msgid)
    {
        case MSGID_BLKDEV_ADD:
            ret = blkdev_handle_add(task);
            break;
        case MSGID_BLKDEV_REMOVE:
            ret = blkdev_handle_remove(task);
            break;
        case MSGID_JSON_RAWSTR:
            ret = blkdev_handle_json(task);
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t blkmod_ops = {
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
        derror("block module register failed\n");
        return Fail;
    }

    dprint("blkmod_init ret = %d\n", ret);
    return ret;
}

void blkmod_exit(void)
{
    dmodule_unregister(&blkmod);
    dprint("block module unregister done\n");
}