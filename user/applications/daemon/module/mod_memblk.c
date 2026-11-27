#include <string.h>

#include "dlog.h"
#include "dmsgid.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"

static struct dcomp memblkmod;

static int memblk_genl_add_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(comp);
    UNUSED(srcid);
    if (unlikely(data_size == 0 || data == NULL))
    {
        derror("invalid data size or data\n");
        return Fail;
    }

    dprint("add: data[%s]\n", data);

    return Success;
}

static int memblk_genl_remove_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(comp);
    UNUSED(srcid);
    if (unlikely(data_size == 0 || data == NULL))
    {
        derror("invalid data size or data\n");
        return Fail;
    }

    dprint("remove: data[%s]\n", data);

    return Success;
}

static const struct msg_handler memblk_handlers[] = {
    {.name = "generic-netlink", .msgid = MSGID_GENL_ACT_ADD, .func = memblk_genl_add_handler },
    {.name = "generic-netlink", .msgid = MSGID_GENL_ACT_REMOVE, .func = memblk_genl_remove_handler },
};

static int memblkmod_init(void)
{
    int ret = Success;

    memset(&memblkmod, 0, sizeof(memblkmod));
    dcomp_init(&memblkmod, ModMemblkName, ModMemblkId);
    dcomp_set_handlers(&memblkmod, ARRAY_SIZE(memblk_handlers), memblk_handlers);

    ret = dcomp_record_add(&memblkmod);
    if (unlikely(ret != Success))
    {
        derror("failed to add module[%s] to record\n", ModMemblkName);
        return ret;
    }

    dprint("[%s] init success, id[%u]\n", ModMemblkName, memblkmod.dcompid);

    return Success;
}

static void memblkmod_exit(void)
{
    dcomp_record_del(&memblkmod);
    dprint("[%s] exit\n", ModMemblkName);

    return;
}

DCOMP_INIT_NORMPRIO(memblkmod_init);
DCOMP_EXIT_NORMPRIO(memblkmod_exit);
