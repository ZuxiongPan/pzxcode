#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "uevent_translator.h"

static dmod_t ueventmod;

static int handle_uevent(const uevent_strs_t *info);

static int ueventmod_ontask(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Fail;
    dtask_t *task = (dtask_t *)arg;
    uevent_strs_t info;
    memset(&info, 0, sizeof(uevent_strs_t));

    switch (task->datatype)
    {
        case DataBinaryToModule:
            uevent_translate(task->data, task->data_size, &info);
            ret = handle_uevent(&info);
            break;
        default:
            derror("unknown task datatype %d\n", task->datatype);
            break;
    }

    return ret;
}

static const mod_ops_t ueventmod_ops = {
    .ontask = ueventmod_ontask,
};

int ueventmod_init(void)
{
    int ret = Success;
    memset(&ueventmod, 0, sizeof(dmod_t));
    dcomponent_init(&ueventmod.dcomp, ModuleIDUevent, "uevent_mod");
    ueventmod.ops = &ueventmod_ops;

    ret = dmodule_register(&ueventmod);
    if (ret != Success)
    {
        derror("uevent module register failed\n");
        return Fail;
    }

    dprint("ueventmod_init ret = %d\n", ret);
    return ret;
}

void ueventmod_exit(void)
{
    dmodule_unregister(&ueventmod);
    dprint("uevent module unregister done\n");
}

static int handle_uevent(const uevent_strs_t *info)
{
    if (NULL != info->devtype && !strcmp(info->devtype, "disk"))
    {
        dprint("disk uevent\n");
        rawlog("\taction = %s\n", info->action ? info->action : "null");
        rawlog("\tdevpath = %s\n", info->devpath ? info->devpath : "null");
        rawlog("\tsubsystem = %s\n", info->subsystem ? info->subsystem : "null");
        rawlog("\tdevname = %s\n", info->devname ? info->devname : "null");
        rawlog("\tdevtype = %s\n", info->devtype ? info->devtype : "null");
    }

    return Success;
}