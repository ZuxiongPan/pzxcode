#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "uevent_translator.h"
#include "lib/util.h"

#define DEVICE_PATH_MAX_LEN 128

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
    dcomponent_init(&ueventmod.dcomp, ModuleIDUevent, "netlink");
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

DCOMP_INIT_NORMPRIO(ueventmod_init);
DCOMP_EXIT_NORMPRIO(ueventmod_exit);

static int handle_uevent(const uevent_strs_t *info)
{
    if (NULL != info->devname && NULL != info->expanded)
    {
        char path[DEVICE_PATH_MAX_LEN] = {0};
        if (!strcmp(info->expanded, "formatted"))
        {
            snprintf(path, DEVICE_PATH_MAX_LEN, "/dev/%s", info->devname);
            char *const fmtargs[] = {
                "mkfs.minix", path, NULL
            };
            run_new_program("mkfs.minix", fmtargs);
        }
    }

    return Success;
}
