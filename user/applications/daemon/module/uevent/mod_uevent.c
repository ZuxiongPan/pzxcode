#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "lib/util.h"

#define DEVICE_PATH_MAX_LEN 128

static dmod_t ueventmod;

static int ueventmod_ontask(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    dtask_t *task = (dtask_t *)arg;

    switch (task->datatype)
    {
        case DataBinaryToModule:
            char *str = (char *)task->data;
            for (unsigned int i = 0; i < task->data_size; i++)
            {
                if (str[i] == '\0')
                {
                    str[i] = ',';
                }
            }
            str[task->data_size - 1] = '\0';
            dprint("uevent string {%s}\n", str);
            break;
        default:
            derror("unknown task datatype %d\n", task->datatype);
            break;
    }

    return Success;
}

static const mod_ops_t ueventmod_ops = {
    .ontask = ueventmod_ontask,
};

int ueventmod_init(void)
{
    int ret = Success;
    memset(&ueventmod, 0, sizeof(dmod_t));
    dcomponent_init(&ueventmod.dcomp, ModuleIDUevent, "uevent");
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

/*
static int handle_uevent(const uevent_strs_t *info)
{
    int ret = Success;
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if (NULL != info->devname && NULL != info->expanded)
    {
        char devpath[DEVICE_PATH_MAX_LEN] = {0};
        char mntpath[DEVICE_PATH_MAX_LEN] = {0};
        if (!strcmp(info->expanded, "formatted"))
        {
            snprintf(devpath, DEVICE_PATH_MAX_LEN, "/dev/%s", info->devname);
            char *const fmtargs[] = {
                "mkfs.minix", devpath, NULL
            };
            ret = run_new_program_sync("mkfs.minix", fmtargs);
        }

        if (ret == Success)
        {
            snprintf(mntpath, DEVICE_PATH_MAX_LEN, "/mnt/%s", info->devname);
            ret = stat(mntpath, &st);
            if (ret < 0)
            {
                if (mkdir(mntpath, 0755) < 0)
                {
                    derror("mkdir %s failed\n", mntpath);
                    ret = Fail;
                }
                else
                {
                    ret = mount(devpath, mntpath, NULL, 0, NULL);
                }
            }
            else if (S_ISDIR(st.st_mode))
            {
                ret = mount(devpath, mntpath, NULL, 0, NULL);
            }
            else
            {
                derror("mount %s to %s failed\n", devpath, mntpath);
                ret = Fail;
            }
        }
    }

    return ret;
}
*/