#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "channel/chnl_api.h"
#include "module/dmsgid.h"
#include "lib/util.h"

#include "common/uk_netlink.h"

struct blkinfo {
    char devpath[32];
    char mntpath[32];
    struct statvfs stvfs;
    struct blkinfo *next;
};
typedef struct blkinfo blkinfo_t;

struct memblk {
    dmod_t mod;
    int timer_statvfs;
    pthread_mutex_t lock;
    blkinfo_t *head;
} memblkmod;

static int memblkmod_ontask(dmod_t *m, int src_compid, unsigned int msgid,
    void *data, unsigned int data_size)
{
    UNUSED(m);
    UNUSED(data_size);
    int ret = Success;

    switch (msgid)
    {
        case MSGID_GENL_BIN:
            if (!data || data_size != 0)
            {
                dprint("a new memory block device [%s] installed\n", (const char *)data);
                blkinfo_t *info = (blkinfo_t *)calloc(1, sizeof(blkinfo_t));
                if (NULL == info)
                {
                    derror("calloc a new blkinfo_t failed\n");
                }
                else
                {
                    snprintf(info->devpath, sizeof(info->devpath), "/dev/%s", (const char *)data);
                    snprintf(info->mntpath, sizeof(info->mntpath), "/mnt/%s", (const char *)data);
                    char *const fmtargs[] = { "mkfs.minix", info->devpath, NULL };
                    ret = run_new_program_sync("mkfs.minix", fmtargs);
                    if (ret != Success)
                    {
                        derror("mkfs.minix failed\n");
                        free(info);
                        info = NULL;
                    }
                    else
                    {
                        mkdir(info->mntpath, 0755);
                        ret = mount(info->devpath, info->mntpath, "minix", 0, NULL);
                        if (ret != 0)
                        {
                            derror("mount failed\n");
                            free(info);
                            info = NULL;
                        }
                        else
                        {
                            pthread_mutex_lock(&memblkmod.lock);
                            info->next = memblkmod.head;
                            memblkmod.head = info;
                            pthread_mutex_unlock(&memblkmod.lock);
                        }
                    }
                }
                break;
            }
            break;
        case MSGID_STATVFS_TIMER:
            pthread_mutex_lock(&memblkmod.lock);
            if (NULL != memblkmod.head)
            {
                blkinfo_t *info = memblkmod.head;
                while (NULL != info)
                {
                    blkinfo_t *next = info->next;
                    statvfs(info->mntpath, &info->stvfs);
                    info = next;
                }
            }
            pthread_mutex_unlock(&memblkmod.lock);
            break;
        case MSGID_SIMPLE_STR:
            char buf[TASK_DATA_MAXSIZE];
            int len = 0;
            if (data && !strcmp("blkinfo", (const char *)data))
            {
                pthread_mutex_lock(&memblkmod.lock);
                if (NULL != memblkmod.head)
                {
                    blkinfo_t *info = memblkmod.head;
                    while (NULL != info)
                    {
                        blkinfo_t *next = info->next;
                        len += snprintf(buf + len, sizeof(buf) - len, "devpath = %s, mntpath = %s, f_bsize = %ld, f_bfree = %ld, f_bavail = %ld, f_files = %ld, f_ffree = %ld, f_ffree = %ld\n",
                            info->devpath, info->mntpath, info->stvfs.f_bsize, info->stvfs.f_bfree, info->stvfs.f_bavail, info->stvfs.f_files, info->stvfs.f_ffree, info->stvfs.f_ffree);
                        info = next;
                    }
                }
                pthread_mutex_unlock(&memblkmod.lock);
                task_enqueue(DataToOuter, memblkmod.mod.dcomp.dcompid, src_compid, 0, len, buf);
            }
            break;
        default:
            dprint("invalid msgid 0x%x\n", msgid);
            break;
    }

    return ret;
}

static const mod_ops_t memblkmod_ops = {
    .ontask = memblkmod_ontask,
};

static int memblkmod_init(void)
{
    int ret = Success;
    memset(&memblkmod, 0, sizeof(memblkmod));
    dcomponent_init(&memblkmod.mod.dcomp, ModuleIDMemblk, USER_MEMBLK_MODNAME);
    memblkmod.mod.ops = &memblkmod_ops;
    memblkmod.timer_statvfs = -1;
    memblkmod.head = NULL;
    pthread_mutex_init(&memblkmod.lock, NULL);

    memblkmod.timer_statvfs = timer_add(5000, 5000, true, ModuleIDMemblk, MSGID_STATVFS_TIMER);
    if (memblkmod.timer_statvfs < 0)
    {
        derror("memblk module timer add failed\n");
    }

    ret = dmodule_register(&memblkmod.mod);
    if (ret != Success)
    {
        derror("memblk module register failed\n");
        return Fail;
    }

    dprint("memblk module register ret = %d\n", ret);
    return ret;
}

static void memblkmod_exit(void)
{
    if (memblkmod.timer_statvfs >= 0)
    {
        timer_del(memblkmod.timer_statvfs);
        memblkmod.timer_statvfs = -1;
    }
    pthread_mutex_lock(&memblkmod.lock);
    if (NULL != memblkmod.head)
    {
        blkinfo_t *info = memblkmod.head;
        while (NULL != info)
        {
            blkinfo_t *next = info->next;
            free(info);
            info = next;
        }
        memblkmod.head = NULL;
    }
    pthread_mutex_unlock(&memblkmod.lock);
    dmodule_unregister(&memblkmod.mod);
    dprint("memblk module unregister done\n");
}

DCOMP_INIT_NORMPRIO(memblkmod_init);
DCOMP_EXIT_NORMPRIO(memblkmod_exit);
