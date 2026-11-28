#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/statvfs.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "channel/chnl_api.h"
#include "lib/util.h"

#define MEMBLK_NAME_LEN 64
#define MEMBLK_FS_TYPE "minix"

#define MEMBLK_TIMER_INTERVAL_MS 5000U
#define MEMBLK_MKFS_TIMEOUT_MS 10000U

struct memblk_info {
    char devname[MEMBLK_NAME_LEN];
    char devpath[MEMBLK_NAME_LEN];
    char mntpath[MEMBLK_NAME_LEN];
    bool valid;
    struct statvfs stvfs;
    struct lnode node;
};

struct memblk_mgr {
    struct dcomp mod;
    struct lnode memblk_list;
    unsigned int count;
    int tid;
    pthread_mutex_t lock;
};

static struct memblk_mgr memblkmod;

/* caller must hold memblkmod.lock */
static struct memblk_info *memblk_find_locked(const char *devname)
{
    struct lnode *node = NULL;

    for (node = memblkmod.memblk_list.next; node != &memblkmod.memblk_list; node = node->next)
    {
        struct memblk_info *info = container_of(node, struct memblk_info, node);

        if (strcmp(info->devname, devname) == 0)
        {
            return info;
        }
    }

    return NULL;
}

/* caller must hold memblkmod.lock */
static void memblk_timer_start_locked(void)
{
    if (memblkmod.tid >= 0)
    {
        return ;
    }

    memblkmod.tid = timer_add(MEMBLK_TIMER_INTERVAL_MS, MEMBLK_TIMER_INTERVAL_MS,
        true, ModMemblkId, MSGID_SYS_TIMER);
    if (memblkmod.tid < 0)
    {
        derror("memblk statvfs timer add failed\n");
        memblkmod.tid = -1;
        return ;
    }

    dprint("memblk statvfs timer started, tid[%d], interval[%ums]\n",
        memblkmod.tid, MEMBLK_TIMER_INTERVAL_MS);

    return ;
}

/* caller must hold memblkmod.lock */
static void memblk_timer_stop_locked(void)
{
    if (memblkmod.tid < 0)
    {
        return ;
    }

    timer_del(memblkmod.tid);
    dprint("memblk statvfs timer stopped, tid[%d]\n", memblkmod.tid);
    memblkmod.tid = -1;

    return ;
}

static int memblk_setup_locked(struct memblk_info *info)
{
    char *const mkfs_args[] = { "mkfs.minix", info->devpath, NULL };
    int ret = Success;

    if (access(info->devpath, F_OK) != 0)
    {
        dprint("[%s] %s is not ready yet\n", info->devname, info->devpath);
        return -ENOENT;
    }

    ret = run_new_program_sync("mkfs.minix", mkfs_args, MEMBLK_MKFS_TIMEOUT_MS, NULL);
    if (ret != Success)
    {
        derror("[%s] mkfs.minix on %s failed, code: %d\n",
            info->devname, info->devpath, ret);
        return Fail;
    }

    if (mkdir(info->mntpath, 0755) != 0 && errno != EEXIST)
    {
        derror("[%s] mkdir %s failed, errno: %d\n", info->devname, info->mntpath, errno);
        return Fail;
    }

    if (mount(info->devpath, info->mntpath, MEMBLK_FS_TYPE, 0, NULL) != 0)
    {
        derror("[%s] mount %s on %s failed, errno: %d\n",
            info->devname, info->devpath, info->mntpath, errno);
        return Fail;
    }

    if (statvfs(info->mntpath, &info->stvfs) != 0)
    {
        derror("[%s] statvfs %s failed, errno: %d\n", info->devname, info->mntpath, errno);
        return Fail;
    }

    dprint("[%s] %s mounted on %s, bsize[%lu] blocks[%lu] bfree[%lu]\n",
        info->devname, info->devpath, info->mntpath,
        (unsigned long)info->stvfs.f_bsize, (unsigned long)info->stvfs.f_blocks,
        (unsigned long)info->stvfs.f_bfree);

    return Success;
}

static int memblk_genl_add_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    struct memblk_info *info = NULL;
    int ret = Success;

    UNUSED(comp);
    UNUSED(srcid);

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("memblk add without payload\n");
        return Fail;
    }

    pthread_mutex_lock(&memblkmod.lock);

    info = memblk_find_locked(data);
    if (NULL != info)
    {
        dprint("[%s] already mounted, valid[%d]\n", data, info->valid);
        pthread_mutex_unlock(&memblkmod.lock);
        return Success;
    }
    else
    {
        info = (struct memblk_info *)calloc(1, sizeof(struct memblk_info));
        if (NULL == info)
        {
            pthread_mutex_unlock(&memblkmod.lock);
            derror("calloc memblk info[%s] failed\n", data);
            return Fail;
        }

        snprintf(info->devname, sizeof(info->devname), "%s", data);
        snprintf(info->devpath, sizeof(info->devpath), "/dev/%s", data);
        snprintf(info->mntpath, sizeof(info->mntpath), "/mnt/%s", data);
        lnode_init(&info->node);
        list_add_tail(&info->node, &memblkmod.memblk_list);
        memblkmod.count++;

        memblk_timer_start_locked();
    }

    ret = memblk_setup_locked(info);
    info->valid = (ret == Success);

    pthread_mutex_unlock(&memblkmod.lock);

    if (ret != Success)
    {
        if (ret == -ENOENT)
        {
            dprint("[%s] setup failed, the device is not prepared\n", data);
        }
        else
        {
            derror("[%s] setup failed, code: %d\n", data, ret);
        }

        return Fail;
    }

    return Success;
}

static int memblk_genl_remove_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    struct memblk_info *info = NULL;
    unsigned int left = 0;

    UNUSED(comp);
    UNUSED(srcid);

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("memblk remove without payload\n");
        return Fail;
    }

    pthread_mutex_lock(&memblkmod.lock);

    info = memblk_find_locked(data);
    if (NULL == info)
    {
        pthread_mutex_unlock(&memblkmod.lock);
        derror("[%s] remove for unknown memblk, ignored\n", data);
        return Success;
    }

    if (info->valid && umount(info->mntpath) != 0)
    {
        derror("[%s] umount %s failed, errno: %d\n", data, info->mntpath, errno);
    }

    if (rmdir(info->mntpath) != 0 && errno != ENOENT)
    {
        derror("[%s] rmdir %s failed, errno: %d\n", data, info->mntpath, errno);
    }

    list_del(&info->node);
    free(info);
    memblkmod.count--;

    if (memblkmod.count == 0)
    {
        memblk_timer_stop_locked();
    }

    left = memblkmod.count;

    pthread_mutex_unlock(&memblkmod.lock);

    dprint("[%s] removed, %u memblk left\n", data, left);

    return Success;
}

static int memblk_statvfs_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    struct lnode *node = NULL;
    struct lnode *next = NULL;

    UNUSED(comp);
    UNUSED(srcid);
    UNUSED(data_size);
    UNUSED(data);

    pthread_mutex_lock(&memblkmod.lock);

    for (node = memblkmod.memblk_list.next; node != &memblkmod.memblk_list; node = next)
    {
        struct memblk_info *info = container_of(node, struct memblk_info, node);

        next = node->next;

        if (!info->valid)
        {
            derror("[%s] not mounted, statvfs ignored\n", info->devname);
            continue;
        }

        if (statvfs(info->mntpath, &info->stvfs) != 0)
        {
            derror("[%s] statvfs %s failed, errno: %d\n",
                info->devname, info->mntpath, errno);
            continue;
        }

        dprint("[%s] bsize[%lu] blocks[%lu] bfree[%lu] bavail[%lu] files[%lu] ffree[%lu] usage[%lu%%]\n",
            info->devname,
            (unsigned long)info->stvfs.f_bsize,
            (unsigned long)info->stvfs.f_blocks,
            (unsigned long)info->stvfs.f_bfree,
            (unsigned long)info->stvfs.f_bavail,
            (unsigned long)info->stvfs.f_files,
            (unsigned long)info->stvfs.f_ffree,
            info->stvfs.f_blocks ?
                (unsigned long)((info->stvfs.f_blocks - info->stvfs.f_bfree) * 100 /
                    info->stvfs.f_blocks) : 0UL);
    }

    pthread_mutex_unlock(&memblkmod.lock);

    return Success;
}

static const struct msg_handler memblk_handlers[] = {
    {.name = "genl-add", .msgid = MSGID_GENL_ACT_ADD, .func = memblk_genl_add_handler },
    {.name = "genl-remove", .msgid = MSGID_GENL_ACT_REMOVE, .func = memblk_genl_remove_handler },
    {.name = "statvfs", .msgid = MSGID_SYS_TIMER, .func = memblk_statvfs_handler },
};

static int memblkmod_init(void)
{
    int ret = Success;

    memset(&memblkmod, 0, sizeof(memblkmod));
    memblkmod.tid = -1;
    lnode_init(&memblkmod.memblk_list);
    pthread_mutex_init(&memblkmod.lock, NULL);

    dcomp_init(&memblkmod.mod, ModMemblkName, ModMemblkId);
    dcomp_set_handlers(&memblkmod.mod, ARRAY_SIZE(memblk_handlers), memblk_handlers);

    ret = dcomp_record_add(&memblkmod.mod);
    if (unlikely(ret != Success))
    {
        derror("failed to add module[%s] to record\n", ModMemblkName);
        pthread_mutex_destroy(&memblkmod.lock);
        return ret;
    }

    dprint("[%s] init success, id[%u]\n", ModMemblkName, memblkmod.mod.dcompid);

    return Success;
}

static void memblkmod_exit(void)
{
    struct lnode *node = NULL;
    struct lnode *next = NULL;

    pthread_mutex_lock(&memblkmod.lock);

    memblk_timer_stop_locked();

    for (node = memblkmod.memblk_list.next; node != &memblkmod.memblk_list; node = next)
    {
        struct memblk_info *info = container_of(node, struct memblk_info, node);

        next = node->next;

        if (info->valid && umount(info->mntpath) != 0)
        {
            derror("[%s] umount %s failed, errno: %d\n",
                info->devname, info->mntpath, errno);
        }

        list_del(&info->node);
        free(info);
        memblkmod.count--;
    }

    pthread_mutex_unlock(&memblkmod.lock);

    dcomp_record_del(&memblkmod.mod);
    pthread_mutex_destroy(&memblkmod.lock);

    dprint("[%s] exit\n", ModMemblkName);

    return;
}

DCOMP_INIT_LOWPRIO(memblkmod_init);
DCOMP_EXIT_LOWPRIO(memblkmod_exit);
