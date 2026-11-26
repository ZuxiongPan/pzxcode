/*
 * memblk module: 内核 memblk 块设备的管理者
 *
 * 数据流（当前阶段）：
 *   内核 --generic netlink--> channel.generic-netlink --> module.dispatcher
 *        --> 按 target 路由 --> 本模块 MSGID_MEMBLK_DEV_ADD
 *   target 字符串是内核侧的裸设备名（见 include/common/uk_netlink.h 的
 *   USER_MEMBLK_MODNAME），在 init/fix_comp.c 里登记成 ModMemblkId 的别名。
 *
 * 本模块负责：
 *   1. 设备上线事件：等设备节点出现 ->（必要时）mkfs.minix -> 挂载到 /mnt/<name>
 *   2. 周期采样已挂载文件系统的 statvfs，缓存起来
 *   3. 应答查询命令（当前只支持 "blkinfo"），把缓存打回去
 *   4. 设备下线事件：umount 并标记失效
 *
 * 为什么有一个自己的线程：
 *   mkfs/等待设备节点都要几百毫秒到几秒，放在 dworker 里会占住工作线程，而
 *   dworker 只有 WORKER_MAXNUM 个、dsync 的阻塞预算还要留一个给唤醒消息，长
 *   阻塞会直接把队列拖死。所以 handler 只负责登记 + 投递作业，真正的准备动作
 *   由 setup 线程串行完成（挂载本来也不适合并发）。
 *
 * 没有实现的部分：结果回传内核、mount 失败后的重试。等内核侧 netlink 通路调通
 * 之后再按需要加。
 */
// for strnlen
#define _GNU_SOURCE

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
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

#define MEMBLK_NAME_MAX 32U
#define MEMBLK_PATH_MAX 64U

#define MEMBLK_FS_TYPE "minix"

/* add_disk 之后设备节点是 devtmpfs/mdev 异步创建的，不会立刻可见 */
#define MEMBLK_NODE_WAIT_MS 5000U
#define MEMBLK_NODE_POLL_MS 100U
/* mkfs.minix 在内存盘上很快，给足余量即可，超时就按失败处理 */
#define MEMBLK_MKFS_TIMEOUT_MS 15000U

#define MEMBLK_STATVFS_INTERVAL_MS 5000U

/* 一条应答的最大载荷：不能超过任务池最大槽位放得下的数据量 */
#define MEMBLK_REPLY_MAX (LARGE_POOL_SLOT_SIZE - sizeof(struct dtask))

enum memblk_state {
    MemblkStateCreated = 0, /* 事件已登记，等待 setup 线程处理 */
    MemblkStateSetting,     /* setup 线程正在格式化/挂载 */
    MemblkStateMounted,     /* 已挂载，statvfs 缓存有效 */
    MemblkStateFailed,      /* 格式化或挂载失败，不再重试 */
    MemblkStateRemoved,     /* 已下线，设备项保留到模块退出 */
};

static const char *memblk_state_str(enum memblk_state state)
{
    switch (state) {
    case MemblkStateCreated: return "pending";
    case MemblkStateSetting: return "setting";
    case MemblkStateMounted: return "mounted";
    case MemblkStateFailed:  return "failed";
    case MemblkStateRemoved: return "removed";
    default:                 return "unknown";
    }
}

struct memblk_dev {
    struct lnode node;
    char name[MEMBLK_NAME_MAX];
    char devpath[MEMBLK_PATH_MAX];
    char mntpath[MEMBLK_PATH_MAX];
    enum memblk_state state;
    bool stvfs_valid;
    struct statvfs stvfs;
};

/* setup 线程的作业项：只带设备名，设备项本身由 devs 链持有 */
struct memblk_job {
    struct lnode node;
    char name[MEMBLK_NAME_MAX];
};

struct memblk_mod {
    struct dcomp comp;
    int timer_statvfs;

    /* 保护 devs/dev_num。设备项只在模块退出时释放，解锁后继续用指针是安全的，
     * 这也是 setup 线程能拿着指针去跑 mkfs 的前提 */
    pthread_mutex_t lock;
    struct lnode devs;
    unsigned int dev_num;

    /* setup 线程与它的作业队列 */
    pthread_t setup_tid;
    bool setup_started;
    pthread_mutex_t job_lock;
    pthread_cond_t job_cond;
    struct lnode jobs;
    unsigned int job_num;
    bool stop;
};

static struct memblk_mod memblkmod;

static void *memblk_setup_thread(void *arg);

static bool memblk_stopped(void)
{
    bool stop = false;

    pthread_mutex_lock(&memblkmod.job_lock);
    stop = memblkmod.stop;
    pthread_mutex_unlock(&memblkmod.job_lock);

    return stop;
}

/*
 * 设备名会直接拼进 /dev/<name> 和 /mnt/<name>，只接受一层、无分隔符的字面量，
 * 否则内核侧一个畸形 target 就能把路径带到 /dev/../ 之类的地方去。
 */
static bool memblk_name_ok(const char *name, size_t len)
{
    if (name == NULL || len == 0 || len >= MEMBLK_NAME_MAX) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        char c = name[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
            continue;
        }
        return false;
    }

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return false;
    }

    return true;
}

/* caller must hold memblkmod.lock */
static struct memblk_dev *dev_find_locked(const char *name)
{
    struct lnode *node = NULL;

    for (node = memblkmod.devs.next; node != &memblkmod.devs; node = node->next) {
        struct memblk_dev *dev = container_of(node, struct memblk_dev, node);

        if (strcmp(dev->name, name) == 0) {
            return dev;
        }
    }

    return NULL;
}

/*
 * 登记一个设备，状态置回 Created。
 * 返回 NULL 表示同名设备已经在处理中（重复事件）或者内存不足，调用方跳过即可。
 */
static struct memblk_dev *dev_get_or_create(const char *name)
{
    struct memblk_dev *dev = NULL;

    pthread_mutex_lock(&memblkmod.lock);
    dev = dev_find_locked(name);

    if (dev != NULL && dev->state != MemblkStateRemoved) {
        pthread_mutex_unlock(&memblkmod.lock);
        return NULL;
    }

    if (dev == NULL) {
        dev = calloc(1, sizeof(*dev));
        if (dev == NULL) {
            pthread_mutex_unlock(&memblkmod.lock);
            derror("failed to alloc memblk dev[%s]\n", name);
            return NULL;
        }

        snprintf(dev->name, sizeof(dev->name), "%s", name);
        snprintf(dev->devpath, sizeof(dev->devpath), "/dev/%s", name);
        snprintf(dev->mntpath, sizeof(dev->mntpath), "/mnt/%s", name);
        lnode_init(&dev->node);
        list_add_tail(&dev->node, &memblkmod.devs);
        memblkmod.dev_num++;
    }

    dev->state = MemblkStateCreated;
    dev->stvfs_valid = false;
    memset(&dev->stvfs, 0, sizeof(dev->stvfs));
    pthread_mutex_unlock(&memblkmod.lock);

    return dev;
}

static int job_push(const char *name)
{
    struct memblk_job *job = calloc(1, sizeof(*job));

    if (job == NULL) {
        derror("failed to alloc memblk job[%s]\n", name);
        return Fail;
    }

    snprintf(job->name, sizeof(job->name), "%s", name);
    lnode_init(&job->node);

    pthread_mutex_lock(&memblkmod.job_lock);
    list_add_tail(&job->node, &memblkmod.jobs);
    memblkmod.job_num++;
    pthread_cond_signal(&memblkmod.job_cond);
    pthread_mutex_unlock(&memblkmod.job_lock);

    return Success;
}

/* 等设备节点出现，节点由内核 uevent + mdev/devtmpfs 创建，有延迟 */
static int wait_dev_node(const char *devpath)
{
    struct timespec ts;
    struct stat st;
    unsigned int waited = 0;

    ts.tv_sec = 0;
    ts.tv_nsec = (long)MEMBLK_NODE_POLL_MS * 1000000L;

    while (waited < MEMBLK_NODE_WAIT_MS) {
        if (stat(devpath, &st) == 0) {
            return Success;
        }

        if (memblk_stopped()) {
            return -ECANCELED;
        }

        nanosleep(&ts, NULL);
        waited += MEMBLK_NODE_POLL_MS;
    }

    return -ENOENT;
}

static int dev_mount(const char *name, const char *devpath, const char *mntpath)
{
    int code = 0;

    if (mkdir(mntpath, 0755) != 0 && errno != EEXIST) {
        derror("[%s] mkdir %s failed, errno: %d\n", name, mntpath, errno);
        return Fail;
    }

    /*
     * 先直接挂：设备上已经有文件系统（重新上线、或内核复用同一块内存）时，
     * 再格式化一次就会把数据抹掉。mount 成功说明没必要动它。
     */
    if (mount(devpath, mntpath, MEMBLK_FS_TYPE, 0, NULL) == 0) {
        return Success;
    }

    if (errno == EBUSY) {
        /* 已经挂在别处，目录上能 statvfs 到就当作可用 */
        dprint("[%s] %s is already mounted\n", name, devpath);
        return Success;
    }

    if (errno != EINVAL) {
        /*
         * EINVAL 是"设备上没有可识别的文件系统"，只有这种情况才值得格式化；
         * 其它错误（ENOENT/ENODEV/EPERM...）格式化解决不了，反而会毁数据
         */
        derror("[%s] mount %s on %s failed, errno: %d\n", name, devpath, mntpath, errno);
        return Fail;
    }

    dprint("[%s] no %s filesystem on %s, formatting\n", name, MEMBLK_FS_TYPE, devpath);

    {
        char *const args[] = { "mkfs.minix", (char *)devpath, NULL };

        code = run_new_program_sync("mkfs.minix", args, MEMBLK_MKFS_TIMEOUT_MS, NULL);
    }

    if (code != Success) {
        derror("[%s] mkfs.minix on %s failed, code: %d\n", name, devpath, code);
        return Fail;
    }

    if (mount(devpath, mntpath, MEMBLK_FS_TYPE, 0, NULL) != 0) {
        derror("[%s] mount %s on %s failed after mkfs, errno: %d\n",
            name, devpath, mntpath, errno);
        return Fail;
    }

    return Success;
}

/* setup 线程的一次完整作业：等节点 -> 挂载 -> 更新状态 */
static void dev_setup(const char *name)
{
    struct memblk_dev *dev = NULL;
    char devpath[MEMBLK_PATH_MAX];
    char mntpath[MEMBLK_PATH_MAX];
    bool mounted_here = false;
    bool removed = false;
    int ret = Fail;

    /* 名字和路径先取本地副本，后面长时间不持锁 */
    pthread_mutex_lock(&memblkmod.lock);
    dev = dev_find_locked(name);
    if (dev == NULL || dev->state != MemblkStateCreated) {
        pthread_mutex_unlock(&memblkmod.lock);
        dprint("[%s] setup skipped, state changed\n", name);
        return;
    }
    dev->state = MemblkStateSetting;
    snprintf(devpath, sizeof(devpath), "%s", dev->devpath);
    snprintf(mntpath, sizeof(mntpath), "%s", dev->mntpath);
    pthread_mutex_unlock(&memblkmod.lock);

    ret = wait_dev_node(devpath);
    if (ret != Success) {
        derror("[%s] device node %s not ready, code: %d\n", name, devpath, ret);
        goto out;
    }

    ret = dev_mount(name, devpath, mntpath);
    if (ret != Success) {
        goto out;
    }
    mounted_here = true;

    pthread_mutex_lock(&memblkmod.lock);
    if (statvfs(mntpath, &dev->stvfs) == 0) {
        dev->stvfs_valid = true;
    }
    pthread_mutex_unlock(&memblkmod.lock);

out:
    pthread_mutex_lock(&memblkmod.lock);
    /* setup 期间收到下线事件，就别再把状态改回 mounted 了 */
    removed = (dev->state == MemblkStateRemoved);
    if (ret == Success && !removed) {
        dev->state = MemblkStateMounted;
    } else if (removed) {
        dev->state = MemblkStateRemoved;
    } else {
        dev->state = MemblkStateFailed;
        dev->stvfs_valid = false;
    }
    pthread_mutex_unlock(&memblkmod.lock);

    if (mounted_here && removed) {
        if (umount(mntpath) != 0) {
            derror("[%s] umount %s failed, errno: %d\n", name, mntpath, errno);
        } else {
            dprint("[%s] umounted %s after remove event\n", name, mntpath);
        }
    }

    if (ret == Success) {
        dprint("[%s] mounted on %s, dev %s\n", name, mntpath, devpath);
    } else if (!removed) {
        derror("[%s] setup failed, dev %s\n", name, devpath);
    }

    return;
}

static void *memblk_setup_thread(void *arg)
{
    struct memblk_job *job = NULL;

    UNUSED(arg);

    for (;;) {
        pthread_mutex_lock(&memblkmod.job_lock);
        while (memblkmod.job_num == 0 && !memblkmod.stop) {
            pthread_cond_wait(&memblkmod.job_cond, &memblkmod.job_lock);
        }

        if (memblkmod.stop) {
            pthread_mutex_unlock(&memblkmod.job_lock);
            break;
        }

        job = container_of(memblkmod.jobs.next, struct memblk_job, node);
        list_del(&job->node);
        memblkmod.job_num--;
        pthread_mutex_unlock(&memblkmod.job_lock);

        dev_setup(job->name);
        free(job);
        job = NULL;
    }

    dprint("memblk setup thread exit\n");
    return NULL;
}

/* MSGID_MEMBLK_DEV_ADD：data 是设备名字符串 */
static int memblk_dev_add_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    size_t len = 0;

    UNUSED(self);
    UNUSED(srcid);

    if (unlikely(data == NULL || data_size == 0)) {
        derror("memblk dev add without payload\n");
        return Fail;
    }

    /* 只信任 data_size 之内，不允许读越界 */
    len = strnlen(data, data_size);
    if (len == data_size) {
        derror("memblk dev add payload is not NUL terminated\n");
        return Fail;
    }

    if (!memblk_name_ok(data, len)) {
        derror("memblk dev add with invalid name, len: %zu\n", len);
        return Fail;
    }

    if (dev_get_or_create(data) == NULL) {
        dprint("[%s] already tracked, event ignored\n", data);
        return Success;
    }

    if (job_push(data) != Success) {
        derror("[%s] no memory for setup job, device dropped\n", data);
        pthread_mutex_lock(&memblkmod.lock);
        {
            struct memblk_dev *dev = dev_find_locked(data);

            if (dev != NULL) {
                dev->state = MemblkStateFailed;
            }
        }
        pthread_mutex_unlock(&memblkmod.lock);
        return Fail;
    }

    dprint("[%s] dev add queued, payload %u bytes\n", data, data_size);
    return Success;
}

/* MSGID_MEMBLK_DEV_DEL：data 是设备名字符串 */
static int memblk_dev_del_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    struct memblk_dev *dev = NULL;
    char mntpath[MEMBLK_PATH_MAX];
    bool mounted = false;
    size_t len = 0;

    UNUSED(self);
    UNUSED(srcid);

    if (unlikely(data == NULL || data_size == 0)) {
        derror("memblk dev del without payload\n");
        return Fail;
    }

    len = strnlen(data, data_size);
    if (len == data_size) {
        derror("memblk dev del payload is not NUL terminated\n");
        return Fail;
    }

    pthread_mutex_lock(&memblkmod.lock);
    dev = dev_find_locked(data);
    if (dev == NULL || dev->state == MemblkStateRemoved) {
        pthread_mutex_unlock(&memblkmod.lock);
        dprint("[%s] dev del for unknown device, ignored\n", data);
        return Success;
    }

    /* 先让采样和查询跳过它，再去做 umount 这个慢动作 */
    mounted = (dev->state == MemblkStateMounted);
    dev->state = MemblkStateRemoved;
    dev->stvfs_valid = false;
    snprintf(mntpath, sizeof(mntpath), "%s", dev->mntpath);
    pthread_mutex_unlock(&memblkmod.lock);

    if (mounted && umount(mntpath) != 0) {
        derror("[%s] umount %s failed, errno: %d\n", data, mntpath, errno);
    }

    dprint("[%s] dev removed\n", data);
    return Success;
}

static void dev_refresh_all(void)
{
    struct lnode *node = NULL;

    pthread_mutex_lock(&memblkmod.lock);
    for (node = memblkmod.devs.next; node != &memblkmod.devs; node = node->next) {
        struct memblk_dev *dev = container_of(node, struct memblk_dev, node);

        if (dev->state != MemblkStateMounted) {
            continue;
        }

        if (statvfs(dev->mntpath, &dev->stvfs) == 0) {
            dev->stvfs_valid = true;
        } else {
            /* 挂载点被外部拆掉之类的情况，保留上一次的采样值但标记失效 */
            dev->stvfs_valid = false;
            ddebug("[%s] statvfs %s failed, errno: %d\n", dev->name,
                dev->mntpath, errno);
        }
    }
    pthread_mutex_unlock(&memblkmod.lock);

    return;
}

/* MSGID_MEMBLK_STATVFS_TIMER */
static int memblk_statvfs_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(self);
    UNUSED(srcid);
    UNUSED(data_size);
    UNUSED(data);

    dev_refresh_all();

    return Success;
}

/*
 * 往应答缓冲里追加，写不下时返回 Fail 并把 len 固定到 cap - 1，
 * 让调用方知道后面的内容已经被截断
 */
static int reply_append(char *buf, unsigned int cap, unsigned int *len,
    const char *fmt, ...)
{
    va_list ap;
    unsigned int left = 0;
    int num = 0;

    if (*len >= cap) {
        return Fail;
    }

    left = cap - *len;

    va_start(ap, fmt);
    num = vsnprintf(buf + *len, left, fmt, ap);
    va_end(ap);

    if (num < 0) {
        return Fail;
    }

    if ((unsigned int)num >= left) {
        *len = cap - 1;
        buf[*len] = '\0';
        return Fail;
    }

    *len += (unsigned int)num;
    return Success;
}

static unsigned int dev_info_format(char *buf, unsigned int cap)
{
    struct lnode *node = NULL;
    unsigned int len = 0;
    unsigned int live = 0;

    pthread_mutex_lock(&memblkmod.lock);

    /* 下线的设备项要留到退出才释放，所以计数不能直接用 dev_num */
    for (node = memblkmod.devs.next; node != &memblkmod.devs; node = node->next) {
        struct memblk_dev *dev = container_of(node, struct memblk_dev, node);

        if (dev->state != MemblkStateRemoved) {
            live++;
        }
    }

    reply_append(buf, cap, &len, "memblk devices=%u\n", live);

    for (node = memblkmod.devs.next; node != &memblkmod.devs; node = node->next) {
        struct memblk_dev *dev = container_of(node, struct memblk_dev, node);

        if (dev->state == MemblkStateRemoved) {
            continue;
        }

        if (dev->stvfs_valid) {
            if (reply_append(buf, cap, &len,
                "dev=%s mnt=%s state=%s bsize=%lu blocks=%lu bfree=%lu "
                "bavail=%lu files=%lu ffree=%lu\n",
                dev->devpath, dev->mntpath, memblk_state_str(dev->state),
                (unsigned long)dev->stvfs.f_bsize,
                (unsigned long)dev->stvfs.f_blocks,
                (unsigned long)dev->stvfs.f_bfree,
                (unsigned long)dev->stvfs.f_bavail,
                (unsigned long)dev->stvfs.f_files,
                (unsigned long)dev->stvfs.f_ffree) != Success) {
                break;
            }
        } else {
            if (reply_append(buf, cap, &len, "dev=%s mnt=%s state=%s\n",
                dev->devpath, dev->mntpath, memblk_state_str(dev->state)) != Success) {
                break;
            }
        }
    }

    pthread_mutex_unlock(&memblkmod.lock);

    return len;
}

/* MSGID_MEMBLK_CMD：data 是命令字符串（带结尾 NUL），当前支持 "blkinfo" */
static int memblk_cmd_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    char buf[MEMBLK_REPLY_MAX];
    unsigned int len = 0;
    int ret = Success;

    if (unlikely(data == NULL || data_size == 0)) {
        derror("memblk cmd without payload\n");
        return Fail;
    }

    if (strnlen(data, data_size) == data_size) {
        derror("memblk cmd payload is not NUL terminated\n");
        return Fail;
    }

    if (strcmp(data, "blkinfo") == 0) {
        len = dev_info_format(buf, sizeof(buf));
    } else {
        len = (unsigned int)snprintf(buf, sizeof(buf),
            "memblk: unknown command [%s], try: blkinfo\n", data);
    }

    if (unlikely(len == 0)) {
        return Fail;
    }

    /* 应答回到请求者：UDS 客户端的 dcompid 由通道填在 srcid 里 */
    if (task_enqueue_by_id(self->dcompid, srcid, MSGID_UDS_RESPONSE, len, buf) != Success) {
        derror("response of %u bytes dropped for comp[%u]\n", len, srcid);
        ret = Fail;
    }

    return ret;
}

static const struct msg_handler memblk_handlers[] = {
    { .name = "dev-add", .msgid = MSGID_MEMBLK_DEV_ADD, .func = memblk_dev_add_handler },
    { .name = "dev-del", .msgid = MSGID_MEMBLK_DEV_DEL, .func = memblk_dev_del_handler },
    { .name = "cmd", .msgid = MSGID_MEMBLK_CMD, .func = memblk_cmd_handler },
    { .name = "statvfs", .msgid = MSGID_MEMBLK_STATVFS_TIMER, .func = memblk_statvfs_handler },
};

static int memblkmod_init(void)
{
    int ret = Success;

    memset(&memblkmod, 0, sizeof(memblkmod));
    lnode_init(&memblkmod.devs);
    lnode_init(&memblkmod.jobs);
    memblkmod.timer_statvfs = -1;
    memblkmod.stop = false;

    pthread_mutex_init(&memblkmod.lock, NULL);
    pthread_mutex_init(&memblkmod.job_lock, NULL);
    pthread_cond_init(&memblkmod.job_cond, NULL);

    dcomp_init(&memblkmod.comp, ModMemblkName, ModMemblkId);
    dcomp_set_handlers(&memblkmod.comp, ARRAY_SIZE(memblk_handlers), memblk_handlers);

    ret = pthread_create(&memblkmod.setup_tid, NULL, memblk_setup_thread, NULL);
    if (unlikely(ret != 0)) {
        derror("failed to create memblk setup thread, ret: %d\n", ret);
        ret = Fail;
        goto fail;
    }
    memblkmod.setup_started = true;

    ret = dcomp_record_add(&memblkmod.comp);
    if (unlikely(ret != Success)) {
        derror("failed to add module[%s] to record\n", ModMemblkName);
        goto fail;
    }

    memblkmod.timer_statvfs = timer_add(MEMBLK_STATVFS_INTERVAL_MS,
        MEMBLK_STATVFS_INTERVAL_MS, true, ModMemblkId, MSGID_MEMBLK_STATVFS_TIMER);
    if (memblkmod.timer_statvfs < 0) {
        /* 没有采样定时器，查询只会看到挂载瞬间的那一次采样 */
        derror("memblk statvfs timer add failed\n");
        memblkmod.timer_statvfs = -1;
    }

    dprint("[%s] init success, id[%u], timer[%d]\n", ModMemblkName,
        memblkmod.comp.dcompid, memblkmod.timer_statvfs);

    return Success;

fail:
    if (memblkmod.setup_started) {
        pthread_mutex_lock(&memblkmod.job_lock);
        memblkmod.stop = true;
        pthread_cond_broadcast(&memblkmod.job_cond);
        pthread_mutex_unlock(&memblkmod.job_lock);
        pthread_join(memblkmod.setup_tid, NULL);
        memblkmod.setup_started = false;
    }
    pthread_cond_destroy(&memblkmod.job_cond);
    pthread_mutex_destroy(&memblkmod.job_lock);
    pthread_mutex_destroy(&memblkmod.lock);

    return Fail;
}

static void memblkmod_exit(void)
{
    struct lnode *node = NULL;
    struct lnode *next = NULL;

    if (memblkmod.timer_statvfs >= 0) {
        timer_del(memblkmod.timer_statvfs);
        memblkmod.timer_statvfs = -1;
    }

    /* 先停 setup 线程：它可能还在等设备节点或者在等 mkfs 返回，退出路径上
     * worker_mgr_stop() 已经 dsync_abort_all()，等待会立刻返回 */
    pthread_mutex_lock(&memblkmod.job_lock);
    memblkmod.stop = true;
    pthread_cond_broadcast(&memblkmod.job_cond);
    pthread_mutex_unlock(&memblkmod.job_lock);

    if (memblkmod.setup_started) {
        pthread_join(memblkmod.setup_tid, NULL);
        memblkmod.setup_started = false;
    }

    /* 队列里没来得及跑的作业 */
    pthread_mutex_lock(&memblkmod.job_lock);
    for (node = memblkmod.jobs.next; node != &memblkmod.jobs; node = next) {
        next = node->next;
        list_del(node);
        free(container_of(node, struct memblk_job, node));
        memblkmod.job_num--;
    }
    pthread_mutex_unlock(&memblkmod.job_lock);

    pthread_mutex_lock(&memblkmod.lock);
    for (node = memblkmod.devs.next; node != &memblkmod.devs; node = next) {
        struct memblk_dev *dev = container_of(node, struct memblk_dev, node);

        next = node->next;
        if (dev->state == MemblkStateMounted) {
            if (umount(dev->mntpath) != 0) {
                derror("[%s] umount %s failed, errno: %d\n", dev->name,
                    dev->mntpath, errno);
            }
        }
        list_del(node);
        free(dev);
        memblkmod.dev_num--;
    }
    pthread_mutex_unlock(&memblkmod.lock);

    dcomp_record_del(&memblkmod.comp);

    pthread_cond_destroy(&memblkmod.job_cond);
    pthread_mutex_destroy(&memblkmod.job_lock);
    pthread_mutex_destroy(&memblkmod.lock);

    dprint("[%s] exit\n", ModMemblkName);
    return;
}

DCOMP_INIT_NORMPRIO(memblkmod_init);
DCOMP_EXIT_NORMPRIO(memblkmod_exit);
