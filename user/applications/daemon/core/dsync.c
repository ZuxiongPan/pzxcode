// for pthread_cond_clockwait
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

#include "dlog.h"
#include "dconf.h"
#include "dextension.h"
#include "core/dworker.h"
#include "core/dsync.h"

// a waiter keeps its worker out of the queue for the whole blocking time, so at
// least one worker must stay free to deliver the very message that wakes it up.
// the budget is derived from real_workers at runtime because thread creation can
// come up short, a compile time limit would allow blocking all of them
#define DSYNC_RESERVE_WORKERS 1U

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;

static struct lnode g_pending[SyncKindMax];
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

// the budget guards the worker pool, not a kind: SyncChild and SyncMsg waiters
// occupy the same workers, a per kind counter would let 3 + 3 block a pool of 4
static atomic_uchar g_blocked;
static atomic_bool g_abort;

static const char *g_kind_name[SyncKindMax] = {
    [SyncChild] = "child",
    [SyncMsg] = "msg",
};

static void pending_init(void)
{
    for (unsigned int i = 1; i < SyncKindMax; i++)
    {
        lnode_init(&g_pending[i]);
    }
    atomic_init(&g_abort, false);

    return ;
}

static unsigned int dsync_capacity(void)
{
    unsigned int total = worker_total();

    return (total > DSYNC_RESERVE_WORKERS) ? (total - DSYNC_RESERVE_WORKERS) : 0;
}

void dsync_init(struct dsync *unit, unsigned int kind, unsigned int key)
{
    if (unit == NULL)
    {
        return ;
    }

    memset(unit, 0, sizeof(struct dsync));
    unit->kind = kind;
    unit->key = key;
    lnode_init(&unit->node);

    return ;
}

void dsync_arm(struct dsync *unit)
{
    if (unit == NULL || unit->kind == 0 || unit->kind >= SyncKindMax)
    {
        return ;
    }

    // this function guard that pending_init will be called only once
    (void)pthread_once(&g_once, pending_init);

    pthread_mutex_lock(&g_lock);
    if (!unit->armed)
    {
        list_add_tail(&unit->node, &g_pending[unit->kind]);
        unit->armed = true;
    }
    pthread_mutex_unlock(&g_lock);

    return ;
}

void dsync_cancel(struct dsync *unit)
{
    if (unit == NULL)
    {
        return ;
    }

    (void)pthread_once(&g_once, pending_init);

    pthread_mutex_lock(&g_lock);
    if (unit->armed)
    {
        list_del(&unit->node);
        lnode_init(&unit->node);
        unit->armed = false;
    }
    pthread_mutex_unlock(&g_lock);

    return ;
}

int dsync_wait(struct dsync *unit, uint64_t timeout_ms, int *status)
{
    struct timespec ts = { 0 };
    unsigned int cap = 0;
    int ret = 0;

    if (unit == NULL || status == NULL ||
        unit->kind == 0 || unit->kind >= SyncKindMax)
    {
        return -EINVAL;
    }

    (void)pthread_once(&g_once, pending_init);

    // reserve a blocking slot before touching the pending list: two waiters that
    // only read a count would both pass and block, the atomic add is what makes
    // "one worker stays free" hold. it never blocks, a caller that cannot be
    // admitted is told so instead of being queued behind the budget
    cap = dsync_capacity();
    if (atomic_fetch_add(&g_blocked, 1) >= cap)
    {
        atomic_fetch_sub(&g_blocked, 1);
        derror("dsync: %s wait refused, %u blocked of %u workers\n",
            g_kind_name[unit->kind], (unsigned int)atomic_load(&g_blocked),
            worker_total());
        return -EBUSY;
    }

    if (timeout_ms != 0)
    {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += (time_t)(timeout_ms / 1000);
        ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
    }

    pthread_mutex_lock(&g_lock);
    if (!unit->armed)
    {
        list_add_tail(&unit->node, &g_pending[unit->kind]);
        unit->armed = true;
    }

    while (!unit->done)
    {
        int wret = 0;

        if (atomic_load(&g_abort))
        {
            ret = -ECANCELED;
            break;
        }

        if (timeout_ms == 0)
        {
            wret = pthread_cond_wait(&g_cond, &g_lock);
        }
        else
        {
            wret = pthread_cond_clockwait(&g_cond, &g_lock, CLOCK_MONOTONIC, &ts);
        }

        if (wret == 0)
        {
            continue;
        }

        if (wret == ETIMEDOUT)
        {
            // the deadline may fire in the same instant a completion lands, the
            // done flag decides which one wins instead of the return code
            if (!unit->done)
            {
                ret = -ETIMEDOUT;
                break;
            }
            continue;
        }

        derror("dsync: cond wait failed, ret[%d]\n", wret);
        ret = -wret;
        break;
    }

    // every exit path unlinks here: the completion side never touches the node
    // once done is set, so the stack frame stays valid until this point
    if (unit->armed)
    {
        list_del(&unit->node);
        lnode_init(&unit->node);
        unit->armed = false;
    }

    if (ret == 0)
    {
        *status = unit->status;
    }
    pthread_mutex_unlock(&g_lock);

    atomic_fetch_sub(&g_blocked, 1);

    return ret;
}

bool dsync_can_block(void)
{
    return (unsigned int)atomic_load(&g_blocked) < dsync_capacity();
}

int dsync_complete(unsigned int kind, unsigned int key, int status)
{
    struct lnode *node = NULL;
    int found = -ENOENT;

    if (kind == 0 || kind >= SyncKindMax)
    {
        return -EINVAL;
    }

    (void)pthread_once(&g_once, pending_init);

    pthread_mutex_lock(&g_lock);
    for (node = g_pending[kind].next; node != &g_pending[kind]; node = node->next)
    {
        struct dsync *unit = container_of(node, struct dsync, node);

        // a completed unit keeps its node until the waiter unlinks it, skip it so
        // a late completion cannot overwrite the status already handed out
        if (unit->key != key || unit->done)
        {
            continue;
        }

        unit->done = true;
        unit->status = status;
        found = 0;
        break;
    }

    if (found == 0)
    {
        // one cond is shared by every unit, signal() could wake a waiter whose
        // own unit is not done and the intended one would sleep until the deadline
        pthread_cond_broadcast(&g_cond);
    }
    pthread_mutex_unlock(&g_lock);

    return found;
}

void dsync_abort_all(void)
{
    (void)pthread_once(&g_once, pending_init);

    atomic_store(&g_abort, true);

    pthread_mutex_lock(&g_lock);
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);

    return ;
}

void dsync_info(void)
{
    char buf[LINUX_PAGE_SIZE];
    unsigned int cap = 0;
    int bytes = 0;

    (void)pthread_once(&g_once, pending_init);

    cap = dsync_capacity();
    bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "----------[Sync]----------\n");
    bytes += snprintf(buf + bytes, sizeof(buf) - bytes,
        "worker %u\tcapacity %u\tblocked %u\tabort %u\n",
        worker_total(), cap, (unsigned int)atomic_load(&g_blocked),
        (unsigned int)atomic_load(&g_abort));
    bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "kind\tpending\t\tdone\n");

    pthread_mutex_lock(&g_lock);
    for (unsigned int i = 1; i < SyncKindMax; i++)
    {
        unsigned int cnt = 0;
        unsigned int fin = 0;
        struct lnode *node = NULL;

        for (node = g_pending[i].next; node != &g_pending[i]; node = node->next)
        {
            struct dsync *unit = container_of(node, struct dsync, node);

            cnt++;
            if (unit->done)
            {
                fin++;
            }
        }

        bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "%s\t%u\t\t%u\n",
            g_kind_name[i], cnt, fin);
    }
    pthread_mutex_unlock(&g_lock);

    printf("%s", buf);

    return ;
}
