// for pthread_cond_clockwait
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "dlog.h"
#include "dextension.h"
#include "core/dcontext.h"
#include "dcomp_info.h"
#include "core/dworker.h"
#include "core/dsync.h"

// a slot must be able to hold at least the header when the payload is empty,
// otherwise pool_select() would push every task up into the medium pool
_Static_assert(sizeof(struct dtask) <= SMALL_POOL_SLOT_SIZE,
    "dtask header exceeds the smallest pool slot");

static const unsigned int spool_data_maxlen = SMALL_POOL_SLOT_SIZE - sizeof(struct dtask);
static const unsigned int mpool_data_maxlen = MEDIUM_POOL_SLOT_SIZE - sizeof(struct dtask);
static const unsigned int lpool_data_maxlen = LARGE_POOL_SLOT_SIZE - sizeof(struct dtask);

static uint8_t real_workers = 0;
static char *taskmem = NULL;
static struct dworker_mgr worker_mgr = { 0 };

static inline int pool_select(unsigned int task_size)
{
    int ret = PoolMax;

    if (task_size <= spool_data_maxlen)
    {
        ret = SmallPool;
    }
    else if (task_size <= mpool_data_maxlen)
    {
        ret = MediumPool;
    }
    else if (task_size <= lpool_data_maxlen)
    {
        ret = LargePool;
    }

    return ret;
}

// this function must be called with lock held
static inline struct dtask* alloc_task(struct dtask_pool *pool)
{
    struct dtask *ret = NULL;
    unsigned int bit_pos = 0;
    unsigned int slot_idx = 0;

    for (unsigned int i = 0; i < pool->bitmap_size; i++)
    {
        if (pool->bitmap[i] == BITMAP_UNIT_FULL)
        {
            continue;
        }
        // here we check bitmap[i] is not all 1, following code will not be invalid
        bit_pos = __builtin_ctz(~pool->bitmap[i]);
        pool->bitmap[i] |= (1U << bit_pos);
        slot_idx = i * BITMAP_UNIT_BITS + bit_pos;
        ret = (struct dtask *) (pool->base + slot_idx * pool->slot_size);
        ret->id = worker_mgr.queue.total;
        ret->slot_idx = slot_idx;
        ret->next = NULL;
        break;
    }

    return ret;
}

static inline void recycle_slot(int poolid, unsigned int slot_idx)
{
    struct dtask_pool *pool = &worker_mgr.queue.pools[poolid];

    pool->bitmap[slot_idx / BITMAP_UNIT_BITS] &=
        ~(1U << (slot_idx & (BITMAP_UNIT_BITS - 1)));

    return ;
}

static inline void process_task(struct dtask *task)
{
    int ret = -ENOENT;
    // the destination is resolved to an id before enqueue, so there is exactly
    // one lookup path here; a stale id (component unregistered after enqueue)
    // simply misses, it can never land on a different component
    const struct dcomp *comp = find_dcomp_by_id(task->dstid);
    UNUSED(ret);

    if (comp == NULL)
    {
        derror("component id[%u] not found, msgid[0x%x]\n", task->dstid, task->msgid);
        return ;
    }

    for (unsigned int i = 0; i < comp->handle_num; i++)
    {
        if (comp->handlers[i].msgid == task->msgid)
        {
            ret = comp->handlers[i].func(comp, task->srcid, task->data_size, task->data);
            break;
        }
    }

    ddebug("process task msgid[0x%x], ret[%d]\n", task->msgid, ret);

    return ;
}

static void* worker_thread(void *arg)
{
    UNUSED(arg);
    struct dtask *task = NULL;
    struct dctx *ctx = dctx_instance();
    struct dtask_queue *queue = &worker_mgr.queue;

    while (true)
    {
        pthread_mutex_lock(&queue->lock);
        if (!atomic_load(&ctx->status) || atomic_load(&worker_mgr.stop))
        {
            pthread_mutex_unlock(&queue->lock);
            break;
        }

        while (queue->count == 0 &&
            atomic_load(&ctx->status) && !atomic_load(&worker_mgr.stop))
        {
            pthread_cond_wait(&queue->cond, &queue->lock);
        }

        // the wait also returns when the shutdown broadcast arrives, and then
        // there is nothing to dequeue: let the top of the loop decide to stop
        // instead of dereferencing an empty head below
        if (unlikely(queue->count == 0))
        {
            pthread_mutex_unlock(&queue->lock);
            continue;
        }

        atomic_fetch_add(&worker_mgr.busy, 1);
        task = queue->head;
        queue->head = task->next;
        if (queue->head == NULL)
        {
            queue->tail = NULL;
        }
        queue->count--;
        pthread_mutex_unlock(&queue->lock);

        // the slot keeps its bitmap bit set for the whole callback, so
        // alloc_task() can never hand it out again and the payload stays valid
        // in place - this is what makes the copy the old version needed obsolete
        unsigned int slot_idx = task->slot_idx;
        int poolid = pool_select(task->data_size);

        process_task(task);

        // recycle only once the callback returned: recycling first would let the
        // next enqueue allocate this slot and overwrite what the handler reads.
        // the header is not read below, a handler must not have to be trusted
        // with keeping it intact
        pthread_mutex_lock(&queue->lock);
        if (unlikely(poolid == PoolMax))
        {
            // unreachable: task_submit() never allocates a slot for such a size
            derror("task slot cannot be mapped back to a pool\n");
        }
        else
        {
            recycle_slot(poolid, slot_idx);
        }
        pthread_mutex_unlock(&queue->lock);

        atomic_fetch_sub(&worker_mgr.busy, 1);
    }

    return NULL;
}

static void* monitor_thread(void *arg)
{
    UNUSED(arg);
    struct dctx *ctx = dctx_instance();
    struct dtask_queue *queue = &worker_mgr.queue;
    struct timespec ts;

    while (true)
    {
        pthread_mutex_lock(&worker_mgr.monitor_lock);
        if (!atomic_load(&ctx->status) || atomic_load(&worker_mgr.stop))
        {
            pthread_mutex_unlock(&worker_mgr.monitor_lock);
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += MONITOR_INTERVAL_SEC;
        pthread_cond_clockwait(&worker_mgr.monitor_cond, &worker_mgr.monitor_lock,
            CLOCK_MONOTONIC, &ts);
        pthread_mutex_unlock(&worker_mgr.monitor_lock);

        pthread_mutex_lock(&queue->lock);
        unsigned int pending = queue->count;
        pthread_mutex_unlock(&queue->lock);

        if (!atomic_load(&ctx->status) || atomic_load(&worker_mgr.stop))
        {
            break;
        }

        if (atomic_load(&worker_mgr.busy) == real_workers)
        {
            demerg("monitor: all %u workers busy, %u tasks pending\n",
                    real_workers, pending);
        }
    }

    return NULL;
}

static void task_queue_init(struct dtask_queue *q)
{
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);

    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->total = 0;
    q->drop = 0;

    // init task pools
    q->pools[SmallPool].base = taskmem;
    q->pools[SmallPool].slot_size = SMALL_POOL_SLOT_SIZE;
    q->pools[SmallPool].slots = SMALL_POOL_SLOTS;
    q->pools[SmallPool].bitmap_size = (SMALL_POOL_SLOTS + BITMAP_UNIT_BITS - 1) / BITMAP_UNIT_BITS;

    q->pools[MediumPool].base = taskmem + SMALL_POOL_SIZE;
    q->pools[MediumPool].slot_size = MEDIUM_POOL_SLOT_SIZE;
    q->pools[MediumPool].slots = MEDIUM_POOL_SLOTS;
    q->pools[MediumPool].bitmap_size = (MEDIUM_POOL_SLOTS + BITMAP_UNIT_BITS - 1) / BITMAP_UNIT_BITS;

    q->pools[LargePool].base = taskmem + SMALL_POOL_SIZE + MEDIUM_POOL_SIZE;
    q->pools[LargePool].slot_size = LARGE_POOL_SLOT_SIZE;
    q->pools[LargePool].slots = LARGE_POOL_SLOTS;
    q->pools[LargePool].bitmap_size = (LARGE_POOL_SLOTS + BITMAP_UNIT_BITS - 1) / BITMAP_UNIT_BITS;

    return ;
}

int worker_mgr_init(void)
{
    int inner_ret = 0;

    worker_mgr.initialized = false;
    worker_mgr.stopped = false;
    real_workers = 0;
    atomic_init(&worker_mgr.stop, false);

    pthread_mutex_init(&worker_mgr.monitor_lock, NULL);
    inner_ret = pthread_cond_init(&worker_mgr.monitor_cond, NULL);
    if (inner_ret != 0)
    {
        derror("monitor cond init failed: %d\n", inner_ret);
        pthread_mutex_destroy(&worker_mgr.monitor_lock);
        return Fail;
    }

    taskmem = calloc(1, TASK_QUEUE_SIZE);
    if (taskmem == NULL)
    {
        derror("failed to alloc task memory\n");
        pthread_cond_destroy(&worker_mgr.monitor_cond);
        pthread_mutex_destroy(&worker_mgr.monitor_lock);
        return Fail;
    }

    task_queue_init(&worker_mgr.queue);
    atomic_init(&worker_mgr.busy, 0);
    worker_mgr.initialized = true;

    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        inner_ret = pthread_create(&worker_mgr.workers[i].tid, NULL, worker_thread, NULL);
        if (inner_ret != 0)
        {
            worker_mgr.workers[i].valid = false;
            derror("failed to create worker thread %d\n", i);
        }
        else
        {
            worker_mgr.workers[i].valid = true;
            real_workers++;
        }
    }

    inner_ret = pthread_create(&worker_mgr.monitor.tid, NULL, monitor_thread, NULL);
    if (inner_ret != 0)
    {
        worker_mgr.monitor.valid = false;
        derror("failed to create monitor thread\n");
    }
    else
    {
        worker_mgr.monitor.valid = true;
    }

    if (unlikely(real_workers <= (WORKER_MAXNUM / 2) || !worker_mgr.monitor.valid))
    {
        derror("failed to create worker threads or monitor thread\n");
        return Fail;
    }

    dprint("created worker threads [%d], expect [%d], monitor thread [%d]\n", real_workers, WORKER_MAXNUM, worker_mgr.monitor.valid);
    return Success;
}

void worker_mgr_stop(void)
{
    if (!worker_mgr.initialized || worker_mgr.stopped)
    {
        return;
    }

    worker_mgr.stopped = true;
    atomic_store(&worker_mgr.stop, true);

    // a worker blocked in dsync_wait() never looks at the queue again, and a
    // wait without deadline has no other exit: wake them before join
    dsync_abort_all();

    pthread_mutex_lock(&worker_mgr.queue.lock);
    pthread_cond_broadcast(&worker_mgr.queue.cond);
    pthread_mutex_unlock(&worker_mgr.queue.lock);

    pthread_mutex_lock(&worker_mgr.monitor_lock);
    pthread_cond_broadcast(&worker_mgr.monitor_cond);
    pthread_mutex_unlock(&worker_mgr.monitor_lock);

    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        if (worker_mgr.workers[i].valid)
        {
            pthread_join(worker_mgr.workers[i].tid, NULL);
            worker_mgr.workers[i].valid = false;
        }
    }

    if (worker_mgr.monitor.valid)
    {
        pthread_join(worker_mgr.monitor.tid, NULL);
        worker_mgr.monitor.valid = false;
    }

    dprint("all threads stopped\n");

    return ;
}

void worker_mgr_destroy(void)
{
    if (!worker_mgr.initialized)
    {
        return;
    }

    // join before free: a worker may still be copying out of a pool slot,
    // freeing taskmem first left a use-after-free window open
    worker_mgr_stop();

    pthread_mutex_lock(&worker_mgr.queue.lock);
    worker_mgr.queue.count = 0;
    worker_mgr.queue.head = NULL;
    worker_mgr.queue.tail = NULL;
    pthread_mutex_unlock(&worker_mgr.queue.lock);

    pthread_cond_destroy(&worker_mgr.queue.cond);
    pthread_mutex_destroy(&worker_mgr.queue.lock);
    
    pthread_cond_destroy(&worker_mgr.monitor_cond);
    pthread_mutex_destroy(&worker_mgr.monitor_lock);

    // taskmem must be valid, because it was checked when initialized
    free(taskmem);
    taskmem = NULL;
    worker_mgr.initialized = false;

    return;
}

static int task_submit(unsigned int dstid, unsigned int srcid,
    unsigned int msgid, unsigned int data_size, const char *data)
{
    struct dtask_queue *q = &worker_mgr.queue;
    struct dtask *task = NULL;
    int poolid = pool_select(data_size);
    unsigned int dropped = 0;

    if (unlikely(dstid == DCOMPID_RESERVED))
    {
        derror("invalid destination id\n");
        return Fail;
    }

    if (unlikely(data_size > 0 && data == NULL))
    {
        derror("invalid payload: size %u but data is NULL\n", data_size);
        return Fail;
    }

    if (unlikely(atomic_load(&worker_mgr.stop)))
    {
        // nothing drains the queue any more, no point in reserving a slot
        return Fail;
    }

    if (unlikely(poolid == PoolMax))
    {
        derror("task size %u is too large, max %u\n", data_size, lpool_data_maxlen);
        pthread_mutex_lock(&q->lock);
        q->total++;
        q->drop++;
        pthread_mutex_unlock(&q->lock);
        return Fail;
    }

    pthread_mutex_lock(&q->lock);
    q->total++;
    task = alloc_task(&q->pools[poolid]);
    if (task == NULL)
    {
        q->drop++;
        dropped = q->drop;
    }
    pthread_mutex_unlock(&q->lock);

    if (task == NULL)
    {
        derror("task pool[%d] exhausted, size %u, dropped %u\n",
            poolid, data_size, dropped);
        return Fail;
    }

    task->srcid = srcid;
    task->dstid = dstid;
    task->msgid = msgid;
    task->data_size = data_size;

    if (unlikely(atomic_load(&worker_mgr.stop)))
    {
        pthread_mutex_lock(&q->lock);
        recycle_slot(poolid, task->slot_idx);
        pthread_mutex_unlock(&q->lock);
        return Fail;
    }

    if (data_size > 0)
    {
        memcpy(task->data, data, data_size);
    }

    pthread_mutex_lock(&q->lock);
    q->count++;
    if (q->head == NULL)
    {
        q->head = task;
    }
    else
    {
        q->tail->next = task;
    }
    q->tail = task;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);

    return Success;
}

int task_enqueue_by_id(unsigned int srcid, unsigned int dstid, unsigned int msgid,
    unsigned int data_size, const char *data)
{
    return task_submit(dstid, srcid, msgid, data_size, data);
}

int task_enqueue_by_name(unsigned int srcid, const char *dst_name, unsigned int msgid,
    unsigned int data_size, const char *data)
{
    unsigned int dstid = find_fix_dcompid(dst_name);

    return task_submit(dstid, srcid, msgid, data_size, data);
}

unsigned int worker_total(void)
{
    return (unsigned int)real_workers;
}

void dworker_info(void)
{
    int bytes = 0;
    char buf[LINUX_PAGE_SIZE];
    struct dtask_queue *q = &worker_mgr.queue;

    bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "----------[Worker]----------\nactive %u\tbusy %u\n",
        real_workers, atomic_load(&worker_mgr.busy));
    pthread_mutex_lock(&q->lock);
    bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "total %u\tcount %u\tdrop %u\n",
        q->total, q->count, q->drop);
    for (int i = SmallPool; i < PoolMax; i++)
    {
        bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "pool %d bitmap\n", i);
        for (unsigned int j = 0; j < q->pools[i].bitmap_size; j++)
        {
            bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "0x%08x ",
                q->pools[i].bitmap[j]);
        }
        bytes += snprintf(buf + bytes, sizeof(buf) - bytes, "\n");
    }
    pthread_mutex_unlock(&q->lock);
    printf("%s", buf);

    return ;
}