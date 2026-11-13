#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dlog.h"
#include "dextension.h"
#include "core/dcontext.h"
#include "core/dworker.h"

// a task slot must always fit into a stack buffer of the worker thread
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
        ret->slot_idx = slot_idx;
        ret->next = NULL;
        break;
    }

    return ret;
}

static inline void recycle_task(struct dtask *task)
{
    int poolid = pool_select(task->data_size);
    if (unlikely(poolid == PoolMax))
    {
        derror("invalid task size %u\n", task->data_size);
        return ;
    }

    struct dtask_pool *pool = &worker_mgr.queue.pools[poolid];
    pool->bitmap[task->slot_idx / BITMAP_UNIT_BITS] &=
        ~(1U << (task->slot_idx & (BITMAP_UNIT_BITS - 1)));

    return;
}

static inline void process_task(void *buf)
{
    int ret = Success;
    bool handled = false;
    // this buffer must be valid, so skip check
    struct dtask *task = (struct dtask *)buf;
    const struct dcomp *comp = NULL;

    if (task->dstinfo.type == DEST_ID)
    {
        comp = find_dcomp_by_id(task->dstinfo.dst.dstid);
    }
    else if (task->dstinfo.type == DEST_NAME)
    {
        comp = find_dcomp_by_name(task->dstinfo.dst.dstname);
    }

    if (comp == NULL)
    {
        // never print dstname for DEST_ID: the union holds an integer there and
        // passing it to "%s" dereferences a bogus pointer
        if (task->dstinfo.type == DEST_ID)
        {
            derror("component id[%u] not found, msgid[0x%x]\n",
                task->dstinfo.dst.dstid, task->msgid);
        }
        else
        {
            derror("component name[%s] not found, msgid[0x%x]\n",
                task->dstinfo.dst.dstname == NULL ? "(null)" : task->dstinfo.dst.dstname,
                task->msgid);
        }
        return ;
    }

    for (unsigned int i = 0; i < comp->handle_num; i++)
    {
        if (comp->handlers[i].msgid == task->msgid)
        {
            ret = comp->handlers[i].func(comp, task->srcid, task->data_size, task->data);
            handled = true;
            break;
        }
    }

    if (unlikely(!handled))
    {
        ddebug("component[%s] has no handler for msgid[0x%x]\n", comp->name, task->msgid);
    }

    ddebug("process task msgid[0x%x], ret[%d]\n", task->msgid, ret);

    return ;
}

static void* worker_thread(void *arg)
{
    UNUSED(arg);
    char buffer[LARGE_POOL_SLOT_SIZE];
    struct dtask *task = NULL;
    struct dctx *ctx = dctx_instance();
    struct dtask_queue *queue = &worker_mgr.queue;

    while (atomic_load(&ctx->status) && !atomic_load(&worker_mgr.stop))
    {
        pthread_mutex_lock(&queue->lock);
        while (queue->count == 0 &&
            atomic_load(&ctx->status) && !atomic_load(&worker_mgr.stop))
        {
            pthread_cond_wait(&queue->cond, &queue->lock);
        }
        if (!atomic_load(&ctx->status) || atomic_load(&worker_mgr.stop))
        {
            pthread_mutex_unlock(&queue->lock);
            break;
        }

        task = queue->head;
        queue->head = task->next;
        if (queue->head == NULL)
        {
            queue->tail = NULL;
        }
        queue->count--;
        atomic_fetch_add(&worker_mgr.busy, 1);
        pthread_mutex_unlock(&queue->lock);

        // the slot is off the queue now, nobody else can touch it, so the copy
        // can be done outside the global queue lock instead of inside it
        memcpy(buffer, task, sizeof(struct dtask) + task->data_size);

        pthread_mutex_lock(&queue->lock);
        recycle_task(task);
        pthread_mutex_unlock(&queue->lock);

        process_task(buffer);

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
    bool warned = false;

    while (atomic_load(&ctx->status) && !atomic_load(&worker_mgr.stop))
    {
        // absolute CLOCK_MONOTONIC timeout; select() would rewrite its timeval
        // argument and the rest of the sleep becomes a busy loop
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_nsec += (long)MONITOR_INTERVAL_MS * 1000000L;
        while (ts.tv_nsec >= 1000000000L)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }

        pthread_mutex_lock(&queue->lock);
        pthread_cond_timedwait(&worker_mgr.monitor_cond, &queue->lock, &ts);
        unsigned int pending = queue->count;
        pthread_mutex_unlock(&queue->lock);

        if (!atomic_load(&ctx->status) || atomic_load(&worker_mgr.stop))
        {
            break;
        }

        if (atomic_load(&worker_mgr.busy) == real_workers)
        {
            // only log on the transition, otherwise a busy system floods the log
            if (!warned)
            {
                dprint("monitor: all %u workers busy, %u task(s) pending\n",
                    real_workers, pending);
                warned = true;
            }
        }
        else if (warned)
        {
            dprint("monitor: worker available again, %u task(s) pending\n", pending);
            warned = false;
        }
    }

    return NULL;
}

static void task_queue_init(struct dtask_queue *q)
{
    pthread_condattr_t attr;
    int ret = 0;

    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);

    // monitor_cond must be driven by CLOCK_MONOTONIC, otherwise the absolute
    // timestamp built in monitor_thread() would be interpreted as CLOCK_REALTIME
    // and pthread_cond_timedwait() would time out immediately (busy loop)
    ret = pthread_condattr_init(&attr);
    if (ret == 0)
    {
        ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        if (ret != 0)
        {
            derror("condattr_setclock failed: %d\n", ret);
        }
        ret = pthread_cond_init(&worker_mgr.monitor_cond, &attr);
        if (ret != 0)
        {
            derror("monitor cond init failed: %d\n", ret);
        }
        pthread_condattr_destroy(&attr);
    }
    else
    {
        derror("condattr_init failed: %d\n", ret);
        pthread_cond_init(&worker_mgr.monitor_cond, NULL);
    }

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
    taskmem = calloc(1, TASK_QUEUE_SIZE);
    if (taskmem == NULL)
    {
        derror("failed to alloc task memory\n");
        return Fail;
    }

    task_queue_init(&worker_mgr.queue);
    atomic_init(&worker_mgr.busy, 0);
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

    worker_mgr.initialized = true;
    dprint("created %d worker threads, expect %d\n", real_workers, WORKER_MAXNUM);
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

    // both condvars share queue.lock, take it before broadcasting
    pthread_mutex_lock(&worker_mgr.queue.lock);
    pthread_cond_broadcast(&worker_mgr.queue.cond);
    pthread_cond_broadcast(&worker_mgr.monitor_cond);
    pthread_mutex_unlock(&worker_mgr.queue.lock);

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

    dprint("all worker threads stopped\n");

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
    pthread_cond_destroy(&worker_mgr.monitor_cond);
    pthread_mutex_destroy(&worker_mgr.queue.lock);

    free(taskmem);
    taskmem = NULL;
    worker_mgr.initialized = false;

    return;
}

static int task_submit(const struct destinfo *dstinfo, unsigned int srcid,
    unsigned int msgid, unsigned int data_size, const char *data)
{
    struct dtask_queue *q = &worker_mgr.queue;
    struct dtask *task = NULL;
    int poolid = pool_select(data_size);
    unsigned int dropped = 0;

    if (unlikely(data_size > 0 && data == NULL))
    {
        derror("invalid payload: size %u but data is NULL\n", data_size);
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

    if (unlikely(atomic_load(&worker_mgr.stop)))
    {
        pthread_mutex_lock(&q->lock);
        recycle_task(task);
        pthread_mutex_unlock(&q->lock);
        return Fail;
    }

    // the slot is reserved but not linked into the queue yet, so filling it
    // does not have to happen under the global queue lock
    task->srcid = srcid;
    task->dstinfo = *dstinfo;
    task->msgid = msgid;
    task->data_size = data_size;
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
    struct destinfo dstinfo;

    memset(&dstinfo, 0, sizeof(dstinfo));
    dstinfo.type = DEST_ID;
    dstinfo.dst.dstid = dstid;

    return task_submit(&dstinfo, srcid, msgid, data_size, data);
}

int task_enqueue_by_name(unsigned int srcid, const char *dst_name, unsigned int msgid,
    unsigned int data_size, const char *data)
{
    struct destinfo dstinfo;

    if (unlikely(dst_name == NULL))
    {
        derror("destination name is NULL\n");
        return Fail;
    }

    memset(&dstinfo, 0, sizeof(dstinfo));
    dstinfo.type = DEST_NAME;
    dstinfo.dst.dstname = dst_name;

    return task_submit(&dstinfo, srcid, msgid, data_size, data);
}
