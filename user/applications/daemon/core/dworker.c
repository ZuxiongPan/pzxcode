#include <stdlib.h>
#include <string.h>

#include "dlog.h"
#include "dextension.h"
#include "core/dcontext.h"
#include "core/dworker.h"

static const unsigned int spool_data_maxlen = SMALL_POOL_SLOT_SIZE - sizeof(struct dtask);
static const unsigned int mpool_data_maxlen = MEDIUM_POOL_SLOT_SIZE - sizeof(struct dtask);
static const unsigned int lpool_data_maxlen = LARGE_POOL_SLOT_SIZE - sizeof(struct dtask);

static char *taskmem = NULL;
static struct worker_mgr worker_mgr = { 0 };

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
    int bit_pos = -1;
    int slot_idx = -1;

    for (unsigned int i = 0; i < pool->bitmap_size; i++)
    {
        if (pool->bitmap[i] == BITMAP_UNIT_FULL)
        {
            continue;
        }
        // here we check bitmap[i] is not all 1, following code will not invalid behavior
        bit_pos = __builtin_ctzll(~pool->bitmap[i]);
        pool->bitmap[i] |= (1 << bit_pos);
        slot_idx = i * BITMAP_UNIT_BITS + bit_pos;
        ret = pool->base + slot_idx * pool->slot_size;
        ret->slot_idx = slot_idx;
        ret->next = NULL;
        break;
    }

    return ret;
}

static inline void recycle_task(struct dtask *task)
{
    int pool = pool_select(task->data_size);
    if (unlikely(pool == PoolMax))
    {
        derror("invalid task size %u\n", task->data_size);
        return ;
    }

    struct dtask_pool *pool = &worker_mgr.queue.pools[pool];
    pool->bitmap[task->slot_idx / BITMAP_UNIT_BITS] &= ~(1 << (task->slot_idx & (BITMAP_UNIT_BITS - 1)));

    return;
}

static void* worker_thread(void *arg)
{
    UNUSED(arg);
    char buffer[LARGE_POOL_SLOT_SIZE];
    struct dtask *task = NULL;
    struct dctx_t *ctx = dctx_instance();
    struct dtask_queue *queue = &worker_mgr.queue;

    while (atomic_load(&ctx->status))
    {
        pthread_mutex_lock(&queue->lock);
        while (queue->count == 0 && atomic_load(&ctx->status))
        {
            pthread_cond_wait(&queue->cond, &queue->lock);
        }
        if (!atomic_load(&ctx->status))
        {
            pthread_mutex_unlock(&queue->lock);
            break;
        }

        atomic_fetch_add(&worker_mgr.busy, 1);
        task = queue->head;
        queue->head = task->next;
        if (queue->head == NULL)
        {
            queue->tail = NULL;
        }
        queue->count--;
        memset(buffer, 0, LARGE_POOL_SLOT_SIZE);
        memcpy(buffer, task, sizeof(struct dtask) + task->data_size);
        recycle_task(task);
        pthread_mutex_unlock(&queue->lock);

        /** todo
            process_task(buffer);
         */
        atomic_fetch_sub(worker_mgr.busy, 1);
    }

    return NULL;
}

static void* monitor_thread(void *arg)
{
    UNUSED(arg);
    struct dctx_t *ctx = dctx_instance();

    while (atomic_load(&ctx->status))
    {
        struct timeval tv = { 0, MONITOR_INTERVAL_MS * 1000 };
        select(0, NULL, NULL, NULL, &tv);
        dprint("monitor: busy workers %u\n", atomic_load(&ctx->worker_mgr->busy));
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
    uint8_t tmp = 0;
    int inner_ret = 0;

    worker_mgr.initialized = false;
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
            tmp++;
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
    dprint("created %d worker threads, expect %d\n", tmp, WORKER_MAXNUM);
    return Success;
}

void worker_mgr_destroy(void)
{
    if (!worker_mgr.initialized)
    {
        return;
    }

    worker_mgr.initialized = false;
    pthread_mutex_lock(&worker_mgr.queue.lock);
    worker_mgr.queue.count = 0;
    worker_mgr.queue.head = NULL;
    worker_mgr.queue.tail = NULL;
    pthread_mutex_unlock(&worker_mgr.queue.lock);
    pthread_cond_broadcast(&worker_mgr.queue.cond);
    
    free(taskmem);

    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        if (worker_mgr.workers[i].valid)
        {
            pthread_join(worker_mgr.workers[i].tid, NULL);
        }
    }

    if (worker_mgr.monitor.valid)
    {
        pthread_join(worker_mgr.monitor.tid, NULL);
    }

    return;
}

int task_enqueue_by_id(int srcid, int dstid, unsigned int msgid,
    unsigned int data_size, const char *data)
{
    int pool = pool_select(data_size);
    int ret = Success;

    pthread_mutex_lock(&worker_mgr.queue.lock);
    worker_mgr.queue.total++;
    if (likely(pool != PoolMax))
    {
        struct dtask *task = alloc_task(&worker_mgr.queue.pools[pool]);
        if (task == NULL)
        {
            derror("failed to alloc task slot\n");
            worker_mgr.queue.drop++;
            ret = Fail;
        }
        else
        {
            task->srcid = srcid;
            task->dstinfo.dst.id = dstid;
            task->dstinfo.type = DEST_ID;
            task->msgid = msgid;
            task->data_size = data_size;
            memcpy(task->data, data, data_size);
            worker_mgr.queue.count++;
            if (worker_mgr.queue.head == NULL)
            {
                worker_mgr.queue.head = task;
            }
            else
            {
                worker_mgr.queue.tail->next = task;
            }
            worker_mgr.queue.tail = task;
            pthread_cond_signal(&worker_mgr.queue.cond);
        }
    }
    else
    {
        derror("task size %d is too large\n", data_size);
        worker_mgr.queue.drop++;
        ret = Fail;
    }
    pthread_mutex_unlock(&worker_mgr.queue.lock);

    return ret;
}

int task_enqueue_by_name(int srcid, const char *dst_name, unsigned int msgid,
    unsigned int data_size, const char *data)
{
    int ret = Success;
    int pool = pool_select(data_size);

    pthread_mutex_lock(&worker_mgr.queue.lock);
    worker_mgr.queue.total++;
    if (likely(pool != PoolMax))
    {
        struct dtask *task = alloc_task(&worker_mgr.queue.pools[pool]);
        if (task == NULL)
        {
            derror("failed to alloc task slot\n");
            worker_mgr.queue.drop++;
            ret = Fail;
        }
        else
        {
            task->srcid = srcid;
            task->dstinfo.dst.name = dst_name;
            task->dstinfo.type = DEST_NAME;
            task->msgid = msgid;
            task->data_size = data_size;
            memcpy(task->data, data, data_size);
            worker_mgr.queue.count++;
            if (worker_mgr.queue.head == NULL)
            {
                worker_mgr.queue.head = task;
            }
            else
            {
                worker_mgr.queue.tail->next = task;
            }
            worker_mgr.queue.tail = task;
            pthread_cond_signal(&worker_mgr.queue.cond);
        }
    }
    else
    {
        derror("task size %d is too large\n", data_size);
        worker_mgr.queue.drop++;
        ret = Fail;
    }
    pthread_mutex_unlock(&worker_mgr.queue.lock);

    return ret;
}
