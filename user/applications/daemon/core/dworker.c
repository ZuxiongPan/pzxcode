#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dcontext.h"

const int payload_max_len = MSGBUF_SIZE - sizeof(dmsg_t);

static inline dmsg_t* get_msg_addr(dmsg_queue_t *queue, int idx)
{
    return (dmsg_t *)((char *)queue->msgs + idx * MSGBUF_SIZE);
}

static void* worker_thread(void* arg)
{
    (void)arg;
    dctx_t *ctx = dctx_instance();
    dmsg_t *msg = NULL;
    dmsg_queue_t *queue = &ctx->worker_mgr->queue;

    while (true)
    {
        pthread_mutex_lock(&queue->mutex);
        while (queue->count == 0 && atomic_load(&ctx->status))
        {
            pthread_cond_wait(&queue->cond, &queue->mutex);
        }
        if (!atomic_load(&ctx->status))
        {
            pthread_mutex_unlock(&queue->mutex);
            break;
        }
        msg = get_msg_addr(queue, queue->head);
        queue->head = (queue->head + 1) % MSGQUEUE_SIZE;
        queue->count--;
        pthread_mutex_unlock(&queue->mutex);
        /**
         * todo: module process message
         */
        atomic_fetch_sub(&msg->refcnt, 1);
    }

    return NULL;
}

int message_enqueue(uint32_t msgid, int src, int dst,
    int payload_len, void *payload)
{
    dctx_t *ctx = dctx_instance();
    dmsg_queue_t *queue = &ctx->worker_mgr->queue;

    pthread_mutex_lock(&queue->mutex);
    queue->total++;
    dmsg_t *msg = get_msg_addr(queue, queue->tail);
    if (queue->count >= MSGQUEUE_SIZE || atomic_load(&msg->refcnt) > 0
        || payload_len > payload_max_len)
    {
        queue->drop++;
        pthread_mutex_unlock(&queue->mutex);
        derror("message_enqueue: no space for new message\n");
        return Fail;
    }

    msg->msgid = msgid;
    msg->src_mid = src;
    msg->dst_mid = dst;
    atomic_init(&msg->refcnt, 1);
    msg->payload_len = payload_len;
    memcpy(msg->payload, payload, payload_len);
    queue->tail = (queue->tail + 1) % MSGQUEUE_SIZE;
    queue->count++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    return Success;
}

int worker_manager_init(dworker_mgr_t* mgr)
{
    // here we shoule check mgr is valid, but this is a key init, mgr must be valid
    int tmp = 0, inner_ret = 0;
    dmsg_queue_t *queue = &mgr->queue;

    // 1. init message queue, first version we use a fixed-size array
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
    queue->count = 0;
    queue->head = 0;
    queue->tail = 0;
    queue->msgs = calloc(MSGQUEUE_SIZE, MSGBUF_SIZE);
    if (queue->msgs == NULL)
    {
        derror("worker_init: failed to malloc message queue\n");
        return Fail;
    }

    // 2. init worker threads
    atomic_init(&mgr->busy, 0);
    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        inner_ret = pthread_create(&mgr->workers[i].tid, NULL, worker_thread, NULL);
        if (inner_ret != 0)
        {
            mgr->workers[i].valid = false;
            derror("worker_init: failed to create worker thread %d\n", i);
        }
        else
        {
            mgr->workers[i].valid = true;
            tmp++;
        }
    }

    dprint("worker_init: created %d worker threads, expect %d\n", tmp, WORKER_MAXNUM);
    return Success;
}

void worker_manager_destroy(dworker_mgr_t* mgr)
{
    pthread_cond_broadcast(&mgr->queue.cond);
    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        if (mgr->workers[i].valid)
        {
            pthread_join(mgr->workers[i].tid, NULL);
        }
    }
    
    if (mgr->queue.msgs != NULL)
    {
        free(mgr->queue.msgs);
    }
    
    return ;
}
