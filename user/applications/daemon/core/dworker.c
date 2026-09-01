#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dmodule.h"
#include "core/dchannel.h"
#include "module/dmsgid.h"
#include "lib/cJSON.h"

static const int task_max_needed = TASK_DATA_MAXSIZE + sizeof(dtask_t);
static int process_task(char *buffer);
static void rawstr_parse(const char *rawstr, int *real_dst, unsigned int *msgid);

static inline dtask_t* get_task_addr(task_queue_t *queue, unsigned int offset)
{
    return (dtask_t *)(queue->tasks + offset);
}

static void* worker_thread(void* arg)
{
    (void)arg;
    int inner_ret = Success;
    char buffer[task_max_needed];
    dctx_t *ctx = dctx_instance();
    dtask_t *task = NULL;
    task_queue_t *queue = &ctx->worker_mgr->queue;

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
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
        atomic_fetch_add(&ctx->worker_mgr->busy, 1);
        task = get_task_addr(queue, queue->first_offset);
        queue->first_offset = task->next_offset;
        /** here we use temporary buffer to store task data
         *  to avoid after unlock queue the data is polluted
        */
        memcpy(buffer, task, sizeof(dtask_t) + task->data_size);
        queue->count--;
        pthread_mutex_unlock(&queue->mutex);
        /* process task */
        inner_ret = process_task(buffer);
        ddebug("process task ret %d\n", inner_ret);
        atomic_fetch_sub(&ctx->worker_mgr->busy, 1);
    }

    return NULL;
}

int task_enqueue(dtask_datatype_e datatype, int src, int dst,
    unsigned int msgid, unsigned int data_size, const char *data)
{
    dctx_t *ctx = dctx_instance();
    task_queue_t *queue = &ctx->worker_mgr->queue;
    unsigned int aligned = (data_size + 7) & ~7;    // 8 bytes align
    unsigned int required = sizeof(dtask_t) + aligned;

    if (required > task_max_needed)
    {
        pthread_mutex_lock(&queue->mutex);
        queue->total++;
        queue->drop++;
        pthread_mutex_unlock(&queue->mutex);
        derror("data_size %d is too large\n", data_size);
        return Fail;
    }

    dtask_t *last_task = NULL;
    dtask_t *new_task = NULL;
    pthread_mutex_lock(&queue->mutex);
    queue->total++;

    if (queue->count == 0)
    {
        queue->first_offset = 0;
        queue->last_offset = 0;
        queue->idle_offset = 0;
    }
    
    unsigned int target_offset = queue->idle_offset;
    
    if (queue->idle_offset >= queue->first_offset)
    {
        if ((TASK_QUEUE_BYTES - queue->idle_offset) < required)
        {
            if (queue->first_offset < required)
            {
                derror("there is no space for new task\n");
                queue->drop++;
                pthread_mutex_unlock(&queue->mutex);
                return Fail;
            }
            target_offset = 0;
        }
    }
    else
    {
        if ((queue->first_offset - queue->idle_offset) < required)
        {
            derror("there is no space for new task\n");
            queue->drop++;
            pthread_mutex_unlock(&queue->mutex);
            return Fail;
        }
    }

    if (queue->count > 0)
    {
        last_task = get_task_addr(queue, queue->last_offset);
        last_task->next_offset = target_offset;
    }

    new_task = get_task_addr(queue, target_offset);
    new_task->datatype = datatype;
    new_task->msgid = msgid;
    new_task->src_compid = src;
    new_task->dst_compid = dst;
    new_task->data_size = data_size;
    new_task->next_offset = target_offset + required;
    if (data != NULL && data_size > 0)
    {
        memcpy(new_task->data, data, data_size);
    }
    queue->last_offset = target_offset;
    queue->idle_offset = new_task->next_offset;
    queue->count++;

    //dprint("task info: datatype[%d], src[0x%x], dst[0x%x], msgid[0x%x], data_size[%d], next_offset[0x%x]\n", \
        datatype, src, dst, msgid, data_size, new_task->next_offset);
    //dprint("queue info: first_offset[0x%x], last_offset[0x%x], idle_offset[0x%x], count[%d]\n", \
        queue->first_offset, queue->last_offset, queue->idle_offset, queue->count);

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    return Success;
}

int worker_manager_init(dworker_mgr_t* mgr)
{
    // here we shoule check mgr is valid, but this is a key init, mgr must be valid
    uint8_t tmp = 0;
    int inner_ret = 0;
    task_queue_t *queue = &mgr->queue;

    // 1. init task queue, first version we use a fixed-size array
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
    queue->tasks = calloc(1, TASK_QUEUE_BYTES);
    if (queue->tasks == NULL)
    {
        derror("failed to malloc task queue\n");
        return Fail;
    }
    queue->first_offset = 0;
    queue->last_offset = 0;
    queue->idle_offset = 0;
    queue->count = 0;
    queue->total = 0;
    queue->drop = 0;

    // 2. init worker threads
    atomic_init(&mgr->busy, 0);
    for (int i = 0; i < WORKER_MAXNUM; i++)
    {
        inner_ret = pthread_create(&mgr->workers[i].tid, NULL, worker_thread, NULL);
        if (inner_ret != 0)
        {
            mgr->workers[i].valid = false;
            derror("failed to create worker thread %d\n", i);
        }
        else
        {
            mgr->workers[i].valid = true;
            tmp++;
        }
    }

    mgr->valid = tmp;
    dprint("created %d worker threads, expect %d\n", tmp, WORKER_MAXNUM);
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
    
    if (mgr->queue.tasks != NULL)
    {
        free(mgr->queue.tasks);
    }
    
    return ;
}

static int process_task(char *buffer)
{
    dtask_t *task = (dtask_t *)buffer;
    int real_dst = DCOMPID_NONE;
    unsigned int msgid = 0;
    int ret = Success;

    switch (task->datatype)
    {
        case DataModuleMsg:
        case DataBinaryToModule:
            ret = dmodule_handle(buffer);
            break;
        case DataRawString:
            rawstr_parse(task->data, &real_dst, &msgid);
            task->dst_compid = real_dst;
            task->msgid = msgid;
            ret = dmodule_handle(buffer);
            break;
        case DataToOuter:   
            ret = dchannel_write_to_outer(buffer);
            break;
        default:
            derror("unknown task datatype %d\n", task->datatype);
            break;
    }

    return ret;
}

static void rawstr_parse(const char *rawstr, int *real_dst, unsigned int *msgid)
{
    *real_dst = DCOMPID_NONE;
    *msgid = 0;

    cJSON *root = cJSON_Parse(rawstr);
    if (root == NULL)
    {
        derror("failed to parse rawstr %s\n", rawstr);
        return ;
    }

    cJSON *dst = cJSON_GetObjectItem(root, "target");
    if (dst == NULL)
    {
        derror("failed to parse rawstr %s, no target field\n", rawstr);
        cJSON_Delete(root);
        return ;
    }

    const dcomp_t *comp = find_dcomponent_by_name(dst->valuestring, Layer_Module);
    if (comp == NULL)
    {
        derror("target not found\n");
        cJSON_Delete(root);
        return ;
    }

    *real_dst = comp->dcomp_id;
    *msgid = MSGID_JSON_RAWSTR;

    cJSON_Delete(root);
    return ;
}