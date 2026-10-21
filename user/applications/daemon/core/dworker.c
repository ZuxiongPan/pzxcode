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
#include "channel/chnl_api.h"
#include "common/uk_netlink.h"

#define MODULE_TMPNAME_MAXSIZE 32

static const int task_max_needed = TASK_DATA_MAXSIZE + sizeof(dtask_t);
static int process_task(char *buffer);
static void rawbinary_parse(char *binary, int *real_dst, void **payload,
    unsigned int *real_size, unsigned int *msgid, unsigned int data_size);
static void genlbin_parse(char *binary, int *real_dst, void **payload,
    unsigned int *real_size, unsigned int data_size);

static inline dtask_t* get_task_addr(task_queue_t *queue, unsigned int offset)
{
    return (dtask_t *)(queue->tasks + offset);
}

static void* worker_thread(void* arg)
{
    UNUSED(arg);
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
        process_task(buffer);
        //ddebug("process task ret %d\n", inner_ret);
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

    /*dprint("task info: datatype[%d], src[0x%x], dst[0x%x], msgid[0x%x], data_size[%d], next_offset[0x%x]\n", \
        datatype, src, dst, msgid, data_size, new_task->next_offset);
    dprint("queue info: first_offset[0x%x], last_offset[0x%x], idle_offset[0x%x], count[%d]\n", \
        queue->first_offset, queue->last_offset, queue->idle_offset, queue->count); */

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
    int real_dst = task->dst_compid;
    unsigned int msgid = task->msgid;
    unsigned int data_realsize = task->data_size;
    void *payload = task->data;
    int ret = Success;

    switch (task->datatype)
    {
        case DataRawBinary:
            if ((unsigned int)real_dst == DCOMPID_NONE && msgid == 0)
            {
                rawbinary_parse(task->data, &real_dst, &payload, &msgid, &data_realsize, task->data_size);
            }
            ret = dmodule_handle(task->src_compid, real_dst, msgid, payload, data_realsize);
            break;
        case DataGenlAttrs:
            genlbin_parse(task->data, &real_dst, &payload, &data_realsize, task->data_size);
            ret = dmodule_handle(task->src_compid, real_dst, msgid, payload, data_realsize);
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

static void rawbinary_parse(char *binary, int *real_dst, void **payload,
    unsigned int *msgid, unsigned int *real_size, unsigned int data_size)
{
    if (*binary == '/')
    {
        const char *target = binary + 1;
        char *data = strchr(target, '/');
        char module[MODULE_TMPNAME_MAXSIZE] = { 0 };
        unsigned long len = (data - target);
        if (len > sizeof(module))
        {
            len = sizeof(module) - 1;
        }
        strncpy(module, target, len);
        module[len] = '\0';
        const dcomp_t *comp = find_dcomponent_by_name(module);
        if (comp == NULL)
        {
            derror("target not found\n");
            return ;
        }
        *real_dst = comp->dcompid;
        *msgid = MSGID_SIMPLE_STR;
        *real_size = data_size - (data - binary);
        *payload = data + 1;
    }
/*
    else if (*binary == '{')
    {
        cJSON *root = cJSON_Parse(binary);
        if (root == NULL)
        {
            derror("failed to parse binary %s\n", binary);
            return ;
        }

        cJSON *dst = cJSON_GetObjectItem(root, "target");
        if (dst == NULL)
        {
            derror("failed to parse rawstr %s, no target field\n", rawstr);
            cJSON_Delete(root);
            return ;
        }

        const dcomp_t *comp = find_dcomponent_by_name(dst->valuestring);
        if (comp == NULL)
        {
            derror("target not found\n");
            cJSON_Delete(root);
            return ;
        }

        *real_dst = comp->dcompid;
        *msgid = MSGID_JSON_RAWSTR;

        cJSON_Delete(root);
    }
*/
    else
    {
        derror("invalid binary: ");
        for (unsigned int i = 0; i < data_size; i++)
        {
            rawlog("0x%02x ", binary[i]);
        }
        derror("\n");
    }

    return ;
}

static void genlbin_parse(char *binary, int *real_dst, void **payload,
    unsigned int *real_size, unsigned int data_size)
{
    struct nlattr *tb[NLATTR_MAX + 1] = {0};
    int ret = genl_parse_attrs_armd(binary, data_size, tb);

    if (ret != Success)
    {
        derror("invalid generic netlink data\n");
        return ;
    }

    const dcomp_t *target = find_dcomponent_by_name((char *)tb[NLATTR_TARGET] + NLA_HDRLEN);
    if (target == NULL)
    {
        derror("target not found\n");
        return ;
    }

    *real_dst = target->dcompid;
    *real_size = tb[NLATTR_DATA]->nla_len - NLA_HDRLEN;
    *payload = (char *)tb[NLATTR_DATA] + NLA_HDRLEN;

    return ;
}
