#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "module/dmsgid.h"
#include "lib/cJSON.h"

static dmod_t statmod;

static int stat_handle_json_rawstr(dtask_t *task)
{
    char buf[TASK_DATA_MAXSIZE] = { 0 };
    int bytes = 0;
    dcomp_t *comp = NULL;
    dctx_t *ctx = dctx_instance();
    dworker_mgr_t *worker_mgr = ctx->worker_mgr;

    bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "Layer Info:\n");
    for (int i = 0; i < Layer_Unknown; i++)
    {
        bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "Layer%02d", i);
        pthread_rwlock_rdlock(&ctx->records[i].rwlock);
        comp = ctx->records[i].sentinel.next;
        while (comp != &ctx->records[i].sentinel)
        {
            bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "->[0x%08x-%s]",
                comp->dcomp_id, comp->name);
            comp = comp->next;
        }
        pthread_rwlock_unlock(&ctx->records[i].rwlock);
        bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "\n");
    }

    bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "Worker Info:\n");
    bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "workers: %d, busy: %d\n",
        worker_mgr->valid, atomic_load(&worker_mgr->busy));
    
    bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "Queue Info:\n");
    pthread_mutex_lock(&worker_mgr->queue.mutex);
    bytes += snprintf(buf + bytes, TASK_DATA_MAXSIZE - bytes, "count: %d, total: %d, drop: %d\n",
        worker_mgr->queue.count, worker_mgr->queue.total, worker_mgr->queue.drop);
    pthread_mutex_unlock(&worker_mgr->queue.mutex);

    rawlog(buf);

    return Success;
}

static int statmod_onmsg(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Fail;
    dtask_t *task = (dtask_t *)arg;

    switch (task->msgid)
    {
        case MSGID_JSON_RAWSTR:
            ret = stat_handle_json_rawstr(task);
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t statmod_ops = {
    .onmsg = statmod_onmsg,
};

int statmod_init(void)
{
    int ret = Success;
    memset(&statmod, 0, sizeof(dmod_t));
    dcomponent_init(&statmod.dcomp, ModuleIDStatus, "mod_status");
    statmod.ops = &statmod_ops;

    ret = dmodule_register(&statmod);
    if (ret != Success)
    {
        derror("status module register failed\n");
        return Fail;
    }

    dprint("blkmod_init ret = %d\n", ret);
    return ret;
}

void statmod_exit(void)
{
    dmodule_unregister(&statmod);
    dprint("status module unregister done\n");
}