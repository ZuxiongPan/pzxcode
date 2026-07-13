#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dcontext.h"

static dctx_t g_ctx;

dctx_t* dctx_instance(void)
{
    return &g_ctx;
}

static inline void context_init_check(int retcode)
{
    if (retcode != Success)
    {
        demerg("context init failed, exit process\n");
        daemon_context_destroy();
        exit(EXIT_FAILURE);
    }
}

int daemon_context_init(void)
{
    int ret = Success;
    memset(&g_ctx, 0, sizeof(dctx_t));
    atomic_init(&g_ctx.status, false);
    for (int i = Layer_Channel; i < Layer_Unknown; i++)
    {
        pthread_rwlock_init(&g_ctx.records[i].rwlock, NULL);
        g_ctx.records[i].sentinel.type = i;
        g_ctx.records[i].sentinel.name = "sentinel";
        g_ctx.records[i].sentinel.prev = &g_ctx.records[i].sentinel;
        g_ctx.records[i].sentinel.next = &g_ctx.records[i].sentinel;
    }

    g_ctx.worker_mgr = calloc(1, sizeof(dworker_mgr_t));
    context_init_check(g_ctx.worker_mgr != NULL ? Success : Fail);

    g_ctx.epfd = epoll_create1(EPOLL_CLOEXEC);
    context_init_check(g_ctx.epfd > 0 ? Success : Fail);

    ret = worker_manager_init(g_ctx.worker_mgr);
    context_init_check(ret);
    atomic_store(&g_ctx.status, true);
    
    dprint("context init success\n");
    return ret;
}

void daemon_context_destroy(void)
{
    atomic_store(&g_ctx.status, false);

    if (g_ctx.worker_mgr != NULL)
    {
        worker_manager_destroy(g_ctx.worker_mgr);
        free(g_ctx.worker_mgr);
    }

    if (g_ctx.epfd > 0)
    {
        close(g_ctx.epfd);
    }

    return ;
}

// void dobject_insert(dobj_t *obj, dobj_type_e type, const char *name)
// {
//     if (obj == NULL || name == NULL || type >= ObjType_Unknown)
//     {
//         derror("dobject_init: object is invalid\n");
//         return ;
//     }

//     obj->type = type;
//     obj->name = name;

//     pthread_rwlock_wrlock(&g_ctx.obj_rec.lock);
//     dobj_t *sentinel = &g_ctx.obj_rec.record[type];
//     obj->prev = sentinel;
//     obj->next = sentinel->next;
//     sentinel->next->prev = obj;
//     sentinel->next = obj;
//     pthread_rwlock_unlock(&g_ctx.obj_rec.lock);
// }

// void dobject_remove(dobj_t *obj)
// {
//     if (obj == NULL || obj->type >= ObjType_Unknown)
//     {
//         derror("dobject_remove: object is invalid\n");
//         return ;
//     }

//     pthread_rwlock_wrlock(&g_ctx.obj_rec.lock);
//     dobj_t *sentinel = &g_ctx.obj_rec.record[obj->type];
//     obj->prev->next = obj->next;
//     obj->next->prev = obj->prev;
//     obj->prev = NULL;
//     obj->next = NULL;
//     pthread_rwlock_unlock(&g_ctx.obj_rec.lock);
// }
