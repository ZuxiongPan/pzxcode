#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dcontext.h"

extern void dchannel_handle(void *arg);

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

void daemon_context_init(void)
{
    int ret = Success;
    memset(&g_ctx, 0, sizeof(dctx_t));
    atomic_init(&g_ctx.status, false);
    for (int i = Layer_Channel; i < Layer_Unknown; i++)
    {
        pthread_rwlock_init(&g_ctx.records[i].rwlock, NULL);
        g_ctx.records[i].sentinel.name = "sentinel";
        g_ctx.records[i].sentinel.prev = &g_ctx.records[i].sentinel;
        g_ctx.records[i].sentinel.next = &g_ctx.records[i].sentinel;
    }

    g_ctx.worker_mgr = calloc(1, sizeof(dworker_mgr_t));
    context_init_check(g_ctx.worker_mgr != NULL ? Success : Fail);

    g_ctx.epfd = epoll_create1(EPOLL_CLOEXEC);
    context_init_check(g_ctx.epfd > 0 ? Success : Fail);

    atomic_store(&g_ctx.status, true);
    ret = worker_manager_init(g_ctx.worker_mgr);
    context_init_check(ret);
    
    dprint("context init success\n");
    return ;
}

void daemon_context_run(void)
{
    int nfds = 0;
    struct epoll_event events[EPOLL_EVENTS];

    while (atomic_load(&g_ctx.status))
    {
        nfds = epoll_wait(g_ctx.epfd, events, EPOLL_EVENTS, -1);
        if (nfds <= 0)
        {
            derror("epoll_wait failed, retcode: %d\n", nfds);
            continue;
        }
        
        for (int i = 0; i < nfds; i++)
        {
            dchannel_handle(events[i].data.ptr);
        }
    }
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

void dcomponent_init(dcomp_t *comp, int compid, const char *name)
{
    if (comp == NULL)
    {
        derror("dcomponent_init: component is invalid\n");
        return ;
    }

    comp->dcomp_id = compid;
    comp->name = name;
    comp->prev = comp;
    comp->next = comp;
}

int dcomponent_record_add(dcomp_t *comp, dlayer_e layer)
{
    if (comp == NULL || layer >= Layer_Unknown)
    {
        derror("dcomponent_record_add: component is invalid\n");
        return Fail;
    }

    pthread_rwlock_wrlock(&g_ctx.records[layer].rwlock);
    dcomp_t *sentinel = &g_ctx.records[layer].sentinel;
    comp->prev = sentinel;
    comp->next = sentinel->next;
    sentinel->next->prev = comp;
    sentinel->next = comp;
    pthread_rwlock_unlock(&g_ctx.records[layer].rwlock);

    return Success;
}

void dcomponent_record_del(dcomp_t *comp, dlayer_e layer)
{
    if (comp == NULL || layer >= Layer_Unknown)
    {
        derror("dcomponent_unregister: component is invalid\n");
        return ;
    }

    pthread_rwlock_wrlock(&g_ctx.records[layer].rwlock);
    comp->prev->next = comp->next;
    comp->next->prev = comp->prev;
    comp->prev = comp;
    comp->next = comp;
    pthread_rwlock_unlock(&g_ctx.records[layer].rwlock);

    return ;
}

dcomp_t* find_dcomponent_by_id(int compid, dlayer_e layer)
{
    if (layer >= Layer_Unknown || compid < 0)
    {
        derror("find_dcomponent_by_id: invalid layer or compid\n");
        return NULL;
    }

    dcomp_t *comp = NULL;
    pthread_rwlock_rdlock(&g_ctx.records[layer].rwlock);
    comp = g_ctx.records[layer].sentinel.next;
    while (comp != &g_ctx.records[layer].sentinel)
    {
        if (comp->dcomp_id == compid)
        {
            break;
        }
        comp = comp->next;
    }
    pthread_rwlock_unlock(&g_ctx.records[layer].rwlock);

    return (comp == &g_ctx.records[layer].sentinel) ? NULL : comp;
}

dcomp_t* find_dcomponent_by_name(const char *name, dlayer_e layer)
{
    if (layer >= Layer_Unknown || name == NULL)
    {
        derror("find_dcomponent_by_name: invalid layer or name\n");
        return NULL;
    }

    dcomp_t *comp = NULL;
    pthread_rwlock_rdlock(&g_ctx.records[layer].rwlock);
    comp = g_ctx.records[layer].sentinel.next;
    while (comp != &g_ctx.records[layer].sentinel)
    {
        if (strcmp(comp->name, name) == 0)
        {
            break;
        }
        comp = comp->next;
    }
    pthread_rwlock_unlock(&g_ctx.records[layer].rwlock);

    return (comp == &g_ctx.records[layer].sentinel) ? NULL : comp;
}

