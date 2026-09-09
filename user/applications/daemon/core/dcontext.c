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
    pthread_rwlock_init(&g_ctx.ht_rwlock, NULL);
    for (int i = 0; i < COMPREC_HTABLE_SIZE; i++)
    {
        g_ctx.htable[i] = NULL;
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

static inline int dcomp_hash(unsigned int compid)
{
    return (compid % COMPREC_HTABLE_SIZE);
}

void dcomponent_init(dcomp_t *comp, int compid, const char *name)
{
    if (comp == NULL)
    {
        derror("component is invalid\n");
        return ;
    }

    comp->dcompid = compid;
    comp->name = name;
    comp->next = NULL;
}

int dcomponent_record_add(dcomp_t *comp)
{
    if (comp == NULL)
    {
        derror("component is invalid\n");
        return Fail;
    }

    int hash = dcomp_hash(comp->dcompid);
    pthread_rwlock_wrlock(&g_ctx.ht_rwlock);
    // here the id will not be duplicated, it may be a risk
    comp->next = g_ctx.htable[hash];
    g_ctx.htable[hash] = comp;
    pthread_rwlock_unlock(&g_ctx.ht_rwlock);

    return Success;
}

void dcomponent_record_del(dcomp_t *comp)
{
    if (comp == NULL)
    {
        derror("component is invalid\n");
        return ;
    }

    int hash = dcomp_hash(comp->dcompid);
    pthread_rwlock_wrlock(&g_ctx.ht_rwlock);
    dcomp_t *prev = NULL;
    dcomp_t *cur = g_ctx.htable[hash];
    while (cur != NULL)
    {
        if (cur->dcompid == comp->dcompid)
        {
            if (prev != NULL)
            {
                prev->next = cur->next;
            }
            else
            {
                g_ctx.htable[hash] = cur->next;
            }
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_rwlock_unlock(&g_ctx.ht_rwlock);

    return ;
}

dcomp_t* find_dcomponent_by_id(int compid)
{
    int hash = dcomp_hash(compid);
    dcomp_t *comp = NULL;
    pthread_rwlock_rdlock(&g_ctx.ht_rwlock);
    comp = g_ctx.htable[hash];
    while (comp != NULL)
    {
        if (comp->dcompid == compid)
        {
            break;
        }
        comp = comp->next;
    }
    pthread_rwlock_unlock(&g_ctx.ht_rwlock);

    return comp;
}

dcomp_t* find_dcomponent_by_name(const char *name)
{
    if (name == NULL)
    {
        derror("invalid name\n");
        return NULL;
    }

    dcomp_t *comp = NULL;
    bool not_found = true;
    int i = 0;
    pthread_rwlock_rdlock(&g_ctx.ht_rwlock);
    while (i < COMPREC_HTABLE_SIZE && not_found)
    {
        comp = g_ctx.htable[i];
        while (comp != NULL)
        {
            if (strcmp(comp->name, name) == 0)
            {
                not_found = false;
                break;
            }
            comp = comp->next;
        }
        i++;
    }
    pthread_rwlock_unlock(&g_ctx.ht_rwlock);

    return comp;
}

