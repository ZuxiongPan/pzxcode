#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dcontext.h"

static struct dctx g_ctx;

struct dctx* dctx_instance(void)
{
    return &g_ctx;
}

static inline void dctx_init_check(int judge)
{
    if (unlikely(judge))
    {
        earlylog("daemon context init failed, exit process\n");
        atomic_store(&g_ctx.status, false);
        dctx_destroy();
        exit(EXIT_FAILURE);
    }
}

void dctx_init(void)
{
    int ret = Success;
    memset(&g_ctx, 0, sizeof(struct dctx));

    atomic_init(&g_ctx.status, false);
    atomic_init(&g_ctx.next_id, 0);
    pthread_rwlock_init(&g_ctx.name_tb.rwlock, NULL);
    pthread_rwlock_init(&g_ctx.id_tb.rwlock, NULL);
    for (unsigned int i = 0; i < COMPREC_HTABLE_SIZE; i++)
    {
        lnode_init(&g_ctx.name_tb.list[i]);
        lnode_init(&g_ctx.id_tb.list[i]);
    }

    g_ctx.epfd = epoll_create1(EPOLL_CLOEXEC);
    dctx_init_check(g_ctx.epfd < 0);

    atomic_store(&g_ctx.status, true);
    ret = worker_mgr_init();
    dctx_init_check(ret != Success);
    
    dprint("context init success\n");
    return ;
}

void start_dctx_evloop(void)
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
            struct dchannel *ch = (struct dchannel *)events[i].data.ptr;
            if (events[i].events & EPOLLIN && ch->read_from_out != NULL)
            {
                ch->read_from_out(ch);
            }
        }
    }
}

void dctx_destroy(void)
{
    worker_mgr_destroy();

    if (g_ctx.epfd >= 0)
    {
        close(g_ctx.epfd);
    }

    return ;
}

void stop_daemon_evloop(void)
{
    atomic_store(&g_ctx.status, false);
}

// DJB2 hash function
static inline unsigned int str_to_key(const char *str)
{
    unsigned int key = 5381;
    for (const char *p = str; *p; p++)
    {
        key = ((key << 5) + key) + (*p);
    }
    return key;
}

void dcomp_init(struct dcomp *comp, const char *name)
{
    if (comp == NULL)
    {
        derror("component is invalid\n");
        return ;
    }

    comp->dcompid = atomic_fetch_add(&g_ctx.next_id, 1);
    comp->name = name;
    lnode_init(&comp->name_node);
    lnode_init(&comp->id_node);
}

int dcomp_record_add(struct dcomp *comp)
{
    if (unlikely(comp == NULL || comp->name == NULL))
    {
        derror("component is invalid\n");
        return Fail;
    }

    unsigned int idx = 0;
    unsigned int skey = str_to_key(comp->name);

    pthread_rwlock_wrlock(&g_ctx.name_tb.rwlock);
    idx = skey % COMPREC_HTABLE_SIZE;
    list_add_tail(&comp->name_node, &g_ctx.name_tb.list[idx]);
    pthread_rwlock_unlock(&g_ctx.name_tb.rwlock);

    pthread_rwlock_wrlock(&g_ctx.id_tb.rwlock);
    idx = comp->dcompid % COMPREC_HTABLE_SIZE;
    list_add_tail(&comp->id_node, &g_ctx.id_tb.list[idx]);
    pthread_rwlock_unlock(&g_ctx.id_tb.rwlock);

    return Success;
}

void dcomp_record_del(struct dcomp *comp)
{
    if (unlikely(comp == NULL || comp->name == NULL))
    {
        derror("component is invalid\n");
        return ;
    }

    pthread_rwlock_wrlock(&g_ctx.name_tb.rwlock);
    list_del(&comp->name_node);
    pthread_rwlock_unlock(&g_ctx.name_tb.rwlock);

    pthread_rwlock_wrlock(&g_ctx.id_tb.rwlock);
    list_del(&comp->id_node);
    pthread_rwlock_unlock(&g_ctx.id_tb.rwlock);

    return ;
}

const struct dcomp* find_dcomp_by_id(unsigned int compid)
{
    unsigned int idx = compid % COMPREC_HTABLE_SIZE;
    struct dcomp *tmp = NULL, *comp = NULL;
    struct lnode *node = NULL;
    pthread_rwlock_rdlock(&g_ctx.id_tb.rwlock);
    for (node = g_ctx.id_tb.list[idx].next; node != &g_ctx.id_tb.list[idx]; node = node->next)
    {
        tmp = container_of(node, struct dcomp, id_node);
        if (tmp->dcompid == compid)
        {
            comp = tmp;
            break;
        }
    }
    pthread_rwlock_unlock(&g_ctx.id_tb.rwlock);

    return comp;
}

const struct dcomp* find_dcomp_by_name(const char *name)
{
    if (unlikely(name == NULL))
    {
        derror("invalid name\n");
        return NULL;
    }

    unsigned int idx = str_to_key(name) % COMPREC_HTABLE_SIZE;
    struct dcomp *tmp = NULL, *comp = NULL;
    struct lnode *node = NULL;

    pthread_rwlock_rdlock(&g_ctx.name_tb.rwlock);
    for (node = g_ctx.name_tb.list[idx].next; node != &g_ctx.name_tb.list[idx]; node = node->next)
    {
        tmp = container_of(node, struct dcomp, name_node);
        if (strcmp(tmp->name, name) == 0)
        {
            comp = tmp;
            break;
        }
    }
    pthread_rwlock_unlock(&g_ctx.name_tb.rwlock);

    return comp;
}

/**
int dctx_info(char *inbuf, int bufsize)
{
    if (inbuf == NULL || bufsize <= 0)
    {
        derror("invalid input\n");
        return 0;
    }

    int bytes = 0;
    dcomp_t *comp = NULL;
    dworker_mgr_t *worker_mgr = g_ctx.worker_mgr;

    bytes += snprintf(inbuf + bytes, bufsize - bytes, "Components:\n");
    pthread_rwlock_rdlock(&g_ctx.ht_rwlock);
    for (int i = 0; i < COMPREC_HTABLE_SIZE; i++)
    {
        bytes += snprintf(inbuf + bytes, bufsize - bytes, "ht[%d]", i);
        comp = g_ctx.htable[i];
        while (NULL != comp)
        {
            bytes += snprintf(inbuf + bytes, bufsize - bytes, "->[0x%08x-%s]",
                comp->dcompid, comp->name);
            comp = comp->next;
        }
        bytes += snprintf(inbuf + bytes, bufsize - bytes, "\n");
    }
    pthread_rwlock_unlock(&g_ctx.ht_rwlock);

    bytes += snprintf(inbuf + bytes, bufsize - bytes, "Worker Info:\n");
    bytes += snprintf(inbuf + bytes, bufsize - bytes, "workers: %d, busy: %d\n",
        worker_mgr->valid, atomic_load(&worker_mgr->busy));
    
    bytes += snprintf(inbuf + bytes, bufsize - bytes, "Queue Info:\n");
    pthread_mutex_lock(&worker_mgr->queue.mutex);
    bytes += snprintf(inbuf + bytes, bufsize - bytes, "count: %d, total: %d, drop: %d",
        worker_mgr->queue.count, worker_mgr->queue.total, worker_mgr->queue.drop);
    pthread_mutex_unlock(&worker_mgr->queue.mutex);

    return bytes;
}
*/