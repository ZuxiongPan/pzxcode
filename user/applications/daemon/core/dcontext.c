#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

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
    struct epoll_event ev;

    memset(&g_ctx, 0, sizeof(struct dctx));
    g_ctx.epfd = -1;
    g_ctx.wakefd = -1;

    atomic_init(&g_ctx.status, false);
    // 0 is reserved for "invalid / broadcast", the first real component is 1
    atomic_init(&g_ctx.next_id, 1U);
    pthread_rwlock_init(&g_ctx.name_tb.rwlock, NULL);
    pthread_rwlock_init(&g_ctx.id_tb.rwlock, NULL);
    for (unsigned int i = 0; i < COMPREC_HTABLE_SIZE; i++)
    {
        lnode_init(&g_ctx.name_tb.list[i]);
        lnode_init(&g_ctx.id_tb.list[i]);
    }

    g_ctx.epfd = epoll_create1(EPOLL_CLOEXEC);
    dctx_init_check(g_ctx.epfd < 0);

    // eventfd is the only way to wake epoll_wait up from another thread,
    // it replaces the old "arm a 100ms one-shot timer" trick
    g_ctx.wakefd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    dctx_init_check(g_ctx.wakefd < 0);

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;     // NULL is the wakeup sentinel in the dispatch loop
    ret = epoll_ctl(g_ctx.epfd, EPOLL_CTL_ADD, g_ctx.wakefd, &ev);
    dctx_init_check(ret != 0);

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
        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            derror("epoll_wait failed, errno: %d\n", errno);
            break;
        }
        if (nfds == 0)
        {
            continue;
        }
        
        for (int i = 0; i < nfds; i++)
        {
            struct dchannel *ch = (struct dchannel *)events[i].data.ptr;

            if (ch == NULL)
            {
                // wakeup sentinel: drain the counter and re-check status
                uint64_t cnt = 0;
                (void)!read(g_ctx.wakefd, &cnt, sizeof(cnt));
                continue;
            }

            // read first: a peer that closed right after sending still has its
            // last message pending, and a channel learns about the EOF here
            if ((events[i].events & EPOLLIN) && ch->read_from_out != NULL)
            {
                if (ch->read_from_out(ch) != Success)
                {
                    ddebug("channel[%s] read_from_out failed\n",
                        ch->comp.name == NULL ? "no name" : ch->comp.name);
                }
            }

            if (events[i].events & (EPOLLERR | EPOLLHUP))
            {
                // a peer closing normally raises EPOLLIN|EPOLLHUP too, at this
                // point the channel has already seen the EOF and released
                // itself, so the hook must tolerate being called twice.
                // level triggered: a channel that does not drop its fd would
                // fire on every wakeup, so it has to leave epoll in any case.
                if (ch->on_hangup != NULL)
                {
                    ddebug("channel[%s] hangup, events: 0x%x\n",
                        ch->comp.name == NULL ? "no name" : ch->comp.name,
                        events[i].events);
                    ch->on_hangup(ch);
                }
                else
                {
                    derror("channel[%s] error/hangup without hook, dropping it, events: 0x%x\n",
                        ch->comp.name == NULL ? "no name" : ch->comp.name,
                        events[i].events);
                    dchannel_unregister(ch);
                }
            }
        }
    }
}

void dctx_destroy(void)
{
    worker_mgr_destroy();

    if (g_ctx.wakefd >= 0)
    {
        close(g_ctx.wakefd);
        g_ctx.wakefd = -1;
    }

    if (g_ctx.epfd >= 0)
    {
        close(g_ctx.epfd);
        g_ctx.epfd = -1;
    }

    pthread_rwlock_destroy(&g_ctx.name_tb.rwlock);
    pthread_rwlock_destroy(&g_ctx.id_tb.rwlock);

    return ;
}

void stop_daemon_evloop(void)
{
    uint64_t one = 1;

    atomic_store(&g_ctx.status, false);

    // epoll_wait may be blocked in another thread, kick it out immediately
    if (g_ctx.wakefd >= 0)
    {
        (void)!write(g_ctx.wakefd, &one, sizeof(one));
    }
}

// DJB2 hash function
static inline unsigned int str_to_key(const char *str)
{
    unsigned int key = 5381;
    for (const char *p = str; *p; p++)
    {
        // char may be signed, a negative value would be sign-extended here
        key = ((key << 5) + key) + (unsigned int)(unsigned char)(*p);
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
    if (unlikely(comp->dcompid == DCOMPID_RESERVED))
    {
        // next_id wrapped around, ids must stay unique inside the record table
        derror("component id space exhausted, name[%s]\n", name);
    }
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