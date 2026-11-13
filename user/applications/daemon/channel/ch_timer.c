#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "dextension.h"
#include "dcomp_name.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"

#define DTIMER_REPID_START 0x0
#define DTIMER_ONCEID_START 0x10000000

struct dtimer {
    int timer_id;
    uint64_t expire_ms;
    uint64_t interval_ms;
    unsigned int compid;
    unsigned int msgid;
    struct lnode node;
};

struct rep_timer_mgr {
    // double-linked list
    struct lnode rep_timers;
    int next_tid;
    pthread_mutex_t lock;
    struct dchannel ch_repeat;
};

struct once_timer_mgr {
    // little-root heap
    struct dtimer once_timers[ONCE_DTIMER_MAXCNT];
    int count;
    int next_tid;
    pthread_mutex_t lock;
    struct dchannel ch_once;
};

static struct rep_timer_mgr rtimer_mgr;
static struct once_timer_mgr otimer_mgr;

static inline uint64_t get_current_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void rep_timer_insert_locked(struct dtimer *timer)
{
    struct lnode *pos = NULL;

    for (pos = rtimer_mgr.rep_timers.next; pos != &rtimer_mgr.rep_timers;
        pos = pos->next)
    {
        struct dtimer *t = container_of(pos, struct dtimer, node);
        if (t->expire_ms > timer->expire_ms)
        {
            break;
        }
    }

    list_add_after(&timer->node, pos->prev);

    return ;
}

static void rep_timerfd_reprogram(void)
{
    struct itimerspec its;
    uint64_t now = 0, diff = 0, expire = 0;
    bool empty = true;

    memset(&its, 0, sizeof(its));

    pthread_mutex_lock(&rtimer_mgr.lock);
    if (rtimer_mgr.rep_timers.next != &rtimer_mgr.rep_timers)
    {
        empty = false;
        expire = container_of(rtimer_mgr.rep_timers.next,
            struct dtimer, node)->expire_ms;
    }
    pthread_mutex_unlock(&rtimer_mgr.lock);

    if (empty)
    {
        timerfd_settime(rtimer_mgr.ch_repeat.fd, 0, &its, NULL);
        return ;
    }

    now = get_current_ms();
    diff = expire > now ? expire - now : 1;
    its.it_value.tv_sec = diff / 1000;
    its.it_value.tv_nsec = (diff % 1000) * 1000000;
    timerfd_settime(rtimer_mgr.ch_repeat.fd, 0, &its, NULL);

    return ;
}

static void ch_timer_repeat_expire(void)
{
    uint64_t now_ms = get_current_ms();
    struct dtimer *timer = NULL;
    struct lnode *node = NULL;
    struct lnode *next = NULL;

    pthread_mutex_lock(&rtimer_mgr.lock);
    node = rtimer_mgr.rep_timers.next;
    while (node != &rtimer_mgr.rep_timers)
    {
        timer = container_of(node, struct dtimer, node);
        next = node->next;
        if (timer->expire_ms > now_ms)
        {
            break;
        }

        list_del(node);
        task_enqueue_by_id(rtimer_mgr.ch_repeat.comp.dcompid,
            timer->compid, timer->msgid, 0, NULL);
        timer->expire_ms += timer->interval_ms;
        rep_timer_insert_locked(timer);
        node = next;
    }
    pthread_mutex_unlock(&rtimer_mgr.lock);

    rep_timerfd_reprogram();
    return ;
}

static int ch_timer_repeat_read_from_out(struct dchannel *ch)
{
    uint64_t cnt = 0;

    read(ch->fd, &cnt, sizeof(cnt));
    ch_timer_repeat_expire();

    return Success;
}

static inline void once_heap_swap(int i, int j)
{
    struct dtimer tmp = otimer_mgr.once_timers[i];
    otimer_mgr.once_timers[i] = otimer_mgr.once_timers[j];
    otimer_mgr.once_timers[j] = tmp;

    return ;
}

static inline void once_siftup(int idx)
{
    while (idx > 0)
    {
        int parent = (idx - 1) / 2;
        if (otimer_mgr.once_timers[idx].expire_ms >=
            otimer_mgr.once_timers[parent].expire_ms)
        {
            break;
        }
        once_heap_swap(idx, parent);
        idx = parent;
    }

    return ;
}

static inline void once_siftdown(int idx)
{
    while (true)
    {
        int left = idx * 2 + 1;
        int right = idx * 2 + 2;
        int smallest = idx;

        if (left < otimer_mgr.count &&
            otimer_mgr.once_timers[left].expire_ms <
            otimer_mgr.once_timers[smallest].expire_ms)
        {
            smallest = left;
        }
        if (right < otimer_mgr.count &&
            otimer_mgr.once_timers[right].expire_ms <
            otimer_mgr.once_timers[smallest].expire_ms)
        {
            smallest = right;
        }
        if (smallest == idx)
        {
            break;
        }
        once_heap_swap(idx, smallest);
        idx = smallest;
    }

    return ;
}

static inline void once_heap_pop(void)
{
    if (otimer_mgr.count == 0)
    {
        return ;
    }

    once_heap_swap(0, otimer_mgr.count - 1);
    otimer_mgr.count--;
    once_siftdown(0);

    return ;
}

static void once_heap_remove(int idx)
{
    once_heap_swap(idx, otimer_mgr.count - 1);
    otimer_mgr.count--;
    if (idx >= otimer_mgr.count)
    {
        return ;
    }

    if (idx > 0 &&
        otimer_mgr.once_timers[idx].expire_ms <
        otimer_mgr.once_timers[(idx - 1) / 2].expire_ms)
    {
        once_siftup(idx);
    }
    else
    {
        once_siftdown(idx);
    }

    return ;
}

static void once_timerfd_reprogram(void)
{
    struct itimerspec its;
    uint64_t now = 0, diff = 0, expire = 0;
    bool empty = true;

    memset(&its, 0, sizeof(its));

    pthread_mutex_lock(&otimer_mgr.lock);
    if (otimer_mgr.count > 0)
    {
        empty = false;
        expire = otimer_mgr.once_timers[0].expire_ms;
    }
    pthread_mutex_unlock(&otimer_mgr.lock);

    if (empty)
    {
        timerfd_settime(otimer_mgr.ch_once.fd, 0, &its, NULL);
        return ;
    }

    now = get_current_ms();
    diff = expire > now ? expire - now : 1;
    its.it_value.tv_sec = diff / 1000;
    its.it_value.tv_nsec = (diff % 1000) * 1000000;
    timerfd_settime(otimer_mgr.ch_once.fd, 0, &its, NULL);

    return ;
}

static void ch_timer_once_expire(void)
{
    uint64_t now_ms = get_current_ms();

    pthread_mutex_lock(&otimer_mgr.lock);
    while (otimer_mgr.count > 0 &&
        otimer_mgr.once_timers[0].expire_ms <= now_ms)
    {
        task_enqueue_by_id(otimer_mgr.ch_once.comp.dcompid,
            otimer_mgr.once_timers[0].compid,
            otimer_mgr.once_timers[0].msgid, 0, NULL);
        once_heap_pop();
    }
    pthread_mutex_unlock(&otimer_mgr.lock);

    once_timerfd_reprogram();
    return ;
}

static int ch_timer_once_read_from_out(struct dchannel *ch)
{
    uint64_t cnt = 0;

    read(ch->fd, &cnt, sizeof(cnt));
    ch_timer_once_expire();

    return Success;
}

static int ch_timer_init(void)
{
    int ret = Success;

    memset(&rtimer_mgr, 0, sizeof(rtimer_mgr));
    memset(&otimer_mgr, 0, sizeof(otimer_mgr));

    dcomp_init(&rtimer_mgr.ch_repeat.comp, ChannelTimerRepeat);
    dcomp_set_handlers(&rtimer_mgr.ch_repeat.comp, 0, NULL);
    lnode_init(&rtimer_mgr.rep_timers);
    pthread_mutex_init(&rtimer_mgr.lock, NULL);
    rtimer_mgr.next_tid = DTIMER_REPID_START;
    rtimer_mgr.ch_repeat.read_from_out = ch_timer_repeat_read_from_out;
    rtimer_mgr.ch_repeat.fd = timerfd_create(CLOCK_MONOTONIC,
        TFD_NONBLOCK | TFD_CLOEXEC);
    if (rtimer_mgr.ch_repeat.fd < 0)
    {
        derror("repeat timerfd_create failed\n");
        return Fail;
    }
    ret = dchannel_register(EPOLLIN, &rtimer_mgr.ch_repeat);
    if (ret != Success)
    {
        derror("dchannel_register [%s] failed\n",
            rtimer_mgr.ch_repeat.comp.name);
        close(rtimer_mgr.ch_repeat.fd);
        rtimer_mgr.ch_repeat.fd = -1;
        return Fail;
    }
    dprint("[%s] info: fd[%d], id[%u]\n", rtimer_mgr.ch_repeat.comp.name, rtimer_mgr.ch_repeat.fd, rtimer_mgr.ch_repeat.comp.dcompid);

    dcomp_init(&otimer_mgr.ch_once.comp, ChannelTimerOnce);
    dcomp_set_handlers(&otimer_mgr.ch_once.comp, 0, NULL);
    pthread_mutex_init(&otimer_mgr.lock, NULL);
    memset(otimer_mgr.once_timers, 0, sizeof(otimer_mgr.once_timers));
    otimer_mgr.next_tid = DTIMER_ONCEID_START;
    otimer_mgr.count = 0;
    otimer_mgr.ch_once.read_from_out = ch_timer_once_read_from_out;
    otimer_mgr.ch_once.fd = timerfd_create(CLOCK_MONOTONIC,
        TFD_NONBLOCK | TFD_CLOEXEC);
    if (otimer_mgr.ch_once.fd < 0)
    {
        derror("once timerfd_create failed\n");
        dchannel_unregister(&rtimer_mgr.ch_repeat);
        close(rtimer_mgr.ch_repeat.fd);
        rtimer_mgr.ch_repeat.fd = -1;
        return Fail;
    }
    ret = dchannel_register(EPOLLIN, &otimer_mgr.ch_once);
    if (ret != Success)
    {
        derror("dchannel_register [%s] failed\n", otimer_mgr.ch_once.comp.name);
        dchannel_unregister(&rtimer_mgr.ch_repeat);
        close(rtimer_mgr.ch_repeat.fd);
        rtimer_mgr.ch_repeat.fd = -1;
        close(otimer_mgr.ch_once.fd);
        otimer_mgr.ch_once.fd = -1;
        return Fail;
    }
    dprint("[%s] info: fd[%d], id[%u]\n", otimer_mgr.ch_once.comp.name, otimer_mgr.ch_once.fd, otimer_mgr.ch_once.comp.dcompid);

    return Success;
}

static void ch_timer_exit(void)
{
    struct lnode *node = NULL;
    struct lnode *next = NULL;
    struct dtimer *timer = NULL;

    dchannel_unregister(&rtimer_mgr.ch_repeat);
    if (rtimer_mgr.ch_repeat.fd >= 0)
    {
        close(rtimer_mgr.ch_repeat.fd);
        rtimer_mgr.ch_repeat.fd = -1;
    }

    pthread_mutex_lock(&rtimer_mgr.lock);
    node = rtimer_mgr.rep_timers.next;
    while (node != &rtimer_mgr.rep_timers)
    {
        timer = container_of(node, struct dtimer, node);
        next = node->next;
        list_del(node);
        free(timer);
        node = next;
    }
    pthread_mutex_unlock(&rtimer_mgr.lock);
    pthread_mutex_destroy(&rtimer_mgr.lock);
    dprint("[%s] exit\n", rtimer_mgr.ch_repeat.comp.name);

    dchannel_unregister(&otimer_mgr.ch_once);
    if (otimer_mgr.ch_once.fd >= 0)
    {
        close(otimer_mgr.ch_once.fd);
        otimer_mgr.ch_once.fd = -1;
    }
    pthread_mutex_destroy(&otimer_mgr.lock);

    dprint("[%s] exit\n", otimer_mgr.ch_once.comp.name);
    return ;
}

DCOMP_INIT_NORMPRIO(ch_timer_init);
DCOMP_EXIT_NORMPRIO(ch_timer_exit);

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat,
    unsigned int modid, unsigned int msgid)
{
    if (repeat)
    {
        struct dtimer *timer = calloc(1, sizeof(struct dtimer));
        if (timer == NULL)
        {
            return Fail;
        }

        timer->expire_ms = get_current_ms() + timeout_ms;
        timer->interval_ms = interval_ms;
        timer->compid = modid;
        timer->msgid = msgid;

        pthread_mutex_lock(&rtimer_mgr.lock);
        timer->timer_id = rtimer_mgr.next_tid++;
        rep_timer_insert_locked(timer);
        pthread_mutex_unlock(&rtimer_mgr.lock);

        rep_timerfd_reprogram();
        return timer->timer_id;
    }

    struct dtimer *timer = NULL;
    int tid = 0;

    pthread_mutex_lock(&otimer_mgr.lock);
    if (otimer_mgr.count >= ONCE_DTIMER_MAXCNT)
    {
        pthread_mutex_unlock(&otimer_mgr.lock);
        return Fail;
    }

    timer = &otimer_mgr.once_timers[otimer_mgr.count];
    tid = otimer_mgr.next_tid++;
    timer->timer_id = tid;
    timer->expire_ms = get_current_ms() + timeout_ms;
    timer->interval_ms = interval_ms;
    timer->compid = modid;
    timer->msgid = msgid;
    otimer_mgr.count++;
    once_siftup(otimer_mgr.count - 1);
    pthread_mutex_unlock(&otimer_mgr.lock);

    once_timerfd_reprogram();
    return tid;
}

void timer_del(int timer_id)
{
    if (timer_id >= DTIMER_ONCEID_START)
    {
        pthread_mutex_lock(&otimer_mgr.lock);
        for (int i = 0; i < otimer_mgr.count; i++)
        {
            if (otimer_mgr.once_timers[i].timer_id == timer_id)
            {
                once_heap_remove(i);
                break;
            }
        }
        pthread_mutex_unlock(&otimer_mgr.lock);
        once_timerfd_reprogram();
        return ;
    }

    struct lnode *node = NULL;

    pthread_mutex_lock(&rtimer_mgr.lock);
    for (node = rtimer_mgr.rep_timers.next; node != &rtimer_mgr.rep_timers;
        node = node->next)
    {
        struct dtimer *timer = container_of(node, struct dtimer, node);
        if (timer->timer_id == timer_id)
        {
            list_del(node);
            free(timer);
            break;
        }
    }
    pthread_mutex_unlock(&rtimer_mgr.lock);

    rep_timerfd_reprogram();
    return ;
}
