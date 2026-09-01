#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dchannel.h"
#include "core/dworker.h"

typedef struct daemon_timer {
    int timer_id;
    uint64_t expire_ms;
    uint64_t interval_ms;
    bool repeat;
    int modid;
    unsigned int msgid;
} dtimer_t;

typedef struct dtimer_mgr {
    dtimer_t* heap[MAX_DTIMER_COUNT];
    int count;
    int next_tid;
    pthread_mutex_t lock;
} dtimer_mgr_t;

static dtimer_mgr_t dtimer_mgr;
static dchannel_t timer_chnl;

static uint64_t get_current_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static inline dtimer_t* heap_top(void)
{
    dtimer_t *top = NULL;
    pthread_mutex_lock(&dtimer_mgr.lock);
    if (dtimer_mgr.count != 0)
    {
        top = dtimer_mgr.heap[0];
    }
    pthread_mutex_unlock(&dtimer_mgr.lock);

    return top;
}

static inline void heap_swap(int i, int j)
{
    dtimer_t *tmp = dtimer_mgr.heap[i];
    dtimer_mgr.heap[i] = dtimer_mgr.heap[j];
    dtimer_mgr.heap[j] = tmp;
}

static void siftup(int idx)
{
    int parent = 0;
    while (idx > 0)
    {
        parent = (idx - 1) / 2;
        if (dtimer_mgr.heap[idx]->expire_ms >= dtimer_mgr.heap[parent]->expire_ms)
        {
            break;
        }
        heap_swap(idx, parent);
        idx = parent;
    }
}

static void siftdown(int idx)
{
    int left = 0, right = 0, smallest = 0;
    while (true)
    {
        left = idx * 2 + 1;
        right = idx * 2 + 2;
        smallest = idx;
        if (left < dtimer_mgr.count && 
            dtimer_mgr.heap[left]->expire_ms < dtimer_mgr.heap[smallest]->expire_ms)
        {
            smallest = left;
        }
        if (right < dtimer_mgr.count && 
            dtimer_mgr.heap[right]->expire_ms < dtimer_mgr.heap[smallest]->expire_ms)
        {
            smallest = right;
        }
        if (smallest == idx)
        {
            break;
        }
        heap_swap(idx, smallest);
        idx = smallest;
    }
}

static int heap_push(dtimer_t *timer)
{
    pthread_mutex_lock(&dtimer_mgr.lock);
    if (dtimer_mgr.count >= MAX_DTIMER_COUNT)
    {
        pthread_mutex_unlock(&dtimer_mgr.lock);
        return Fail;
    }

    dtimer_mgr.heap[dtimer_mgr.count] = timer;
    dtimer_mgr.count++;
    siftup(dtimer_mgr.count - 1);
    pthread_mutex_unlock(&dtimer_mgr.lock);

    return Success;
}

static void heap_pop(void) 
{
    pthread_mutex_lock(&dtimer_mgr.lock);
    if (dtimer_mgr.count == 0)
    {
        pthread_mutex_unlock(&dtimer_mgr.lock);
        return ;
    }
    heap_swap(0, dtimer_mgr.count - 1);
    dtimer_mgr.count--;
    siftdown(0);
    pthread_mutex_unlock(&dtimer_mgr.lock);

    return ;
}

static void timerfd_reprogram(void)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    uint64_t now, diff;
    dtimer_t *top = heap_top();

    if (top == NULL)
    {
        timerfd_settime(timer_chnl.fd, 0, &its, NULL);
        return ;
    }

    now = get_current_ms();
    diff = top->expire_ms > now ? top->expire_ms - now : 1;
    its.it_value.tv_sec = diff / 1000;
    its.it_value.tv_nsec = (diff % 1000) * 1000000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    timerfd_settime(timer_chnl.fd, 0, &its, NULL);
}

static void timerfd_expired_process(void)
{
    uint64_t now = get_current_ms();
    dtimer_t *timer = NULL;
    int inner_ret = Success;

    while (true)
    {
        timer = heap_top();
        if (timer == NULL || timer->expire_ms > now)
        {
            break;
        }

        inner_ret = task_enqueue(DataModuleMsg, timer_chnl.dcomp.dcomp_id, timer->modid,
                    timer->msgid, 0, NULL);
        dprint("enqueue timer %d task to module 0x%x msg 0x%x ret %d\n", timer->timer_id,
            timer->modid, timer->msgid, inner_ret);
        heap_pop();
        if (timer->repeat)
        {
            timer->expire_ms += timer->interval_ms;
            heap_push(timer);
        }
        else
        {
            free(timer);
        }
    }

    timerfd_reprogram();
}

static int timer_chnl_callback(dchannel_t *chnl)
{
    uint64_t cnt = 0;

    read(chnl->fd, &cnt, sizeof(cnt));
    timerfd_expired_process();
    return Success;
}

const channel_ops_t timer_chnl_ops = {
    .callback = timer_chnl_callback,
    .write_to_outer = NULL,
};

int ch_timer_init(void)
{
    int ret = Success;

    memset(&dtimer_mgr, 0, sizeof(dtimer_mgr_t));
    memset(&timer_chnl, 0, sizeof(dchannel_t));

    dcomponent_init(&timer_chnl.dcomp, ChannelIDTimer, "ch_dtimer");
    pthread_mutex_init(&dtimer_mgr.lock, NULL);
    dtimer_mgr.count = 0;
    dtimer_mgr.next_tid = 0;

    timer_chnl.ops = &timer_chnl_ops;
    timer_chnl.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_chnl.fd < 0)
    {
        derror("failed to create dtimer fd\n");
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &timer_chnl);
    if (ret != Success)
    {
        derror("failed to register dtimer channel\n");
        close(timer_chnl.fd);
        return Fail;
    }

    dprint("dtimer channel fd = %d\n", timer_chnl.fd);
    return Success;
}

void ch_timer_exit(void)
{
    dchannel_unregister(&timer_chnl);
    if (timer_chnl.fd >= 0)
    {
        close(timer_chnl.fd);
    }
    timer_chnl.fd = -1;

    pthread_mutex_lock(&dtimer_mgr.lock);
    for (int i = 0; i < dtimer_mgr.count; i++)
    {
        free(dtimer_mgr.heap[i]);
    }
    dtimer_mgr.count = 0;
    dtimer_mgr.next_tid = 0;
    pthread_mutex_unlock(&dtimer_mgr.lock);
    pthread_mutex_destroy(&dtimer_mgr.lock);

    dprint("dtimer channel exit\n");
}

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat,
            int modid, unsigned int msgid)
{
    dtimer_t *timer = calloc(1, sizeof(dtimer_t));
    if (timer == NULL)
    {
        return Fail;
    }
    timer->timer_id = dtimer_mgr.next_tid++;
    timer->expire_ms = get_current_ms() + timeout_ms;
    timer->interval_ms = interval_ms;
    timer->repeat = repeat;
    timer->modid = modid;
    timer->msgid = msgid;
    if (heap_push(timer) < 0)
    {
        free(timer);
        return Fail;
    }
    timerfd_reprogram();
    return timer->timer_id;
}

void timer_del(int timer_id)
{
    dtimer_t *timer = NULL;
    bool reprogram = false;

    pthread_mutex_lock(&dtimer_mgr.lock);
    for (int i = 0; i < dtimer_mgr.count; i++)
    {
        timer = dtimer_mgr.heap[i];
        if (timer->timer_id == timer_id)
        {
            heap_swap(i, dtimer_mgr.count - 1);
            dtimer_mgr.count--;
            if (i == 0)
            {
                siftdown(i);
            }
            else
            {
                int parent = (i - 1) / 2;
                if (dtimer_mgr.heap[parent]->expire_ms > dtimer_mgr.heap[i]->expire_ms)
                {
                    siftup(i);
                }
                else
                {
                    siftdown(i);
                }
            }
            free(timer);
            if (dtimer_mgr.count == 0 || i == 0)
            {
                reprogram = true;
            }
            break;
        }
    }
    pthread_mutex_unlock(&dtimer_mgr.lock);
    if (reprogram)
    {
        timerfd_reprogram();
    }
}
