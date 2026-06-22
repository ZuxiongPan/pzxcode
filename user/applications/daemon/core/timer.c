#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "core/timer.h"
#include "core/evloop.h"

#define MAX_TIMER_COUNT 1024

static dtimer_t *g_timer_heap[MAX_TIMER_COUNT];
static int g_heap_size = 0;
static int g_timerfd = -1;
static uint64_t g_next_timer_id = 0;

static uint64_t get_current_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void heap_swap(int i, int j)
{
    dtimer_t *tmp = g_timer_heap[i];
    g_timer_heap[i] = g_timer_heap[j];
    g_timer_heap[j] = tmp;
    g_timer_heap[i]->heap_idx = i;
    g_timer_heap[j]->heap_idx = j;
}

static void siftup(int idx)
{
    int parent = 0;
    while (idx > 0)
    {
        parent = (idx - 1) / 2;
        if (g_timer_heap[idx]->expire_ms >= g_timer_heap[parent]->expire_ms)
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
        if (left < g_heap_size && g_timer_heap[left]->expire_ms < g_timer_heap[smallest]->expire_ms)
        {
            smallest = left;
        }
        if (right < g_heap_size && g_timer_heap[right]->expire_ms < g_timer_heap[smallest]->expire_ms)
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
    if (g_heap_size >= MAX_TIMER_COUNT)
    {
        return -1;
    }

    timer->heap_idx = g_heap_size;
    g_timer_heap[g_heap_size] = timer;
    g_heap_size++;
    siftup(timer->heap_idx);

    return 0;
}

static dtimer_t* heap_top(void)
{
    if (g_heap_size == 0)
    {
        return NULL;
    }

    return g_timer_heap[0];
}

static dtimer_t* heap_pop(void)
{
    if (g_heap_size == 0)
    {
        return NULL;
    }

    dtimer_t *top = g_timer_heap[0];
    heap_swap(0, g_heap_size - 1);
    g_heap_size--;
    siftdown(0);

    return top;
}

static void heap_remove(dtimer_t *timer)
{
    if (timer == NULL)
    {
        return;
    }

    int idx = timer->heap_idx;
    heap_swap(idx, g_heap_size - 1);
    g_heap_size--;
    siftdown(idx);
}

static void timerfd_reprogram(void)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    uint64_t now, diff;
    dtimer_t *top = heap_top();

    if (top == NULL)
    {
        timerfd_settime(g_timerfd, 0, &its, NULL);
        return ;
    }

    now = get_current_ms();
    diff = top->expire_ms > now ? top->expire_ms - now : 1;
    its.it_value.tv_sec = diff / 1000;
    its.it_value.tv_nsec = (diff % 1000) * 1000000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    timerfd_settime(g_timerfd, 0, &its, NULL);
}

static void timerfd_expired_process(void)
{
    uint64_t now = get_current_ms();
    dtimer_t *timer = NULL;

    while (true)
    {
        timer = heap_top();
        if (timer == NULL || timer->expire_ms > now)
        {
            break;
        }

        heap_pop();
        if (timer->cb != NULL)
        {
            timer->cb(timer->arg);
        }

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

static void timerfd_ep_callback(int fd, uint32_t events, void *arg)
{
    uint64_t cnt = 0;
    (void)events;
    (void)arg;

    read(fd, &cnt, sizeof(cnt));
    timerfd_expired_process();
}

int timer_init(void)
{
    g_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_timerfd < 0)
    {
        return -1;
    }

    return evloop_add(g_timerfd, EPOLLIN, timerfd_ep_callback, NULL);
}

uint64_t timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat, 
    timer_cb_f cb, void *arg)
{
    dtimer_t *timer = calloc(1, sizeof(dtimer_t));
    if (timer == NULL)
    {
        return 0;
    }
    timer->timer_id = g_next_timer_id++;
    timer->expire_ms = get_current_ms() + timeout_ms;
    timer->interval_ms = interval_ms;
    timer->repeat = repeat;
    timer->cb = cb;
    timer->arg = arg;
    heap_push(timer);
    timerfd_reprogram();
    return timer->timer_id;
}

int timer_del(uint64_t timer_id)
{
    dtimer_t *timer = NULL;
    for (int i = 0; i < g_heap_size; i++)
    {
        timer = g_timer_heap[i];
        if (timer->timer_id == timer_id)
        {
            heap_remove(timer);
            free(timer);
            timerfd_reprogram();
            return 0;
        }
    }
    return -1;
}
