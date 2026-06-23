#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "core/bus.h"
#include "core/worker.h"

#define MSG_QUEUE_SIZE 1024

typedef struct msg_queue {
    message_t *msgs[MSG_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} msg_queue_t;

static msg_queue_t g_queue = { 0 };
static pthread_t *g_workers = NULL;
static int g_worker_cnt = 0;
static volatile int g_busy_cnt = 0;
static bool g_running = false;

static int queue_push(message_t *msg)
{
    pthread_mutex_lock(&g_queue.lock);
    if (g_queue.count >= MSG_QUEUE_SIZE)
    {
        pthread_mutex_unlock(&g_queue.lock);
        return -1;
    }
    g_queue.msgs[g_queue.tail] = msg;
    g_queue.tail = (g_queue.tail + 1) % MSG_QUEUE_SIZE;
    g_queue.count++;
    pthread_cond_signal(&g_queue.cond);
    pthread_mutex_unlock(&g_queue.lock);

    return 0;
}

static message_t* queue_pop(void)
{
    message_t *msg = NULL;

    pthread_mutex_lock(&g_queue.lock);
    while (g_running && g_queue.count == 0)
    {
        pthread_cond_wait(&g_queue.cond, &g_queue.lock);
    }
    if (!g_running)
    {
        pthread_mutex_unlock(&g_queue.lock);
        return NULL;
    }

    msg = g_queue.msgs[g_queue.head];
    g_queue.head = (g_queue.head + 1) % MSG_QUEUE_SIZE;
    g_queue.count--;
    pthread_mutex_unlock(&g_queue.lock);

    return msg;
}

static void* worker_thread(void* arg)
{
    (void)arg;
    while (g_running)
    {
        message_t *msg = queue_pop();
        if (msg == NULL)
        {
            continue;
        }

        __sync_fetch_and_add(&g_busy_cnt, 1);
        bus_router_msg(msg);
        msg_destroy(msg);
        __sync_fetch_and_sub(&g_busy_cnt, 1);
    }

    return NULL;
}

int worker_push_msg(message_t *msg)
{
    return queue_push(msg);
}

int worker_init(int worker_cnt)
{
    g_running = true;
    pthread_mutex_init(&g_queue.lock, NULL);
    pthread_cond_init(&g_queue.cond, NULL);
    g_workers = calloc(worker_cnt, sizeof(pthread_t));
    if (g_workers == NULL)
    {
        return -1;
    }
    g_worker_cnt = worker_cnt;
    for (int i = 0; i < worker_cnt; i++)
    {
        pthread_create(&g_workers[i], NULL, worker_thread, NULL);
    }

    return 0;
}

void worker_destroy(void)
{
    g_running = false;
    pthread_cond_broadcast(&g_queue.cond);
    for (int i = 0; i < g_worker_cnt; i++)
    {
        pthread_join(g_workers[i], NULL);
    }
    free(g_workers);

    return ;
}

int worker_busy_count(void)
{
    return g_busy_cnt;
}

int worker_queue_msgs(void)
{
    int count = -1;
    pthread_mutex_lock(&g_queue.lock);
    count = g_queue.count;
    pthread_mutex_unlock(&g_queue.lock);
    
    return count;
}
