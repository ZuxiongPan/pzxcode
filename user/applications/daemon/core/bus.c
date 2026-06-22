#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/eventfd.h>
#include <sys/epoll.h>

#include "core/bus.h"
#include "core/module.h"
#include "core/evloop.h"

#define BUS_QUEUE_MAX_COUNT 1024

typedef struct bus_ctx {
    message_t *queue[BUS_QUEUE_MAX_COUNT];
    int head;
    int tail;
    int count;
    int eventfd;
    pthread_mutex_t lock;
} bus_ctx_t;

static bus_ctx_t g_bus = { 0 };

message_t* msg_create(uint32_t msg_id, const char* src_name, const char* dst_name, 
    int payload_len, const void* payload)
{
    message_t *msg = calloc(1, sizeof(message_t));
    if (msg == NULL)
    {
        return NULL;
    }

    if (src_name != NULL)
    {
        snprintf(msg->src_name, sizeof(msg->src_name), "%s", src_name);
    }
    if (dst_name != NULL)
    {
        snprintf(msg->dst_name, sizeof(msg->dst_name), "%s", dst_name);
    }

    msg->msg_id = msg_id;
    msg->payload_len = payload_len;
    if (payload_len > 0 && payload != NULL)
    {
        msg->payload = calloc(1, payload_len);
        if (msg->payload == NULL)
        {
            free(msg);
            return NULL;
        }
        memcpy(msg->payload, payload, payload_len);
    }

    return msg;
}

void msg_destroy(message_t *msg)
{
    if (msg == NULL)
    {
        return;
    }

    if (msg->payload != NULL)
    {
        free(msg->payload);
    }
    free(msg);
}

static int bus_queue_push(message_t *msg)
{
    pthread_mutex_lock(&g_bus.lock);
    if (g_bus.count >= BUS_QUEUE_MAX_COUNT)
    {
        pthread_mutex_unlock(&g_bus.lock);
        return -1;
    }
    g_bus.queue[g_bus.tail] = msg;
    g_bus.tail = (g_bus.tail + 1) % BUS_QUEUE_MAX_COUNT;
    g_bus.count++;
    pthread_mutex_unlock(&g_bus.lock);

    return 0;
}

static message_t* bus_pop_msg(void)
{
    message_t *msg = NULL;

    pthread_mutex_lock(&g_bus.lock);
    if (g_bus.count > 0)
    {
        msg = g_bus.queue[g_bus.head];
        g_bus.head = (g_bus.head + 1) % BUS_QUEUE_MAX_COUNT;
        g_bus.count--;
    }
    pthread_mutex_unlock(&g_bus.lock);

    return msg;
}

static void bus_eventfd_ep_callback(int fd, uint32_t events, void *arg)
{
    (void)arg;
    (void)events;

    uint64_t cnt = 0;
    read(fd, &cnt, sizeof(cnt));

    while(true)
    {
        message_t *msg = bus_pop_msg();
        if (msg == NULL)
        {
            break;
        }
        // dispatch msg to module
    }
}

int bus_init(void)
{
    memset(&g_bus, 0, sizeof(bus_ctx_t));
    pthread_mutex_init(&g_bus.lock, NULL);
    g_bus.eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_bus.eventfd < 0)
    {
        return -1;
    }

    return evloop_add(g_bus.eventfd, EPOLLIN, bus_eventfd_ep_callback, NULL);
}

int bus_post_msg(const char *dst, uint32_t msg_id, int payload_len, const void* payload)
{
    uint64_t one = 1;
    message_t *msg = msg_create(msg_id, "bus", dst, payload_len, payload);
    if (msg == NULL)
    {
        return -1;
    }

    if (bus_queue_push(msg) < 0)
    {
        msg_destroy(msg);
        return -1;
    }

    write(g_bus.eventfd, &one, sizeof(one));

    return 0;
}

int bus_dispatch_msg(message_t *msg)
{
    if (msg == NULL)
    {
        return -1;
    }

    module_t *mod = module_find(msg->dst_name);
    if (mod == NULL || mod->ops == NULL)
    {
        return -1;
    }

    if (mod->ops->on_msg != NULL)
    {
        return mod->ops->on_msg(mod, msg);
    }
    
    return 0;
}
