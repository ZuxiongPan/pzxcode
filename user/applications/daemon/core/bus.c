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
#include "core/worker.h"

message_t* msg_create(uint32_t msg_id, const char* src_name, const char* dst_name, 
    int payload_len, const void* payload)
{
    message_t *msg = calloc(1, sizeof(message_t) + payload_len);
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

    free(msg);
}

int bus_post_msg(const char *src, const char *dst, uint32_t msg_id, int payload_len, const void* payload)
{
    message_t *msg = msg_create(msg_id, src, dst, payload_len, payload);
    if (msg == NULL)
    {
        return -1;
    }

    return worker_push_msg(msg);
}

int bus_router_msg(message_t *msg)
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
