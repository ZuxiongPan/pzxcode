#ifndef _DDISPATCHER_H_
#define _DDISPATCHER_H_

#include <stdint.h>
#include <stddef.h>

unsigned int dispatcher_compid(void);

struct genl_upmsg {
    uint16_t target_len;    // bytes of target, the trailing NUL is not counted
    uint16_t data_len;
    char body[];            // target[target_len], '\0', data[data_len]
};

static inline const char *genl_upmsg_target(const struct genl_upmsg *msg)
{
    return msg->body;
}

static inline const char *genl_upmsg_data(const struct genl_upmsg *msg)
{
    return msg->body + msg->target_len + 1;
}

/* returns NULL when the payload does not carry the layout above */
static inline const struct genl_upmsg *genl_upmsg_check(unsigned int data_size,
    const char *data)
{
    const struct genl_upmsg *msg = (const struct genl_upmsg *)data;
    size_t need = 0;

    if (data == NULL || data_size < sizeof(*msg))
    {
        return NULL;
    }

    need = sizeof(*msg) + (size_t)msg->target_len + 1 + (size_t)msg->data_len;
    if (need != data_size)
    {
        return NULL;
    }

    if (msg->body[msg->target_len] != '\0')
    {
        return NULL;
    }

    return msg;
}

#endif
