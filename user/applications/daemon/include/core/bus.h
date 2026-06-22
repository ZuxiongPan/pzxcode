#ifndef _BUS_H_
#define _BUS_H_

#include "message.h"

int bus_init(void);
int bus_post_msg(const char *dst, uint32_t msg_id, int payload_len, const void* payload);
int bus_dispatch_msg(message_t *msg);

#endif
