#ifndef _DCHANNEL_H_
#define _DCHANNEL_H_

#include <stdint.h>
#include <stdbool.h>
#include "core/dcontext.h"

#define ChannelIDTimer (CHANNELID_START + 1)
#define ChannelIDUevent (CHANNELID_START + 2)
#define ChannelIDUds (CHANNELID_START + 3)

struct daemon_channel;

struct channel_ops{
    int (*callback)(struct daemon_channel *ch);
};
typedef struct channel_ops channel_ops_t;

struct daemon_channel {
    dcomp_t dcomp;
    int fd;
    const channel_ops_t *ops;
    void *priv;
};
typedef struct daemon_channel dchannel_t;

int dchannel_register(uint32_t events, dchannel_t *chnl);
void dchannel_unregister(dchannel_t *chnl);
void dchannel_handle(void *arg);

#endif
