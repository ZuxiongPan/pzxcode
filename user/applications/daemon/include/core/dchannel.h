#ifndef _DCHANNEL_H_
#define _DCHANNEL_H_

#include "core/dcontext.h"
#include <stdint.h>

struct daemon_channel;

typedef void (*dchannel_cb_f)(struct daemon_channel *ch);

struct daemon_channel {
    dcomp_t dcomp;
    int fd;
    const dchannel_cb_f cb;
    void *priv;
};
typedef struct daemon_channel dchannel_t;

int dchannel_register(uint32_t events, dchannel_t *chnl);
void dchannel_unregister(dchannel_t *chnl);

#endif
