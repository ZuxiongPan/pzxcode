#ifndef _DCHANNEL_H_
#define _DCHANNEL_H_

#include "core/dcontext.h"
#include <stdint.h>

struct daemon_channel;

typedef void (*dchannel_cb_f)(struct daemon_channel *ch);
typedef int (*dchannel_init_f)(void);
typedef void (*dchannel_exit_f)(void);

struct daemon_channel {
    dcomp_t dcomp;
    int fd;
    dchannel_cb_f cb;
    void *priv;
};
typedef struct daemon_channel dchannel_t;

int dchannel_register(uint32_t events, dchannel_t *ch);
void dchannel_unregister(dchannel_t *ch);

#endif
