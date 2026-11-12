#ifndef _DCHANNEL_H_
#define _DCHANNEL_H_

#include <stdint.h>
#include "core/dcontext.h"

struct dchannel {
    struct dcomp comp;
    int fd;
    int (*read_from_out)(struct dchannel *ch);
};

int dchannel_register(uint32_t events, struct dchannel *ch);
void dchannel_unregister(struct dchannel *ch);

#endif
