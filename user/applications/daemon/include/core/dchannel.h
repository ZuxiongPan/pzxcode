#ifndef _DCHANNEL_H_
#define _DCHANNEL_H_

#include <stdint.h>
#include "core/dcontext.h"

struct dchannel {
    struct dcomp comp;
    int fd;
    int (*read_from_out)(struct dchannel *ch);
    /* optional: epoll reported EPOLLERR/EPOLLHUP, the peer is gone. the channel
     * is expected to drop its fd and unregister itself. without this hook the
     * event loop can only unregister it, which leaks whatever per connection
     * state the channel owns (a peer that closes normally also raises HUP). */
    void (*on_hangup)(struct dchannel *ch);
};

int dchannel_register(uint32_t events, struct dchannel *ch);
void dchannel_unregister(struct dchannel *ch);

#endif
