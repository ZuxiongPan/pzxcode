#ifndef _EVLOOP_H_
#define _EVLOOP_H_

#include <stdint.h>

typedef void (*fd_event_f)(int fd, uint32_t events, void *arg);

struct fd_event {
    int fd;
    fd_event_f cb;
    void *arg;
};
typedef struct fd_event fd_event_t;

int evloop_add(uint32_t events, fd_event_t *fev);
int evloop_del(fd_event_t *fev);
int evloop_run(void);

#endif
