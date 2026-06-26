#ifndef _EVLOOP_H_
#define _EVLOOP_H_

#include <stdint.h>

#define MAX_EPOLL_EVENTS 512

typedef void (*fd_event_f)(int fd, uint32_t events, void *arg);

typedef struct fd_event {
    int fd;
    fd_event_f cb;
    void *arg;
} fd_event_t;

int evloop_init(void);
int evloop_add(uint32_t events, fd_event_t *fev);
int evloop_del(fd_event_t *fev);
int evloop_run(void);
int evloop_stop(void);

#endif
