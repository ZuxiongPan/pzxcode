#ifndef _EVLOOP_H_
#define _EVLOOP_H_

#include <stdint.h>

#define MAX_EPOLL_EVENTS 512

typedef void (*fd_event_f)(int fd, uint32_t events, void *arg);

int evloop_init(void);
int evloop_add(int fd, uint32_t events, fd_event_f cb, void *arg);
int evloop_del(int fd);
int evloop_run(void);
int evloop_stop(void);

#endif
