#ifndef _TIMER_H_
#define _TIMER_H_

#include <stdint.h>
#include <stdbool.h>

typedef void (*timer_cb_f)(void *arg);

typedef struct dtimer {
    uint64_t timer_id;
    uint64_t expire_ms;
    uint64_t interval_ms;
    bool repeat;
    int heap_idx;
    timer_cb_f cb;
    void *arg;
} dtimer_t;

int timer_init(void);
uint64_t timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat, 
    timer_cb_f cb, void *arg);
int timer_del(uint64_t timer_id);

#endif
