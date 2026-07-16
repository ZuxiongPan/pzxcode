#ifndef _CHNL_API_H_
#define _CHNL_API_H_

#include <stdint.h>
#include <stdbool.h>

void dchannel_init(void);
void dchannel_exit(void);

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat);
void timer_del(int timer_id);

#endif