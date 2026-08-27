#ifndef _CHNL_API_H_
#define _CHNL_API_H_

#include <stdbool.h>
#include <stdint.h>

void dchannel_init(void);
void dchannel_exit(void);

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat,
            int modid, unsigned int msgid);
void timer_del(int timer_id);

#endif