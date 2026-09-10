#ifndef _CHNL_API_H_
#define _CHNL_API_H_

#include <stdbool.h>
#include <stdint.h>

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat,
            int modid, unsigned int msgid);
void timer_del(int timer_id);
int dtimer_info(char *inbuf, int bufsize);

#endif
