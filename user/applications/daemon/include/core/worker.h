#ifndef _WORKER_H_
#define _WORKER_H_

#include <stdint.h>

#define WORKER_MAX_CNT 16

int worker_init(int worker_cnt);
void worker_destroy(void);
int worker_busy_count(void);

#endif
