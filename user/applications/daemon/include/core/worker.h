#ifndef _WORKER_H_
#define _WORKER_H_

#include <stdint.h>

#define WORKER_MAX_CNT 16

struct message;

int worker_init(int worker_cnt);
int worker_push_msg(struct message *msg);
void worker_destroy(void);
int worker_busy_count(void);
int worker_queue_msgs(void);

#endif
