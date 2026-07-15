#ifndef _DWORKER_H_
#define _DWORKER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

struct daemon_task {
    unsigned int next_offset;
    unsigned int data_size;
    char data[0];    // flexible array member
};
typedef struct daemon_task dtask_t;

struct daemon_task_queue {
    char *tasks;    // task buffer, every task in buffer is calculated by offset
    unsigned int first_offset;    // offset of first valid task in tasks buffer
    unsigned int last_offset;     // offset of last valid task in tasks buffer
    unsigned int idle_offset;     // offset of first empty byte in tasks buffer
    unsigned int count;  // current count of tasks in tasks buffer
    unsigned int total;  // total count of requested tasks
    unsigned int drop;   // count of dropped tasks
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};
typedef struct daemon_task_queue task_queue_t;

struct daemon_worker {
    pthread_t tid;
    bool valid;
};
typedef struct daemon_worker dworker_t;

struct daemon_worker_manager {
    task_queue_t queue;
    dworker_t workers[WORKER_MAXNUM];
    atomic_uchar busy;
};
typedef struct daemon_worker_manager dworker_mgr_t;

int worker_manager_init(dworker_mgr_t* mgr);
void worker_manager_destroy(dworker_mgr_t* mgr);

#endif
