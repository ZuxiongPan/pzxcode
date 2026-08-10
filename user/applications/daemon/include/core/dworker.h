#ifndef _DWORKER_H_
#define _DWORKER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#define DCOMPID_NONE 0xFFFFFFFF

enum dtask_type {
    TaskInvalid = 0,
    TaskEncode,  // task encode
    TaskDecode, // task decode
    TaskInform, // task inner module message
};
typedef enum dtask_type dtask_type_e;

struct daemon_task {
    dtask_type_e type;
    int src_compid; // source component of task
    int dst_compid; // destination component of task
    unsigned int msgid; // if this is an inform task, msgid is needed
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
    uint8_t valid;  // valid worker count
    atomic_uchar busy;
};
typedef struct daemon_worker_manager dworker_mgr_t;

int worker_manager_init(dworker_mgr_t* mgr);
void worker_manager_destroy(dworker_mgr_t* mgr);
// if type is not TaskInform, msgid is set to 0
int task_enqueue(dtask_type_e type, int src, int dst,
    unsigned int msgid, unsigned int data_size, const char *data);

#endif
