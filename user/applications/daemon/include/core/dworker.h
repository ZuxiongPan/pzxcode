#ifndef _DWORKER_H_
#define _DWORKER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

struct daemon_message {
    uint32_t msgid;
    int src_mid;
    int dst_mid;
    atomic_short refcnt;
    int payload_len;
    char payload[0];    // flexible array member
};
typedef struct daemon_message dmsg_t;

struct daemon_message_queue {
    dmsg_t *msgs;
    int head;
    int tail;
    int count;  // current count of messages in queue
    int total;  // total count of requested messages
    int drop;   // count of dropped messages
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};
typedef struct daemon_message_queue dmsg_queue_t;

struct daemon_worker {
    pthread_t tid;
    bool valid;
};
typedef struct daemon_worker dworker_t;

struct daemon_worker_manager {
    dmsg_queue_t queue;
    dworker_t workers[WORKER_MAXNUM];
    atomic_short busy;
};
typedef struct daemon_worker_manager dworker_mgr_t;

int worker_manager_init(dworker_mgr_t* mgr);
void worker_manager_destroy(dworker_mgr_t* mgr);

#endif
