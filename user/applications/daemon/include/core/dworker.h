#ifndef _DWORKER_H_
#define _DWORKER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#include "dconf.h"

#define SMALL_POOL_SLOT_SIZE 256U
#define MEDIUM_POOL_SLOT_SIZE 1024U
#define LARGE_POOL_SLOT_SIZE 4096U

// task queue allocation policy small:medium:large = 1:2:1
#define SMALL_POOL_SIZE (TASK_QUEUE_SIZE / 4)
#define MEDIUM_POOL_SIZE (TASK_QUEUE_SIZE / 2)
#define LARGE_POOL_SIZE (TASK_QUEUE_SIZE / 4)

#define SMALL_POOL_SLOTS (SMALL_POOL_SIZE / SMALL_POOL_SLOT_SIZE)
#define MEDIUM_POOL_SLOTS (MEDIUM_POOL_SIZE / MEDIUM_POOL_SLOT_SIZE)
#define LARGE_POOL_SLOTS (LARGE_POOL_SIZE / LARGE_POOL_SLOT_SIZE)

#define BITMAP_BITS 1024U    // max bit size of bitmap
#define BITMAP_UNIT_BITS 32U // storage unit of bitmap
#define BITMAP_UNIT_FULL 0xffffffffU

#define BITMAP_MAXSIZE (BITMAP_BITS / BITMAP_UNIT_BITS)

enum {
    SmallPool = 0,
    MediumPool = 1,
    LargePool = 2,
    PoolMax = 3
};

enum dest_type {
    DEST_ID = 0,
    DEST_NAME = 1,
};

union destination {
    unsigned int dstid;
    const char *dstname;
};

struct destinfo {
    union destination dst;
    enum dest_type type;
};

struct dtask {
    unsigned int slot_idx;     // task index in pool memory
    struct dtask *next; // next task in queue
    // task info
    unsigned int srcid; // source component id of task
    struct destinfo dstinfo; // destination component info of task
    unsigned int msgid; // message id of task
    unsigned int data_size; // data size of task
    char data[];    // flexible array member
};

struct dtask_pool {
    char *base;              // pool memory base address
    unsigned int slot_size; // slot size (256/1024/4096)
    unsigned int slots;     // this pool has slots number
    unsigned int bitmap_size;   // real bitmap size (slots / BITMAP_UNIT_BITS)
    uint32_t bitmap[BITMAP_MAXSIZE];    // bitmap
};

struct dtask_queue {
    struct dtask_pool pools[PoolMax]; // small:medium:large pool
    struct dtask *head;   // the first task will be dealt
    struct dtask *tail;     // the last task will be dealt
    unsigned int count; // current task count in queue
    unsigned int total; // the total enqueue task count
    unsigned int drop;  // the dropped task count
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct dworker {
    pthread_t tid;
    bool valid;
};

struct dworker_mgr {
    bool initialized;
    struct dtask_queue queue;
    struct dworker workers[WORKER_MAXNUM];
    // for monitoring workers, there will add saving feature when workers are all blocked
    struct dworker monitor;
    atomic_uchar busy;
};

int worker_mgr_init(void);
void worker_mgr_destroy(void);
int task_enqueue_by_id(unsigned int srcid, unsigned int dstid, unsigned int msgid,
    unsigned int data_size, const char *data);
int task_enqueue_by_name(unsigned int srcid, const char *dst_name, unsigned int msgid,
    unsigned int data_size, const char *data);


#endif