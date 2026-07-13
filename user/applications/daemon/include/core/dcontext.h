#ifndef _DCONTEXT_H_
#define _DCONTEXT_H_

#include <stdatomic.h>
#include <pthread.h>

struct daemon_worker_manager;

enum daemon_layer {
    Layer_Channel = 0,
    Layer_Module,
    Layer_Proto,
    Layer_Unknown,
};
typedef enum daemon_layer dlayer_e;

struct daemon_component {
    dlayer_e type;
    const char *name;
    struct daemon_component *prev;
    struct daemon_component *next;
};
typedef struct daemon_component dcomp_t;

struct dlayer_record {
    dcomp_t sentinel;
    pthread_rwlock_t rwlock;
};
typedef struct dlayer_record dlayer_rec_t;

struct daemon_context {
    atomic_bool status;
    int epfd;
    struct daemon_worker_manager *worker_mgr;
    dlayer_rec_t records[Layer_Unknown];
};
typedef struct daemon_context dctx_t;

dctx_t* dctx_instance(void);
int daemon_context_init(void);
void daemon_context_destroy(void);

#endif
