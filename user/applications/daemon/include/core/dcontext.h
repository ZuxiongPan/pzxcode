#ifndef _DCONTEXT_H_
#define _DCONTEXT_H_

#include <stdatomic.h>
#include <pthread.h>

typedef int (*dcomp_init_f)(void);
typedef void (*dcomp_exit_f)(void);

struct daemon_worker_manager;

enum daemon_layer {
    Layer_Channel = 0,
    Layer_Module,
    Layer_Unknown,
};
typedef enum daemon_layer dlayer_e;

#define CHANNELID_START (Layer_Channel << 16)
#define MODULEID_START (Layer_Module << 16)
#define PROTOID_START (Layer_Proto << 16)

struct daemon_component {
    int dcomp_id;
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
void daemon_context_init(void);
void daemon_context_run(void);
void daemon_context_destroy(void);
void dcomponent_init(dcomp_t *comp, int compid, const char *name);
int dcomponent_record_add(dcomp_t *comp, dlayer_e layer);
void dcomponent_record_del(dcomp_t *comp, dlayer_e layer);
dcomp_t* find_dcomponent_by_id(int compid, dlayer_e layer);
dcomp_t* find_dcomponent_by_name(const char *name, dlayer_e layer);

#endif
