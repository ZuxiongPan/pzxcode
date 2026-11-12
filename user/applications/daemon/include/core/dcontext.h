#ifndef _DCONTEXT_H_
#define _DCONTEXT_H_

#include <stdatomic.h>
#include <pthread.h>

#include "dconf.h"
#include "dextension.h"

// forward declaration
struct dworker_mgr;
struct dcomp;

struct msg_handler {
    const char *name;
    unsigned int msgid;
    int (*func)(const struct dcomp *self, unsigned int srcid,
        unsigned int data_size, const char *data);
};

// this is the daemon-component definition
struct dcomp {
    unsigned int dcompid;   // dynamic set
    const char *name;   // fixed set
    unsigned int handle_num;
    const struct msg_handler *handlers;
    struct lnode name_node;
    struct lnode id_node;
};

struct htable {
    struct lnode list[COMPREC_HTABLE_SIZE];
    pthread_rwlock_t rwlock;
};

// this is the daemon-context definition
struct dctx {
    atomic_bool status;
    atomic_uint next_id;
    int epfd;
    struct htable name_tb;
    struct htable id_tb;
};

struct dctx* dctx_instance(void);
void dctx_init(void);
void dctx_destroy(void);
void start_dctx_evloop(void);
void dcomp_init(struct dcomp *comp, const char *name);
int dcomp_record_add(struct dcomp *comp);
void dcomp_record_del(struct dcomp *comp);
const struct dcomp* find_dcomp_by_id(unsigned int id);
const struct dcomp* find_dcomp_by_name(const char *name);

static inline void dcomp_set_handlers(struct dcomp *comp, unsigned int num,
    const struct msg_handler *handlers)
{
    comp->handle_num = num;
    comp->handlers = handlers;
}

//int dctx_info(char *inbuf, int bufsize);

#endif
