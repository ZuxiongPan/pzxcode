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

// dcompid 0 is reserved as the "invalid / broadcast" marker, real ids start at 1
#define DCOMPID_RESERVED 0U

// this is the daemon-context definition
struct dctx {
    atomic_bool status;
    atomic_uint next_id;
    int epfd;
    int wakefd;     // eventfd used to break out of epoll_wait from any thread
    struct htable name_tb;
    struct htable id_tb;
};

struct dctx* dctx_instance(void);
void dctx_init(void);
void dctx_destroy(void);
void start_dctx_evloop(void);
void stop_daemon_evloop(void);
void dcomp_init(struct dcomp *comp, const char *name);
int dcomp_record_add(struct dcomp *comp);
void dcomp_record_del(struct dcomp *comp);
/* NOTE: the lookup runs under the table read lock, but the returned pointer is
 * used after the lock is released. The caller must guarantee the component
 * outlives the use (all current components are static, keep it that way). */
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
