#ifndef _DCONTEXT_H_
#define _DCONTEXT_H_

#include <stdatomic.h>
#include <pthread.h>

#include "dextension.h"

// forward declaration
struct dworker_mgr;

// this is the daemon-component-type definition
enum dcomp_type {
    DCOMPTYPE_NONE = 0,
    DCOMPTYPE_CHANNEL = 1,
    DCOMPTYPE_MODULE = 2,
};

// this is the daemon-component definition
struct dcomp {
    unsigned int dcompid;   // dynamic set
    const char *name;   // fixed set
    enum dcomp_type type;
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
void stop_dctx_evloop(void);
void dcomp_init(struct dcomp *comp, const char *name);
int dcomp_record_add(struct dcomp *comp);
void dcomp_record_del(struct dcomp *comp);
const struct dcomp* find_dcomp_by_id(unsigned int id);
const struct dcomp* find_dcomp_by_name(const char *name);

//int dctx_info(char *inbuf, int bufsize);

#endif
