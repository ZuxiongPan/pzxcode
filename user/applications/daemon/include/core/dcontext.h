#ifndef _DCONTEXT_H_
#define _DCONTEXT_H_

#include <stdatomic.h>
#include <pthread.h>

struct daemon_worker_manager;

// mask definition
// bit 0-23: the component id of type
// bit 24-31: the type of this id, 00-component 01-uds client 02-tcp client
#define DCOMPID_NONE 0xFFFFFFFF
#define COMP_IDMASK 0x00ffffff
#define COMP_TYPEMASK 0xff000000
#define FIXEDCOMP_IDSTART 0x00000000
#define UDSCLIENT_IDSTART 0x01000000
#define TCPCLIENT_IDSTART 0x02000000

// component layer id definition, bit 16-23 is the layer
#define CHANNELID_START (0x1 << 16)
#define MODULEID_START (0x2 << 16)

struct daemon_component {
    int dcompid;
    const char *name;
    struct daemon_component *next;
};
typedef struct daemon_component dcomp_t;

struct daemon_context {
    atomic_bool status;
    int epfd;
    struct daemon_worker_manager *worker_mgr;
    dcomp_t *htable[COMPREC_HTABLE_SIZE];
    pthread_rwlock_t ht_rwlock;
};
typedef struct daemon_context dctx_t;

dctx_t* dctx_instance(void);
void daemon_context_init(void);
void daemon_context_run(void);
void daemon_context_destroy(void);
void dcomponent_init(dcomp_t *comp, int compid, const char *name);
int dcomponent_record_add(dcomp_t *comp);
void dcomponent_record_del(dcomp_t *comp);
dcomp_t* find_dcomponent_by_id(int compid);
dcomp_t* find_dcomponent_by_name(const char *name);
int dctx_info(char *inbuf, int bufsize);

#endif
