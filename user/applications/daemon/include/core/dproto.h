#ifndef _DPROTO_H_
#define _DPROTO_H_

#include "core/dcontext.h"

#define PROTO_OP_ENCODE 0
#define PROTO_OP_DECODE 1

struct daemon_proto;

enum dproto_type {
    ProtoUnused = 0,
    ProtoUevent,
    ProtoInvalid,
};
typedef enum dproto_type dproto_type_e;

struct proto_ops {
    int (*encode)(const struct daemon_proto *proto, void *outbuf,
        unsigned int outbuf_size, const void *data);
    int (*decode)(const struct daemon_proto *proto, void *inbuf,
        unsigned int inbuf_size, void *data);
};
typedef struct proto_ops proto_ops_t;

struct daemon_proto {
    dcomp_t dcomp;
    const proto_ops_t *ops;
    void *task_tmp;
};
typedef struct daemon_proto dproto_t;

struct dproto_data {
    dproto_type_e type;
    int op;
    unsigned int data_size;
    char data[0];
};
typedef struct dproto_data dpdata_t;

int dproto_register(dproto_t *proto);
void dproto_unregister(dproto_t *proto);
const char *dproto_get_name(dproto_type_e proto);
int dproto_handle(void *arg);

#endif
