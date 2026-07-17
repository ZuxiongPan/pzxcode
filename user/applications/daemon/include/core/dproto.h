#ifndef _DPROTO_H_
#define _DPROTO_H_

#include "core/dcontext.h"

#define PROTO_OP_ENCODE 0
#define PROTO_OP_DECODE 1

struct daemon_proto;

struct proto_ops {
    int (*encode)(const struct daemon_proto *proto, void *outbuf,
        const void *data, unsigned int data_size);
    int (*decode)(const struct daemon_proto *proto, void *inbuf,
        const void *data, unsigned int data_size);
};
typedef struct proto_ops proto_ops_t;

struct daemon_proto {
    dcomp_t dcomp;
    const proto_ops_t *ops;
    void *priv;
};
typedef struct daemon_proto dproto_t;

struct dproto_data {
    int op;
    char data[0];
};
typedef struct dproto_data dpdata_t;

int dproto_register(dproto_t *proto);
void dproto_unregister(dproto_t *proto);

#endif
