#ifndef _DPROTO_H_
#define _DPROTO_H_

#include "core/dcontext.h"

#define ProtoIDUevent (PROTOID_START + 1)

struct daemon_proto;

struct proto_ops {
    // here arg is task pointer
    int (*encode)(const struct daemon_proto *proto, void *arg);
    int (*decode)(const struct daemon_proto *proto, void *arg);
};
typedef struct proto_ops proto_ops_t;

struct daemon_proto {
    dcomp_t dcomp;
    const proto_ops_t *ops;
    void *priv;
};
typedef struct daemon_proto dproto_t;

int dproto_register(dproto_t *proto);
void dproto_unregister(dproto_t *proto);
int dproto_handle(void *arg);

#endif
