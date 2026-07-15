#ifndef _DPROTO_H_
#define _DPROTO_H_

#include "core/dcontext.h"

struct daemon_proto;

typedef int (*dproto_encode_f)(struct daemon_proto *proto, void *outbuf,
    const void *data, unsigned int data_size);
typedef int (*dproto_decode_f)(struct daemon_proto *proto, void *inbuf,
    const void *data, unsigned int data_size);

struct daemon_proto {
    dcomp_t dcomp;
    const dproto_encode_f encode;
    const dproto_decode_f decode;
    void *priv;
};
typedef struct daemon_proto dproto_t;

int dproto_register(dproto_t *proto);
void dproto_unregister(dproto_t *proto);

#endif
