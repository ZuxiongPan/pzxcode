#ifndef _PROTO_H_
#define _PROTO_H_

#include <stdint.h>
#include "core/dcontext.h"

int msg_socket_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data);

int msg_uevent_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data);

int msg_genl_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data);

#endif
