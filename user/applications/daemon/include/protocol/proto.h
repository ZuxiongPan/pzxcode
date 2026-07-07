#ifndef _PROTO_H_
#define _PROTO_H_

typedef enum msg_proto {
    RAW = 0, // msg buffer is directly used
    JSON = 1, // msg buffer is a json string
    INVALID,
} msg_proto_e;

#endif