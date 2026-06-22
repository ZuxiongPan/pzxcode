#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include "common.h"

typedef struct message {
    uint32_t msg_id;
    char src_name[STRUCT_INNER_NAME_LEN];
    char dst_name[STRUCT_INNER_NAME_LEN];
    int payload_len;
    char *payload;
} message_t;

message_t* msg_create(uint32_t msg_id, const char* src_name, const char* dst_name, 
    int payload_len, const void* payload);
void msg_destroy(message_t *msg);

#endif
