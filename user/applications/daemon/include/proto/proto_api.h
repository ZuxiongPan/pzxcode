#ifndef _PROTO_API_H_
#define _PROTO_API_H_

typedef struct dproto_data {
    int src_compid; // real component id from channel/module
    int dst_compid; // real component id from channel/module
    char json_data[0];  // json string data
} dproto_data_t;

void dproto_init(void);
void dproto_exit(void);

#endif