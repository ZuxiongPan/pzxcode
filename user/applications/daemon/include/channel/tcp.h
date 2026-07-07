#ifndef _TCP_H_
#define _TCP_H_

#include <stdbool.h>

#define TCP_PORT 8888
#define TCP_MAX_CONNECT 8
#define TCP_RECV_BUF_SIZE 4096

int tcp_init(void);
bool tcp_add_new_client(int fd);

#endif