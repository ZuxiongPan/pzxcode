#ifndef _DNET_H_
#define _DNET_H_

#include <stdbool.h>
#include "core/message.h"

#define DNET_RECV_BUF_SIZE 4096
#define TCP_PORT 8888
#define TCP_MAX_CONNECT 4
#define UDS_PATH "/var/armd.sock"

int tcp_init(void);
int tcp_send(const message_t *msg);
bool tcp_add_new_client(int fd);

int uds_init(void);
int uevent_init(void);

#endif