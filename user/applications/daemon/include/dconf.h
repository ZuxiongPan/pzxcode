#ifndef _DCONF_H_
#define _DCONF_H_

#define ARMD_VERSION "0.0.1"

#define Success 0
#define Fail -1

#define EPOLL_EVENTS 256

#define TASK_QUEUE_BYTES (2 * 1024 * 1024)
#define TASK_DATA_MAXSIZE 4096  // limit task data size
#define WORKER_MAXNUM 16

#define MAX_DTIMER_COUNT 512

// uds/uevent/net receive buffer size
#define NETCHNL_RECV_BUF_SIZE 3072
#define TCP_PORT 8888
#define TCP_MAX_CONNECT 4
#define UDS_PATH "/var/armd.sock"

#endif
