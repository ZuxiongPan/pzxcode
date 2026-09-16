#ifndef _DCONF_H_
#define _DCONF_H_

#define ARMD_VERSION "0.0.2"

#define Success 0
#define Fail -1

#define EPOLL_EVENTS 256
#define COMPREC_HTABLE_SIZE 19

#define TASK_QUEUE_BYTES (2 * 1024 * 1024)
#define TASK_DATA_MAXSIZE 4096  // limit task data size
#define WORKER_MAXNUM 4

#define MAX_DTIMER_COUNT 128

#define UDS_PATH "/var/armd.sock"
#define LISTENED_CLIENT_NUM 2
#define CLIENT_MAXNUM 5
#define TCP_PORT 8888

#endif
