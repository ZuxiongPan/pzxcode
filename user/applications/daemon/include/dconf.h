#ifndef _DCONF_H_
#define _DCONF_H_

#define ARMD_VERSION "0.0.2"

#define Success 0
#define Fail -1

#define EPOLL_EVENTS 256
#define COMPREC_HTABLE_SIZE 19U

#define TASK_QUEUE_SIZE (512 * 1024)
#define WORKER_MAXNUM 4
#define MONITOR_INTERVAL_MS 300  // 300ms interval

#define MAX_DTIMER_COUNT 128

#define UDS_PATH "/var/armd.sock"
#define LISTENED_CLIENT_NUM 2
#define CLIENT_MAXNUM 5
#define TCP_PORT 8888

#endif