#ifndef _DCONF_H_
#define _DCONF_H_

#define ARMD_VERSION "0.1.0"

#define Success 0
#define Fail -1

#define EPOLL_EVENTS 256
#define COMPREC_HTABLE_SIZE 19U

#define TASK_QUEUE_SIZE (512 * 1024)
#define WORKER_MAXNUM 4
#define MONITOR_INTERVAL_SEC 3  // 3s interval

#define ONCE_DTIMER_MAXCNT 128

#define UDS_PATH "/var/armd.sock"
#define LISTENED_CLIENT_NUM 2
#define CLIENT_MAXNUM 5
// max bytes of one uds request, a whole json object. it has to fit into a single
// large task pool slot. sendcmd uses the same limit for the encoded message.
#define UDS_MSG_MAXLEN 1024
#define TCP_PORT 8888

#endif