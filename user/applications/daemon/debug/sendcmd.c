#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "dconf.h"
#include "lib/cJSON.h"

static int wait_for_response(int fd, int timeout_sec)
{
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int ret = select(fd + 1, &fds, NULL, NULL, &tv);

    return ret;
}

int main(int argc, const char *argv[])
{
    if (argc < 3)
    {
        printf("usage: %s <type> <target> <arg1> <arg2> ...\n", argv[0]);
        printf("type: 1-simple string, 2-json string\n");
        return -1;
    }

    int sockfd = -1;
    int ret = -1, tmp = 0;
    int type = strtol(argv[1], NULL, 10);
    ssize_t len = -1;
    struct sockaddr_un addr;
    char buf[TASK_DATA_MAXSIZE];

    if (type != 1 && type != 2)
    {
        printf("type: 1-simple string, 2-json string\n");
        return -1;
    }

    sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sockfd < 0)
    {
        perror("socket create uds");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        if (errno != EINPROGRESS)
        {
            perror("connect uds");
            close(sockfd);
            return -1;
        }
    }

    if (type == 1)
    {
        tmp = snprintf(buf, sizeof(buf), "/%s", argv[2]);
        for (int i = 3; i < argc; i++)
        {
            tmp += snprintf(buf + tmp, sizeof(buf), "/%s", argv[i]);
        }
        len = send(sockfd, buf, tmp, 0);
    }
    else if (type == 2)
    {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "target", argv[2]);
        for (int i = 3; i < argc; i++)
        {
            memset(buf, 0, sizeof(buf));
            snprintf(buf, sizeof(buf), "arg%d", i - 3);
            cJSON_AddStringToObject(json, buf, argv[i]);
        }
        char *sendstr = cJSON_Print(json);
        len = send(sockfd, sendstr, strlen(sendstr), 0);
        cJSON_Delete(json);
        cJSON_free(sendstr);
    }

    if (len < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            perror("send uds message");
            close(sockfd);
            return -1;
        }
        printf("send uds buffer is full\n");
    }
    else
    {
        printf("send uds message success, len: %ld\n", len);
    }

    ret = wait_for_response(sockfd, 5);
    if (ret > 0)
    {
        memset(buf, 0, sizeof(buf));
        len = recv(sockfd, buf, sizeof(buf), 0);
        if (len > 0)
        {
            buf[len] = '\0';
            printf("receive uds message success, len: %ld, data:\n%s\n", len, buf);
        }
    }
    else
    {
        printf("no response from uds server\n");
    }

    close(sockfd);
    return 0;
}
