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
    if (argc != 3)
    {
        printf("usage: %s <mod> <req> <arg1> <arg2> ...\n", argv[0]);
        return -1;
    }

    int sockfd = -1;
    int ret = -1;
    ssize_t len = -1;
    struct sockaddr_un addr;
    char buf[TASK_DATA_MAXSIZE];

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
        sleep(1);
    }

    snprintf(buf, sizeof(buf), "{\"target\":\"%s\",\"request\":\"%s\"}", argv[1], argv[2]);
    len = send(sockfd, buf, strlen(buf), 0);
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

    ret = wait_for_response(sockfd, 3);
    if (ret > 0)
    {
        len = recv(sockfd, buf, sizeof(buf), 0);
        if (len > 0)
        {
            buf[len] = '\0';
            printf("receive uds message success, len: %ld, data:\n%s\n", len, buf);
        }
    }

    close(sockfd);
    return 0;
}
