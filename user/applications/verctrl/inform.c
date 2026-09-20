#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "verctrl.h"

static int sockfd = -1;

static const char *upgrade_stage[] = {
    [UPG_BEGIN] = "begin",
    [UPG_DOWNLOADING] = "downloading",
    [UPG_DOWNLOAD_FAILED] = "download failed",
    [UPG_DOWNLOADED] = "downloaded",
    [UPG_CHECKING] = "checking",
    [UPG_CHECK_FAILED] = "check failed",
    [UPG_CHECKED] = "checked",
    [UPG_WRITING] = "writing",
    [UPG_WRITE_FAILED] = "write failed",
    [UPG_WRITTEN] = "written",
    [UPG_SUCCESS] = "success",
    [UPG_END] = "end",
};

const char *get_upgrade_stage_str(enum upgrade_stage stage)
{
    return upgrade_stage[stage];
}

int init_uds_socket(void)
{
    int ret = -1;
    struct sockaddr_un addr;

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
        perror("connect uds");
        close(sockfd);
        sockfd = -1;
    }

    return sockfd;
}

int inform_to_armd(enum upgrade_stage stage)
{
    if (sockfd < 0)
    {
        printf("cannot inform to uds server\n");
        return -1;
    }

    ssize_t len = -1;
    char buf[UPG_MSG_MAXLEN];
    snprintf(buf, sizeof(buf), "/upgrade/result/%s", get_upgrade_stage_str(stage));

    len = send(sockfd, buf, strlen(buf), 0);

    return (len > 0);
}

void cleanup_uds_socket(void)
{
    if (sockfd >= 0)
    {
        close(sockfd);
        sockfd = -1;
    }

    return ;
}
