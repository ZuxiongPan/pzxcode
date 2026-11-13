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
    [UPG_DOWNLOADING] = "downloading",
    [UPG_DOWNLOAD_FAILED] = "download failed",
    [UPG_DOWNLOADED] = "downloaded",
    [UPG_BEGIN] = "begin",
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
    if ((unsigned int)stage >= (sizeof(upgrade_stage) / sizeof(upgrade_stage[0])))
    {
        return "unknown";
    }

    return upgrade_stage[stage];
}

/*
 * the request has to be the json the daemon's dispatcher decodes:
 *
 *     {"target":"upgrade","data":"result:<stage>"}
 *
 * so the payload is escaped here. the stage strings are plain words today, but a
 * quote or a control character would otherwise produce a broken request that the
 * daemon can only reject as "invalid json", which hides the real cause.
 */
static void json_escape(char *dst, size_t cap, const char *src)
{
    size_t out = 0;

    if (cap == 0)
    {
        return ;
    }

    for (const unsigned char *p = (const unsigned char *)src; *p != '\0'; p++)
    {
        // six bytes for a \u00xx escape plus the terminator have to fit
        if (out + 7U >= cap)
        {
            break;
        }

        switch (*p)
        {
            case '"':
                dst[out++] = '\\';
                dst[out++] = '"';
                break;
            case '\\':
                dst[out++] = '\\';
                dst[out++] = '\\';
                break;
            case '\n':
                dst[out++] = '\\';
                dst[out++] = 'n';
                break;
            case '\r':
                dst[out++] = '\\';
                dst[out++] = 'r';
                break;
            case '\t':
                dst[out++] = '\\';
                dst[out++] = 't';
                break;
            default:
                if (*p < 0x20U)
                {
                    out += (size_t)snprintf(dst + out, cap - out, "\\u%04x", *p);
                }
                else
                {
                    dst[out++] = (char)*p;
                }
                break;
        }
    }

    dst[out] = '\0';

    return ;
}

int init_uds_socket(void)
{
    int ret = -1;
    struct sockaddr_un addr;

    sockfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
    char payload[UPG_MSG_MAXLEN];
    char escaped[UPG_MSG_MAXLEN];
    char msg[UPG_MSG_MAXLEN * 2U];
    int len = 0;
    ssize_t sent = 0;

    if (sockfd < 0)
    {
        printf("cannot inform to uds server\n");
        return -1;
    }

    len = snprintf(payload, sizeof(payload), "result:%s",
        get_upgrade_stage_str(stage));
    if (len < 0 || (size_t)len >= sizeof(payload))
    {
        printf("upgrade stage message is too long\n");
        return -1;
    }

    json_escape(escaped, sizeof(escaped), payload);

    len = snprintf(msg, sizeof(msg), "{\"target\":\"%s\",\"data\":\"%s\"}",
        UPG_JSON_TARGET, escaped);
    if (len < 0 || (size_t)len >= sizeof(msg))
    {
        printf("inform message is too long\n");
        return -1;
    }

    // the socket is non blocking and seqpacket keeps one send as one message
    sent = send(sockfd, msg, (size_t)len, MSG_NOSIGNAL);
    if (sent < 0)
    {
        printf("inform to armd failed, errno: %d\n", errno);
        return -1;
    }
    if (sent != len)
    {
        printf("inform to armd was cut, %zd of %d bytes\n", sent, len);
        return -1;
    }

    return 0;
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
