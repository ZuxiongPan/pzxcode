#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "dconf.h"
#include "dcomp_info.h"
#include "lib/cJSON.h"

#define IO_TIMEOUT_SEC  3

static int uds_connect(const char *path)
{
    struct sockaddr_un addr;
    struct timeval tv;
    socklen_t addrlen;
    size_t path_len = strlen(path);
    int fd;

    if (path_len >= sizeof(addr.sun_path))
    {
        printf("socket path too long: %zu >= %zu\n",
            path_len, sizeof(addr.sun_path));
        return Fail;
    }

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        perror("socket(AF_UNIX, SOCK_SEQPACKET)");
        return Fail;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);
    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0)
    {
        printf("connect(%s): %s\n", path, strerror(errno));
        printf("  check: is armd running? is UDS_PATH correct? "
                        "do you have write permission on the socket?\n");
        close(fd);
        return Fail;
    }

    /* The server forwards the request to the dispatcher; an unknown command
     * may produce no reply at all. Never wait forever. */
    tv.tv_sec = IO_TIMEOUT_SEC;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

static int uds_send_record(int fd, const char *msg, size_t len)
{
    /* MSG_NOSIGNAL: a server that went away must not kill us with SIGPIPE. */
    ssize_t n = send(fd, msg, len, MSG_NOSIGNAL);

    if (n < 0)
    {
        printf("send: %s\n", strerror(errno));
        return Fail;
    }
    if ((size_t)n != len)
    {
        printf("short send: %zd of %zu bytes, record already truncated\n",
            n, len);
        return Fail;
    }

    return Success;
}

/* Replies may be text ("armd: ...") or binary; keep the output safe. */
static void dump_reply(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)buf[i];

        if (c == '\n')      printf("\\n");
        else if (c == '\r') printf("\\r");
        else if (c == '\t') printf("\\t");
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
}

static int uds_recv_reply(int fd)
{
    char buf[LINUX_PAGE_SIZE];

    for (;;)
    {
        /* MSG_TRUNC returns the real record length even if it does not fit. */
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_TRUNC);

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("(no response within %ds)\n", IO_TIMEOUT_SEC);
                return Fail;          /* not necessarily an error, see below */
            }
            printf("recv: %s\n", strerror(errno));
            return Fail;
        }
        if (n == 0)
        {
            printf("(server closed the connection without a reply)\n");
            return Fail;
        }
        if ((size_t)n > sizeof(buf))
        {
            printf("<- reply too large: %zd bytes (discarded)\n", n);
            return Fail;
        }

        printf("<- %zd bytes: ", n);
        dump_reply(buf, (size_t)n);
        putchar('\n');
        return Success;                   /* one request -> one reply record */
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("usage: %s -r -d <command> -t <target> -c <command>\n", argv[0]);
        return Fail;
    }
    
    int fd = -1, ret = Success;
    bool wait = false, dispatch = false;
    char buffer[LINUX_PAGE_SIZE];
    size_t len = 0;
    cJSON *root = cJSON_CreateObject();

    if (root == NULL)
    {
        printf("cJSON_CreateObject: %s\n", cJSON_GetErrorPtr());
        return Fail;
    }

    while ((ret = getopt(argc, argv, "rd:t:c:")) != -1)
    {
        switch (ret)
        {
        case 'r':
            wait = true;
            break;
        case 'd':
            dispatch = true;
            snprintf(buffer, sizeof(buffer), "{\"target\": \"%s\", \"command\": \"%s\"}", ModDispatcherName, optarg);
            break;
        case 't':
            cJSON_AddStringToObject(root, "target", optarg);
            break;
        case 'c':
            cJSON_AddStringToObject(root, "command", optarg);
            break;
        case '?':
        default:
            printf("usage: %s -r -d <command> -t <target> -c <command>\n", argv[0]);
            cJSON_Delete(root);
            return Fail;
        }
    }

    ret = Success;
    if (!dispatch)
    {
        /* cJSON_PrintPreallocated 返回的是 cJSON_bool（成功为 1），不是写入
         * 的字节数，长度只能用 strlen 量。之前把返回值当长度，请求会被截成
         * 1 个字节，服务端解析全部失败 */
        if (!cJSON_PrintPreallocated(root, buffer, sizeof(buffer), 0))
        {
            printf("cJSON_PrintPreallocated: %s\n", cJSON_GetErrorPtr());
            cJSON_Delete(root);
            return Fail;
        }
        len = strlen(buffer);
    }
    else
    {
        len = strlen(buffer);
    }
    cJSON_Delete(root);

    fd = uds_connect(UDS_PATH);
    if (fd < 0)
    {
        return Fail;
    }

    printf("-> %s: \"%s\" (%zu bytes, 1 SEQPACKET record)\n", UDS_PATH, buffer, len);
    if (uds_send_record(fd, buffer, len) != Success)
    {
        close(fd);
        return Fail;
    }

    if (wait)
    {
        ret = uds_recv_reply(fd);
    }
    close(fd);

    return ret;
}
