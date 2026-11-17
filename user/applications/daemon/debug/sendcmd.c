#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "dconf.h"
#include "dcomp_name.h"

#define REPLY_BUF_SIZE  4096U
#define IO_TIMEOUT_SEC  3

static int uds_connect(const char *path)
{
    struct sockaddr_un addr;
    struct timeval tv;
    socklen_t addrlen;
    size_t path_len = strlen(path);
    int fd;

    /* sun_path is fixed-size; a truncated path would connect nowhere while
     * the server binds the truncated one (same bug class as the server's
     * snprintf into sun_path). */
    if (path_len >= sizeof(addr.sun_path))
    {
        fprintf(stderr, "socket path too long: %zu >= %zu\n",
            path_len, sizeof(addr.sun_path));
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        perror("socket(AF_UNIX, SOCK_SEQPACKET)");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);
    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0)
    {
        fprintf(stderr, "connect(%s): %s\n", path, strerror(errno));
        fprintf(stderr, "  check: is armd running? is UDS_PATH correct? "
                        "do you have write permission on the socket?\n");
        close(fd);
        return -1;
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
        fprintf(stderr, "send: %s\n", strerror(errno));
        return -1;
    }
    if ((size_t)n != len)
    {
        fprintf(stderr, "short send: %zd of %zu bytes, record already truncated\n",
            n, len);
        return -1;
    }

    return 0;
}

/* Replies may be text ("armd: ...") or binary; keep the output safe. */
static void dump_reply(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)buf[i];

        if (c == '\n')      fputs("\\n", stdout);
        else if (c == '\r') fputs("\\r", stdout);
        else if (c == '\t') fputs("\\t", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar((int)c);
        else printf("\\x%02x", c);
    }
}

static int uds_recv_reply(int fd)
{
    char buf[REPLY_BUF_SIZE];

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
                fprintf(stderr, "(no response within %ds)\n", IO_TIMEOUT_SEC);
                return -1;          /* not necessarily an error, see below */
            }
            fprintf(stderr, "recv: %s\n", strerror(errno));
            return -1;
        }
        if (n == 0)
        {
            printf("(server closed the connection without a reply)\n");
            return -1;
        }
        if ((size_t)n > sizeof(buf))
        {
            printf("<- reply too large: %zd bytes (discarded)\n", n);
            return -1;
        }

        printf("<- %zd bytes: ", n);
        dump_reply(buf, (size_t)n);
        putchar('\n');
        return 0;                   /* one request -> one reply record */
    }
}

int main(int argc, char **argv)
{
    const char *msg  = (argc > 2) ? argv[2] : "{\"target\":\"module.dispatcher\",\"data\":\"hello world\"}";
    size_t len = strlen(msg);
    int fd;
    int rc;

    if (len == 0)
    {
        fprintf(stderr, "refusing to send an empty record: the server treats "
                        "recv()==0 as a hangup\n");
        return 1;
    }

    fd = uds_connect(UDS_PATH);
    if (fd < 0)
    {
        return 1;
    }

    printf("-> %s: \"%s\" (%zu bytes, 1 SEQPACKET record)\n", UDS_PATH, msg, len);
    if (uds_send_record(fd, msg, len) != 0)
    {
        close(fd);
        return 1;
    }

    rc = uds_recv_reply(fd);
    close(fd);                      /* peer sees recv()==0, slot is released */

    /* The daemon is NOT an echo server: "hello world" is forwarded to the
     * dispatcher as MSGID_INPUT_SOCKET. Unless that is a valid command for
     * proto_socket.c, expect a parse error or no reply - that still proves
     * the UDS link works. */
    return (rc == 0) ? 0 : 2;
}
