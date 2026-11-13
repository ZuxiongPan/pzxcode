/*
 * sendcmd - armd unix domain socket debug client
 *
 * every request is one json object, the daemon dispatcher decodes it:
 *
 *     {"target":"status","data":"context"}
 *
 *   target  component name registered in the daemon
 *   data    payload for that component, one string built from the remaining
 *           arguments joined with single spaces
 *
 * the request is serialised with cJSON so quoting, backslashes and control
 * characters in the payload cannot break the message. keep the field names in
 * sync with dispatcher/proto_json.c.
 *
 *   sendcmd status context            -> {"target":"status","data":"context"}
 *   sendcmd -n upgrade update         -> fire and forget
 *   sendcmd -c 100 -i 0 status timer  -> stress run
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "dconf.h"
#include "lib/cJSON.h"

// answers may be much larger than a request, they never pass through a task slot
// on the client side but the daemon can still send up to a large pool slot
#define SENDCMD_RESP_MAXLEN 4096U
#define SENDCMD_CONNECT_TIMEOUT_MS 2000

struct sendcmd_opt {
    const char *target;
    char **cmd;
    int cmd_num;
    int count;
    int interval_ms;
    int timeout_ms;
    bool wait_reply;
    bool hexdump;
    bool quiet;
};

static void usage(const char *prog)
{
    printf("usage: %s [options] <target> [cmd arg ...]\n", prog);
    printf("\n");
    printf("  <target>        component name registered in the daemon, e.g. status, upgrade\n");
    printf("  [cmd arg ...]   payload words, joined with a single space into \"data\"\n");
    printf("\n");
    printf("options:\n");
    printf("  -n              do not wait for a response\n");
    printf("  -c <count>      repeat the request <count> times, default 1\n");
    printf("  -i <ms>         interval between repeats in ms, default 10\n");
    printf("  -t <ms>         response timeout in ms, default 1000\n");
    printf("  -x              hex dump the response instead of printing it as text\n");
    printf("  -q              quiet, only print the summary\n");
    printf("  -h              show this help\n");
    printf("\n");
    printf("the request is sent as {\"target\":\"<target>\",\"data\":\"<payload>\"}\n");
    printf("\n");
    printf("examples:\n");
    printf("  %s status context\n", prog);
    printf("  %s -n upgrade result:success\n", prog);
    printf("  %s -c 100 -i 0 -q status timer\n", prog);
}

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int uds_connect(const char *path)
{
    struct sockaddr_un addr;
    struct pollfd pfd;
    socklen_t errlen = sizeof(int);
    socklen_t addrlen = 0;
    int pathlen = 0;
    int err = 0;
    int fd = -1;

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    pathlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (pathlen < 0 || (size_t)pathlen >= sizeof(addr.sun_path))
    {
        fprintf(stderr, "socket path [%s] is too long\n", path);
        close(fd);
        return -1;
    }
    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + (size_t)pathlen + 1U);

    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0)
    {
        if (errno != EINPROGRESS)
        {
            fprintf(stderr, "connect %s: %s (is armd running?)\n", path, strerror(errno));
            close(fd);
            return -1;
        }

        // nonblocking connect on AF_UNIX only defers while the backlog is full
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, SENDCMD_CONNECT_TIMEOUT_MS) <= 0)
        {
            fprintf(stderr, "connect %s: timeout after %d ms\n", path,
                SENDCMD_CONNECT_TIMEOUT_MS);
            close(fd);
            return -1;
        }

        err = 0;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
        {
            fprintf(stderr, "connect %s: %s\n", path, strerror(err));
            close(fd);
            return -1;
        }
    }

    return fd;
}

static int uds_send(int fd, const char *req, size_t len)
{
    ssize_t sent = send(fd, req, len, MSG_NOSIGNAL);

    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            fprintf(stderr, "send: daemon receive buffer is full\n");
        }
        else if (errno == EMSGSIZE)
        {
            fprintf(stderr, "send: message of %zu bytes is too large\n", len);
        }
        else
        {
            fprintf(stderr, "send: %s\n", strerror(errno));
        }
        return -1;
    }

    return (int)sent;
}

/* returns the message length, 0 on timeout, -1 on error */
static int uds_recv(int fd, char *buf, size_t bufsize, int timeout_ms)
{
    struct pollfd pfd;
    ssize_t len = 0;
    int ret = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0)
    {
        if (errno != EINTR)
        {
            fprintf(stderr, "poll: %s\n", strerror(errno));
        }
        return -1;
    }
    if (ret == 0)
    {
        return 0;
    }

    // MSG_TRUNC reports the real length, so a response that does not fit can be
    // reported instead of being printed half way
    len = recv(fd, buf, bufsize, MSG_TRUNC);
    if (len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return 0;
        }
        fprintf(stderr, "recv: %s\n", strerror(errno));
        return -1;
    }
    if (len == 0)
    {
        fprintf(stderr, "recv: daemon closed the connection\n");
        return -1;
    }

    return (int)len;
}

static void print_hexdump(const char *data, size_t len)
{
    for (size_t i = 0; i < len; i += 16)
    {
        printf("%04zx  ", i);
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < len)
            {
                printf("%02x ", (unsigned char)data[i + j]);
            }
            else
            {
                printf("   ");
            }
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++)
        {
            unsigned char c = (unsigned char)data[i + j];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }

    return ;
}

static void print_payload(const char *data, size_t len, bool hexdump)
{
    printf("---- response: %zu bytes ----\n", len);

    if (hexdump)
    {
        print_hexdump(data, len);
        return ;
    }

    // the daemon sends the payload verbatim, it must not be treated as a C
    // string, write exactly len bytes
    fwrite(data, 1, len, stdout);
    if (len == 0 || data[len - 1] != '\n')
    {
        putchar('\n');
    }

    return ;
}

/* argv joined with single spaces, the caller frees, NULL on allocation failure */
static char *join_args(char **argv, int argc)
{
    size_t total = 1;
    char *out = NULL;
    size_t off = 0;

    for (int i = 0; i < argc; i++)
    {
        total += strlen(argv[i]) + 1;
    }

    out = malloc(total);
    if (out == NULL)
    {
        return NULL;
    }
    out[0] = '\0';

    for (int i = 0; i < argc; i++)
    {
        int written = 0;

        if (i > 0)
        {
            out[off++] = ' ';
        }
        written = snprintf(out + off, total - off, "%s", argv[i]);
        if (written < 0)
        {
            free(out);
            return NULL;
        }
        off += (size_t)written;
    }

    return out;
}

/*
 * the whole request, serialised by cJSON: a payload with quotes, backslashes or
 * a newline inside is escaped, so the daemon always receives valid json
 */
static char *build_request(const struct sendcmd_opt *opt)
{
    cJSON *root = NULL;
    char *data = NULL;
    char *json = NULL;

    data = join_args(opt->cmd, opt->cmd_num);
    if (data == NULL)
    {
        fprintf(stderr, "out of memory while joining the payload\n");
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL)
    {
        fprintf(stderr, "out of memory while building the request\n");
        free(data);
        return NULL;
    }

    if (cJSON_AddStringToObject(root, "target", opt->target) == NULL ||
        cJSON_AddStringToObject(root, "data", data) == NULL)
    {
        fprintf(stderr, "out of memory while building the request\n");
        cJSON_Delete(root);
        free(data);
        return NULL;
    }
    free(data);

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json == NULL)
    {
        fprintf(stderr, "out of memory while printing the request\n");
    }

    return json;
}

int main(int argc, char *argv[])
{
    struct sendcmd_opt opt;
    char *req = NULL;
    char resp[SENDCMD_RESP_MAXLEN];
    size_t req_len = 0;
    long long start = 0, elapsed = 0;
    int ok = 0, failed = 0, sent = 0;
    int optch = 0;
    int fd = -1;
    int len = 0;

    memset(&opt, 0, sizeof(opt));
    opt.count = 1;
    opt.interval_ms = 10;
    opt.timeout_ms = 1000;
    opt.wait_reply = true;

    while ((optch = getopt(argc, argv, "c:i:t:nxqh")) != -1)
    {
        switch (optch)
        {
            case 'c':
                opt.count = (int)strtol(optarg, NULL, 10);
                break;
            case 'i':
                opt.interval_ms = (int)strtol(optarg, NULL, 10);
                break;
            case 't':
                opt.timeout_ms = (int)strtol(optarg, NULL, 10);
                break;
            case 'n':
                opt.wait_reply = false;
                break;
            case 'x':
                opt.hexdump = true;
                break;
            case 'q':
                opt.quiet = true;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "missing <target>\n\n");
        usage(argv[0]);
        return -1;
    }

    if (opt.count <= 0 || opt.interval_ms < 0 || opt.timeout_ms <= 0)
    {
        fprintf(stderr, "invalid count/interval/timeout\n");
        return -1;
    }

    opt.target = argv[optind];
    opt.cmd = &argv[optind + 1];
    opt.cmd_num = argc - optind - 1;

    if (opt.target[0] == '\0' || strchr(opt.target, '/') != NULL)
    {
        fprintf(stderr, "invalid target [%s]: must be a component name "
            "without '/'\n", opt.target);
        return -1;
    }

    req = build_request(&opt);
    if (req == NULL)
    {
        return -1;
    }

    req_len = strlen(req);
    if (req_len > UDS_MSG_MAXLEN)
    {
        // json escaping can make the message longer than the payload suggests
        fprintf(stderr, "request of %zu bytes after json encoding is too long, "
            "max %u bytes\n", req_len, UDS_MSG_MAXLEN);
        free(req);
        return -1;
    }

    fd = uds_connect(UDS_PATH);
    if (fd < 0)
    {
        free(req);
        return -1;
    }

    if (!opt.quiet)
    {
        printf("request: %s (%zu bytes)\n", req, req_len);
    }

    start = now_ms();
    for (int i = 0; i < opt.count; i++)
    {
        if (uds_send(fd, req, req_len) < 0)
        {
            failed++;
        }
        else
        {
            sent++;
            if (!opt.wait_reply)
            {
                ok++;
            }
            else
            {
                len = uds_recv(fd, resp, sizeof(resp), opt.timeout_ms);
                if (len < 0)
                {
                    failed++;
                }
                else if (len == 0)
                {
                    printf("no response within %d ms\n", opt.timeout_ms);
                    failed++;
                }
                else
                {
                    ok++;
                    if (!opt.quiet)
                    {
                        if ((size_t)len > sizeof(resp))
                        {
                            printf("---- response truncated: %d > %zu bytes ----\n",
                                len, sizeof(resp));
                            print_payload(resp, sizeof(resp), opt.hexdump);
                        }
                        else
                        {
                            print_payload(resp, (size_t)len, opt.hexdump);
                        }
                    }
                }
            }
        }

        if (i + 1 < opt.count && opt.interval_ms > 0)
        {
            usleep((useconds_t)opt.interval_ms * 1000U);
        }
    }
    elapsed = now_ms() - start;

    if (opt.count > 1 || opt.quiet)
    {
        printf("sent: %d, ok: %d, failed: %d, elapsed: %lld ms, avg: %.2f ms\n",
            sent, ok, failed, elapsed,
            sent > 0 ? (double)elapsed / (double)sent : 0.0);
    }

    close(fd);
    free(req);

    return (failed > 0) ? 1 : 0;
}
