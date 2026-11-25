// for accept4
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "dispatcher/ddispatcher.h"

#define UDS_RECV_BATCH 4U

struct uds_client {
    struct dchannel ch;
    pthread_mutex_t lock;
    bool alive;
    bool used;
};

static struct dchannel ch_uds_server;
static struct uds_client clients[CLIENT_MAXNUM];

static int ch_uds_client_read_from_out(struct dchannel *ch);
static int uds_client_send(struct uds_client *client, const char *data,
    unsigned int size);

static int ch_uds_response_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(srcid);

    struct uds_client *client = container_of(self, struct uds_client, ch.comp);

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("empty response for uds client[%s]\n", self->name);
        return Fail;
    }

    return uds_client_send(client, data, data_size);
}

static const struct msg_handler client_handlers[] = {
    { .name = "response", .msgid = MSGID_UDS_RESPONSE, .func = ch_uds_response_handler },
};

static int uds_client_send(struct uds_client *client, const char *data,
    unsigned int size)
{
    int ret = Fail;
    ssize_t sent = 0;

    pthread_mutex_lock(&client->lock);
    if (!client->alive || client->ch.fd < 0)
    {
        pthread_mutex_unlock(&client->lock);
        ddebug("uds client is gone, response dropped\n");
        return Fail;
    }

    // MSG_NOSIGNAL: a peer that vanished must not raise SIGPIPE in a worker
    sent = send(client->ch.fd, data, size, MSG_NOSIGNAL);
    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            derror("uds client buffer full, response of %u bytes dropped\n", size);
        }
        else
        {
            derror("uds client send failed, errno: %d\n", errno);
        }
    }
    else if ((unsigned int)sent != size)
    {
        // seqpacket is all or nothing, a short send means the message was cut
        derror("uds client short send: %zd of %u\n", sent, size);
    }
    else
    {
        ret = Success;
    }
    pthread_mutex_unlock(&client->lock);

    return ret;
}

static int ch_uds_reply_error(struct uds_client *client, const char *text)
{
    char buf[LINUX_PAGE_SIZE];
    int len = 0;

    len = snprintf(buf, sizeof(buf), "armd: %s\n", text);
    if (unlikely(len < 0))
    {
        return Fail;
    }
    if ((size_t)len >= sizeof(buf))
    {
        len = (int)sizeof(buf) - 1;
    }

    uds_client_send(client, buf, (unsigned int)len);

    return Fail;
}

static void ch_uds_client_release(struct uds_client *client)
{
    if (!client->used)
    {
        return ;
    }

    dchannel_unregister(&client->ch);

    pthread_mutex_lock(&client->lock);
    client->alive = false;
    if (client->ch.fd >= 0)
    {
        close(client->ch.fd);
        client->ch.fd = -1;
    }
    pthread_mutex_unlock(&client->lock);

    client->used = false;
    lnode_init(&client->ch.comp.id_node);

    dprint("uds client released\n");
    return ;
}

static void ch_uds_client_hangup(struct dchannel *ch)
{
    ch_uds_client_release(container_of(ch, struct uds_client, ch));
}

static void ch_uds_forward(struct uds_client *client, const char *data,
    unsigned int len)
{
    if (unlikely(task_enqueue_by_id(client->ch.comp.dcompid, ModDispatcherId,
        MSGID_INPUT_SOCKET, len, data) != Success))
    {
        derror("uds client request of %u bytes dropped, queue is full\n", len);
        ch_uds_reply_error(client, "task queue full");
    }

    return ;
}

static int ch_uds_client_read_from_out(struct dchannel *ch)
{
    struct uds_client *client = container_of(ch, struct uds_client, ch);
    char buf[LINUX_PAGE_SIZE];
    unsigned int handled = 0;
    ssize_t len = 0;

    while (handled < UDS_RECV_BATCH)
    {
        // MSG_TRUNC makes recv return the real message length even when it does
        // not fit, without it an oversized request would be silently cut short
        len = recv(ch->fd, buf, sizeof(buf), MSG_TRUNC);
        if (len < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            derror("uds client recv failed, errno: %d\n", errno);
            ch_uds_client_release(client);
            return Fail;
        }
        if (len == 0)
        {
            dprint("uds client closed by peer\n");
            ch_uds_client_release(client);
            return Success;
        }

        handled++;

        if (unlikely((size_t)len > sizeof(buf)))
        {
            derror("uds client request too large: %zd > %zu\n", len, sizeof(buf));
            ch_uds_reply_error(client, "request too large");
            continue;
        }

        ch_uds_forward(client, buf, (unsigned int)len);

        // the peer may have gone away, a released slot has fd -1 and must not
        // be recv'ed again
        if (!client->alive)
        {
            break;
        }
    }

    return Success;
}

static int ch_uds_client_setup(struct uds_client *client, int fd)
{
    int ret = Success;

    dcomp_init(&client->ch.comp, ChUnixDomainSocketClientName, DCOMPID_RESERVED);
    dcomp_set_handlers(&client->ch.comp, ARRAY_SIZE(client_handlers), client_handlers);
    client->ch.read_from_out = ch_uds_client_read_from_out;
    client->ch.on_hangup = ch_uds_client_hangup;

    pthread_mutex_lock(&client->lock);
    client->ch.fd = fd;
    client->alive = true;
    pthread_mutex_unlock(&client->lock);

    ret = dchannel_register(EPOLLIN, &client->ch);
    if (unlikely(ret != Success))
    {
        derror("uds client[%ld] register failed\n", client - clients);
        ch_uds_client_release(client);
        return Fail;
    }

    dprint("[%ld] connected, fd[%d], id[%u]\n", client - clients, fd, client->ch.comp.dcompid);

    return Success;
}

static struct uds_client *ch_uds_client_alloc(void)
{
    struct uds_client *client = NULL;
    for (unsigned int i = 0; i < CLIENT_MAXNUM; i++)
    {
        if (!clients[i].used)
        {
            clients[i].used = true;
            client = &clients[i];
            break;
        }
    }

    return client;
}

static int ch_uds_server_read_from_out(struct dchannel *ch)
{
    struct uds_client *client = NULL;
    unsigned int accepted = 0;
    int fd = -1;

    while (accepted < LISTENED_CLIENT_NUM)
    {
        fd = accept4(ch->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
        {
            if (errno == EINTR || errno == ECONNABORTED)
            {
                // the peer gave up while queued, keep draining the backlog
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            derror("uds accept failed, errno: %d\n", errno);
            return Fail;
        }
        accepted++;

        client = ch_uds_client_alloc();
        if (client == NULL)
        {
            derror("no free uds client slot, connection rejected\n");
            close(fd);
            // do not break, the accept queue still has to be drained
            continue;
        }

        if (ch_uds_client_setup(client, fd) != Success)
        {
            continue;
        }
    }

    return Success;
}

static int ch_uds_init(void)
{
    struct sockaddr_un addr;
    int ret = Success;

    memset(&ch_uds_server, 0, sizeof(ch_uds_server));
    ch_uds_server.fd = -1;
    memset(&addr, 0, sizeof(addr));

    for (unsigned int i = 0; i < CLIENT_MAXNUM; i++)
    {
        memset(&clients[i], 0, sizeof(clients[i]));
        clients[i].ch.fd = -1;
        clients[i].used = false;
        clients[i].alive = false;
        pthread_mutex_init(&clients[i].lock, NULL);
    }

    dcomp_init(&ch_uds_server.comp, ChUnixDomainSocketName, ChUnixDomainSocketId);
    dcomp_set_handlers(&ch_uds_server.comp, 0, NULL);
    ch_uds_server.read_from_out = ch_uds_server_read_from_out;

    ch_uds_server.fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (unlikely(ch_uds_server.fd < 0))
    {
        derror("uds socket create failed, errno: %d\n", errno);
        return Fail;
    }

    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    // a stale socket file left by a crashed instance would fail bind()
    unlink(UDS_PATH);

    if (unlikely(bind(ch_uds_server.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0))
    {
        derror("uds bind[%s] failed, errno: %d\n", UDS_PATH, errno);
        ret = Fail;
        goto fail;
    }

    if (unlikely(listen(ch_uds_server.fd, LISTENED_CLIENT_NUM) < 0))
    {
        derror("uds listen failed, errno: %d\n", errno);
        ret = Fail;
        goto fail;
    }

    ret = dchannel_register(EPOLLIN, &ch_uds_server);
    if (unlikely(ret != Success))
    {
        derror("dchannel_register [%s] failed\n", ch_uds_server.comp.name);
        ret = Fail;
        goto fail;
    }

    dprint("[%s] info: fd[%d], id[%u], path[%s]\n",
        ch_uds_server.comp.name, ch_uds_server.fd, ch_uds_server.comp.dcompid, UDS_PATH);

    return Success;

fail:
    if (ch_uds_server.fd >= 0)
    {
        close(ch_uds_server.fd);
        ch_uds_server.fd = -1;
    }
    unlink(UDS_PATH);
    for (unsigned int i = 0; i < CLIENT_MAXNUM; i++)
    {
        pthread_mutex_destroy(&clients[i].lock);
    }

    return ret;
}

static void ch_uds_exit(void)
{
    for (unsigned int i = 0; i < CLIENT_MAXNUM; i++)
    {
        ch_uds_client_release(&clients[i]);
        pthread_mutex_destroy(&clients[i].lock);
    }

    dchannel_unregister(&ch_uds_server);
    if (ch_uds_server.fd >= 0)
    {
        close(ch_uds_server.fd);
        ch_uds_server.fd = -1;
    }
    unlink(UDS_PATH);

    dprint("[%s] exit\n", ch_uds_server.comp.name);
    return ;
}

DCOMP_INIT_LOWPRIO(ch_uds_init);
DCOMP_EXIT_LOWPRIO(ch_uds_exit);
