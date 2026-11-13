/*
 * unix domain socket control channel
 *
 * this file is transport only: it moves bytes between a socket and the task
 * queue. it does not know what those bytes mean, which component they are for
 * or how an answer has to look. decoding is the job of ModuleDispatcher, the
 * channel only tags the payload with the wire format of its own transport.
 *
 * one send() is exactly one message (SOCK_SEQPACKET keeps the boundaries, so
 * there is no length prefix and no re-assembly):
 *
 *     json text, the field layout belongs to the dispatcher
 *
 * a request is forwarded as
 *
 *     task_enqueue_by_id(client_id, ModuleDispatcher, MSGID_INPUT_JSON, ...)
 *
 * and the parsed request reaches the addressed component with srcid untouched,
 * so the component answers with
 *
 *     task_enqueue_by_id(self->dcompid, srcid, MSGID_UDS_RESPONSE, len, buf)
 *
 * every connected client owns its own component: that component is the address
 * an answer is delivered to, which is how a reply finds its connection again
 * without the channel having to track requests.
 */

// SO_PEERCRED and struct ucred are glibc extensions, the build does not pass
// -D_GNU_SOURCE, so enable it before the first system header
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
#include "dcomp_name.h"
#include "core/dcontext.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"

#define UDS_CLIENT_NAME_MAXLEN 32U

// drain at most this many messages (accepts) per epoll wakeup: the channel is
// level triggered, so a flooding peer would otherwise monopolize the loop thread
#define UDS_RECV_BATCH 16U
#define UDS_ACCEPT_BATCH 8U

struct uds_client {
    struct dchannel ch;     // must stay first, epoll dispatches on &ch
    const char *name;       // "channel.uds.client<N>", stable for the slot
    pthread_mutex_t lock;   // serializes fd write against close
    bool alive;             // fd is open, only true while holding lock on use
    bool used;              // slot is taken, only touched by the evloop thread
};

static struct dchannel ch_uds_server;
static struct uds_client clients[CLIENT_MAXNUM];
static char client_names[CLIENT_MAXNUM][UDS_CLIENT_NAME_MAXLEN];
// resolved once at init: ModuleDispatcher is registered in a higher priority
// group and never leaves the component table, so the id stays valid
static unsigned int dispatcher_id = DCOMPID_RESERVED;

static int ch_uds_client_read_from_out(struct dchannel *ch);
static int uds_client_send(struct uds_client *client, const char *data,
    unsigned int size);

/*
 * the answer of a component arrives here: the client component is the address a
 * request's srcid points at. nothing has to be correlated, the reply is written
 * to the socket this slot owns.
 */
static int ch_uds_response_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(srcid);

    // self points at the dcomp embedded in our own client object
    struct uds_client *client = container_of(self, struct uds_client, ch.comp);

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("empty response for uds client[%s]\n", self->name);
        return Fail;
    }

    return uds_client_send(client, data, data_size);
}

static const struct msg_handler client_handlers[] = {
    { .name = "uds.response", .msgid = MSGID_UDS_RESPONSE, .func = ch_uds_response_handler },
};

static int set_nonblock_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (unlikely(flags < 0))
    {
        return Fail;
    }
    // O_CLOEXEC is a descriptor flag, it does not belong in F_SETFL
    if (unlikely(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0))
    {
        return Fail;
    }

    flags = fcntl(fd, F_GETFD, 0);
    if (unlikely(flags < 0))
    {
        return Fail;
    }
    if (unlikely(fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0))
    {
        return Fail;
    }

    return Success;
}

/*
 * the client fd may be closed by the event loop thread while a worker thread is
 * still writing a response, so every send is done under the per client lock and
 * re-validates the fd. the slot is never freed, which keeps a stale dcomp
 * pointer handed out by find_dcomp_by_id() harmless.
 */
static int uds_client_send(struct uds_client *client, const char *data,
    unsigned int size)
{
    int ret = Fail;
    ssize_t sent = 0;

    pthread_mutex_lock(&client->lock);
    if (!client->alive || client->ch.fd < 0)
    {
        pthread_mutex_unlock(&client->lock);
        ddebug("uds client[%s] is gone, response dropped\n", client->name);
        return Fail;
    }

    // MSG_NOSIGNAL: a peer that vanished must not raise SIGPIPE in a worker
    sent = send(client->ch.fd, data, size, MSG_NOSIGNAL);
    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            derror("uds client[%s] buffer full, response of %u bytes dropped\n",
                client->name, size);
        }
        else
        {
            derror("uds client[%s] send failed, errno: %d\n", client->name, errno);
        }
    }
    else if ((unsigned int)sent != size)
    {
        // seqpacket is all or nothing, a short send means the message was cut
        derror("uds client[%s] short send: %zd of %u\n", client->name, sent, size);
    }
    else
    {
        ret = Success;
    }
    pthread_mutex_unlock(&client->lock);

    return ret;
}

/*
 * framing level failures only: the channel may answer those because the message
 * never reached the protocol layer, so no component could report them. anything
 * about content is answered by the dispatcher.
 */
static int ch_uds_reply_error(struct uds_client *client, const char *text)
{
    char buf[UDS_MSG_MAXLEN];
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

    // drop the record first so no new task can be routed to this client while
    // the fd is being torn down, then take the lock: any send already in flight
    // holds it and finishes before we close
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
    lnode_init(&client->ch.comp.name_node);
    lnode_init(&client->ch.comp.id_node);

    dprint("[%s] client released\n", client->name);
    return ;
}

/* epoll hook, see struct dchannel. called after the read path already had its
 * chance, so the release has to be idempotent */
static void ch_uds_client_hangup(struct dchannel *ch)
{
    ch_uds_client_release(container_of(ch, struct uds_client, ch));
}

static void ch_uds_forward(struct uds_client *client, const char *data,
    unsigned int len)
{
    if (unlikely(dispatcher_id == DCOMPID_RESERVED))
    {
        derror("uds client[%s] request dropped, no dispatcher\n", client->name);
        ch_uds_reply_error(client, "dispatcher unavailable");
        return ;
    }

    if (unlikely(task_enqueue_by_id(client->ch.comp.dcompid, dispatcher_id,
        MSGID_INPUT_JSON, len, data) != Success))
    {
        derror("uds client[%s] request of %u bytes dropped, queue is full\n",
            client->name, len);
        ch_uds_reply_error(client, "dispatcher busy");
    }

    return ;
}

static int ch_uds_client_read_from_out(struct dchannel *ch)
{
    struct uds_client *client = container_of(ch, struct uds_client, ch);
    char buf[UDS_MSG_MAXLEN];
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
            derror("uds client[%s] recv failed, errno: %d\n", client->name, errno);
            ch_uds_client_release(client);
            return Fail;
        }
        if (len == 0)
        {
            dprint("uds client[%s] closed by peer\n", client->name);
            ch_uds_client_release(client);
            return Success;
        }

        handled++;

        if (unlikely((size_t)len > sizeof(buf)))
        {
            derror("uds client[%s] request too large: %zd > %zu\n",
                client->name, len, sizeof(buf));
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
    struct ucred cred;
    socklen_t credlen = sizeof(cred);
    int ret = Success;

    // every connection gets a fresh id, ids are never recycled
    dcomp_init(&client->ch.comp, client->name);
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
        derror("uds client[%s] register failed\n", client->name);
        ch_uds_client_release(client);
        return Fail;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) == 0)
    {
        dprint("[%s] connected, fd[%d], id[%u], peer pid[%d], uid[%u]\n",
            client->name, fd, client->ch.comp.dcompid,
            (int)cred.pid, (unsigned int)cred.uid);
    }
    else
    {
        dprint("[%s] connected, fd[%d], id[%u], peer unknown\n",
            client->name, fd, client->ch.comp.dcompid);
    }

    return Success;
}

static struct uds_client *ch_uds_client_alloc(void)
{
    for (unsigned int i = 0; i < CLIENT_MAXNUM; i++)
    {
        if (!clients[i].used)
        {
            clients[i].used = true;
            return &clients[i];
        }
    }

    return NULL;
}

static int ch_uds_server_read_from_out(struct dchannel *ch)
{
    struct uds_client *client = NULL;
    unsigned int accepted = 0;
    int fd = -1;

    while (accepted < UDS_ACCEPT_BATCH)
    {
        fd = accept(ch->fd, NULL, NULL);
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

        if (unlikely(set_nonblock_cloexec(fd) != Success))
        {
            derror("uds client fd setup failed, errno: %d\n", errno);
            close(fd);
            continue;
        }

        client = ch_uds_client_alloc();
        if (unlikely(client == NULL))
        {
            derror("no free uds client slot, connection rejected\n");
            close(fd);
            // do not break, the accept queue still has to be drained
            continue;
        }

        if (unlikely(ch_uds_client_setup(client, fd) != Success))
        {
            continue;
        }
    }

    return Success;
}

static int ch_uds_init(void)
{
    struct sockaddr_un addr;
    socklen_t addrlen = 0;
    const struct dcomp *disp = NULL;
    int ret = Success;
    int pathlen = 0;
    int fd = -1;

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
        snprintf(client_names[i], sizeof(client_names[i]), "%s%u",
            ChannelUnixDomainSocketClient, i);
        clients[i].name = client_names[i];
    }

    // without the dispatcher every received message would be dropped, so a
    // missing dispatcher is a channel failure, not a half working channel
    disp = find_dcomp_by_name(ModuleDispatcher);
    if (unlikely(disp == NULL))
    {
        derror("[%s] needs [%s], which is not registered\n",
            ChannelUnixDomainSocket, ModuleDispatcher);
        return Fail;
    }
    dispatcher_id = disp->dcompid;

    dcomp_init(&ch_uds_server.comp, ChannelUnixDomainSocket);
    dcomp_set_handlers(&ch_uds_server.comp, 0, NULL);
    ch_uds_server.read_from_out = ch_uds_server_read_from_out;

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (unlikely(fd < 0))
    {
        derror("uds socket create failed, errno: %d\n", errno);
        return Fail;
    }
    ch_uds_server.fd = fd;

    addr.sun_family = AF_UNIX;
    pathlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    if (unlikely(pathlen < 0 || (size_t)pathlen >= sizeof(addr.sun_path)))
    {
        derror("uds path[%s] is too long\n", UDS_PATH);
        ret = Fail;
        goto fail;
    }
    // a stale socket file left by a crashed instance would fail bind()
    unlink(UDS_PATH);

    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + (size_t)pathlen + 1U);
    if (unlikely(bind(fd, (struct sockaddr *)&addr, addrlen) < 0))
    {
        derror("uds bind[%s] failed, errno: %d\n", UDS_PATH, errno);
        ret = Fail;
        goto fail;
    }

    if (unlikely(listen(fd, LISTENED_CLIENT_NUM) < 0))
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

    dprint("[%s] info: fd[%d], id[%u], path[%s], dispatcher[%u]\n",
        ch_uds_server.comp.name, ch_uds_server.fd, ch_uds_server.comp.dcompid,
        UDS_PATH, dispatcher_id);

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
    dispatcher_id = DCOMPID_RESERVED;

    dprint("[%s] exit\n", ch_uds_server.comp.name);
    return ;
}

// lowest priority: the control channel is a debug/management helper, the daemon
// keeps working without it
DCOMP_INIT_LOWPRIO(ch_uds_init);
DCOMP_EXIT_LOWPRIO(ch_uds_exit);
