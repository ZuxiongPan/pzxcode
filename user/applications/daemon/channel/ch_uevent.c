#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_info.h"
#include "core/dworker.h"
#include "core/dchannel.h"
#include "core/dfuncalls.h"
#include "dispatcher/ddispatcher.h"

#define UEVENT_RECV_BATCH 8U
#define UEVENT_RECV_BUF_SIZE LINUX_PAGE_SIZE
#define UEVENT_RCVBUF_SIZE (256 * 1024)

#define UEVENT_GROUP_KERNEL 1

static struct dchannel ch_uevent;

static int ch_uevent_read_from_out(struct dchannel *chnl)
{
    char buf[UEVENT_RECV_BUF_SIZE];
    unsigned int handled = 0;
    ssize_t len = 0;

    while (handled < UEVENT_RECV_BATCH)
    {
        handled++;
        // MSG_TRUNC reports the real length, so a record that does not fit is
        // dropped as a whole instead of being forwarded truncated
        len = recv(chnl->fd, buf, sizeof(buf), MSG_TRUNC);
        if (len < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // the queue is drained, this is the normal way out
                break;
            }
            if (errno == ENOBUFS)
            {
                // the kernel dropped records because our buffer was full, the
                // socket is still usable
                derror("[%s] receive buffer overflow, uevents were dropped\n",
                    chnl->comp.name);
                break;
            }

            derror("[%s] receive failed, errno: %d\n", chnl->comp.name, errno);
            return Fail;
        }

        if (len == 0)
        {
            // nothing to forward, keep draining
            continue;
        }

        if (unlikely((size_t)len > sizeof(buf)))
        {
            derror("[%s] uevent of %zd bytes exceeds %zu, dropped\n",
                chnl->comp.name, len, sizeof(buf));
            continue;
        }

        if (unlikely(task_enqueue_by_id(chnl->comp.dcompid, ModDispatcherId,
                MSGID_INPUT_UEVENT, (unsigned int)len, buf) != Success))
        {
            derror("[%s] task queue rejected a uevent of %zd bytes\n",
                chnl->comp.name, len);
            return Fail;
        }
    }

    return Success;
}

static void ch_uevent_hangup(struct dchannel *chnl)
{
    derror("[%s] socket hangup, dropping the channel\n", chnl->comp.name);

    dchannel_unregister(chnl);
    if (chnl->fd >= 0)
    {
        close(chnl->fd);
        chnl->fd = -1;
    }

    return ;
}

static int ch_uevent_init(void)
{
    struct sockaddr_nl addr;
    int rcvbuf = UEVENT_RCVBUF_SIZE;
    int ret = Success;

    memset(&ch_uevent, 0, sizeof(ch_uevent));
    // a channel that never got a socket must not close fd 0 on exit
    ch_uevent.fd = -1;

    dcomp_init(&ch_uevent.comp, ChUeventName, ChUeventId);
    dcomp_set_handlers(&ch_uevent.comp, 0, NULL);
    ch_uevent.read_from_out = ch_uevent_read_from_out;
    ch_uevent.on_hangup = ch_uevent_hangup;

    ch_uevent.fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_KOBJECT_UEVENT);
    if (unlikely(ch_uevent.fd < 0))
    {
        derror("[%s] socket create failed, errno: %d\n", ChUeventName, errno);
        return Fail;
    }

    if (setsockopt(ch_uevent.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
    {
        ddebug("[%s] SO_RCVBUF not applied, errno: %d\n", ChUeventName, errno);
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = UEVENT_GROUP_KERNEL;

    if (unlikely(bind(ch_uevent.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0))
    {
        derror("[%s] bind failed, errno: %d\n", ChUeventName, errno);
        goto fail;
    }

    ret = dchannel_register(EPOLLIN, &ch_uevent);
    if (unlikely(ret != Success))
    {
        derror("[%s] channel register failed\n", ChUeventName);
        goto fail;
    }

    dprint("[%s] info: fd[%d], id[%u]\n", ChUeventName,
        ch_uevent.fd, ch_uevent.comp.dcompid);

    return Success;

fail:
    if (ch_uevent.fd >= 0)
    {
        close(ch_uevent.fd);
        ch_uevent.fd = -1;
    }

    return Fail;
}

static void ch_uevent_exit(void)
{
    if (ch_uevent.fd >= 0)
    {
        dchannel_unregister(&ch_uevent);
        close(ch_uevent.fd);
        ch_uevent.fd = -1;
    }

    dprint("[%s] exit\n", ChUeventName);
    return ;
}

DCOMP_INIT_NORMPRIO(ch_uevent_init);
DCOMP_EXIT_NORMPRIO(ch_uevent_exit);
