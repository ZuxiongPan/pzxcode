#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dproto.h"
#include "core/dchannel.h"

static dchannel_t uevent_chnl;

static int uevent_chnl_callback(dchannel_t *chnl)
{
    char buf[NETCHNL_RECV_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = 0;

    len = recv(chnl->fd, buf, sizeof(buf), 0);
    if (len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            derror("uevent message is empty\n");
        }
        else
        {
            derror("receive uevent message failed, err: %d\n", errno);
        }
        
        return Fail;
    }

    return task_enqueue(TaskDecode, chnl->dcomp.dcomp_id,
        ProtoIDUevent, 0, len, buf);
}

const channel_ops_t uevent_chnl_ops = {
    .callback = uevent_chnl_callback,
};

int ch_uevent_init(void)
{
    int ret = Success;
    struct sockaddr_nl addr;

    memset(&addr, 0, sizeof(addr));
    memset(&uevent_chnl, 0, sizeof(dchannel_t));
    dcomponent_init(&uevent_chnl.dcomp, ChannelIDUevent, "ch_uevent");
    uevent_chnl.ops = &uevent_chnl_ops;
    uevent_chnl.fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_KOBJECT_UEVENT);
    if (uevent_chnl.fd < 0)
    {
        derror("uevent socket create failed\n");
        return Fail;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 1;
    if (bind(uevent_chnl.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("uevent channel socket bind failed\n");
        close(uevent_chnl.fd);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &uevent_chnl);
    if (ret != Success)
    {
        derror("uevent channel register failed\n");
        close(uevent_chnl.fd);
        return Fail;
    }

    dprint("uevent channel fd = %d\n", uevent_chnl.fd);
    return Success;
}

void ch_uevent_exit(void)
{
    dchannel_unregister(&uevent_chnl);
    if (uevent_chnl.fd >= 0)
    {
        close(uevent_chnl.fd);
    }
    uevent_chnl.fd = -1;
}
