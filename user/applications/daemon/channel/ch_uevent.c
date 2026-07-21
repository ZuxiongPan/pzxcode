#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dchannel.h"

static dchannel_t uevent_chnl;

static int uevent_chnl_callback(dchannel_t *chnl)
{
    char buf[NETCHNL_RECV_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = 0;
    dpdata_t *pdata = (dpdata_t *)buf;

    len = recv(chnl->fd, pdata->data, sizeof(buf) - sizeof(dpdata_t), 0);
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

    pdata->type = ProtoUevent;
    pdata->op = PROTO_OP_DECODE;
    pdata->data_size = len;
    dchannel_create_task(chnl, len + sizeof(dpdata_t), buf);

    return Success;
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
    dcomponent_init(&uevent_chnl.dcomp, dproto_get_name(ProtoUevent));
    uevent_chnl.ops = &uevent_chnl_ops;
    uevent_chnl.fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_KOBJECT_UEVENT);
    if (uevent_chnl.fd < 0)
    {
        derror("ch_uevent_init: uevent socket create failed\n");
        return Fail;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 1;
    if (bind(uevent_chnl.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("ch_uevent_init: uevent channel socket bind failed\n");
        close(uevent_chnl.fd);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &uevent_chnl);
    if (ret != Success)
    {
        derror("ch_uevent_init: uevent channel register failed\n");
        close(uevent_chnl.fd);
        return Fail;
    }

    dprint("ch_uevent_init: uevent channel fd = %d\n", uevent_chnl.fd);
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
    dprint("ch_uevent_exit: uevent channel fd = %d\n", uevent_chnl.fd);
}