#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dproto.h"
#include "core/dchannel.h"

static dchannel_t g_uds_channel;

static int uds_chnl_callback(dchannel_t *chnl)
{
    (void)chnl;

    return Success;
}

const channel_ops_t uds_chnl_ops = {
    .callback = uds_chnl_callback,
};

int ch_uds_init(void)
{
    int ret = Success;
    struct sockaddr_un addr;

    memset(&g_uds_channel, 0, sizeof(dchannel_t));
    memset(&addr, 0, sizeof(addr));
    dcomponent_init(&g_uds_channel.dcomp, ChannelIDUds, "ch_uds");
    g_uds_channel.ops = &uds_chnl_ops;
    g_uds_channel.fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_uds_channel.fd < 0)
    {
        derror("uds socket create failed\n");
        return Fail;
    }

    unlink(UDS_PATH);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    if (bind(g_uds_channel.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("uds bind failed\n");
        close(g_uds_channel.fd);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &g_uds_channel);
    if (ret != Success)
    {
        derror("uds channel register failed\n");
        close(g_uds_channel.fd);
        return Fail;
    }

    dprint("uds channel fd = %d\n", g_uds_channel.fd);
    return Success;
}

void ch_uds_exit(void)
{
    dchannel_unregister(&g_uds_channel);
    if (g_uds_channel.fd >= 0)
    {
        close(g_uds_channel.fd);
    }
    g_uds_channel.fd = -1;
}
