#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dproto.h"
#include "core/dchannel.h"
#include "channel/chnl_api.h"

typedef struct uds_mgr {
    dchannel_t server;
    dchannel_t client;
    atomic_bool client_inuse;
} uds_mgr_t;

static uds_mgr_t g_uds_mgr;

static int uds_client_chnl_callback(dchannel_t *chnl)
{
    char buf[NETCHNL_RECV_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = 0;

    len = recv(chnl->fd, buf, sizeof(buf), 0);
    if (len == 0)
    {
        dprint("uds client closed by peer\n");
        close(chnl->fd);
        chnl->fd = -1;
        dchannel_unregister(chnl);
        atomic_store(&g_uds_mgr.client_inuse, false);
        return Fail;
    }

    if (len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            derror("uds message is empty\n");
        }
        else
        {
            close(chnl->fd);
            chnl->fd = -1;
            dchannel_unregister(chnl);
            atomic_store(&g_uds_mgr.client_inuse, false);
            derror("receive uds message failed, err: %d\n", errno);
        }
        
        return Fail;
    }

    return task_enqueue(TaskDecode, chnl->dcomp.dcomp_id,
        ProtoIDJSON, 0, len, buf);
}

const channel_ops_t uds_client_chnl_ops = {
    .callback = uds_client_chnl_callback,
};

static int uds_server_chnl_callback(dchannel_t *chnl)
{
    int client_fd = -1;

    if (!atomic_load(&g_uds_mgr.client_inuse))
    {
        client_fd = accept(chnl->fd, NULL, NULL);
        if (client_fd < 0)
        {
            derror("uds accept failed\n");
            return Fail;
        }

        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags < 0)
        {
            derror("uds fcntl failed\n");
            close(client_fd);
            return Fail;
        }
        flags |= (O_NONBLOCK | O_CLOEXEC);
        if (fcntl(client_fd, F_SETFL, flags) < 0)
        {
            derror("uds fcntl failed\n");
            close(client_fd);
            return Fail;
        }

        dcomponent_init(&g_uds_mgr.client.dcomp, ChannelIDUdsClient, "ch_uds_client");
        g_uds_mgr.client.fd = client_fd;
        g_uds_mgr.client.ops = &uds_client_chnl_ops;
        if (dchannel_register(EPOLLIN, &g_uds_mgr.client) != Success)
        {
            derror("uds channel register failed\n");
            close(client_fd);
            return Fail;
        }
        atomic_store(&g_uds_mgr.client_inuse, true);
        dprint("uds client fd = %d\n", client_fd);
    }
    else
    {
        dprint("uds client is in use, only one client allowed at same time\n");
    }

    return Success;
}

const channel_ops_t uds_server_chnl_ops = {
    .callback = uds_server_chnl_callback,
};

int ch_uds_init(void)
{
    int ret = Success;
    struct sockaddr_un addr;

    memset(&g_uds_mgr, 0, sizeof(uds_mgr_t));
    memset(&addr, 0, sizeof(addr));
    atomic_init(&g_uds_mgr.client_inuse, false);
    dcomponent_init(&g_uds_mgr.server.dcomp, ChannelIDUdsServer, "ch_uds_server");
    g_uds_mgr.server.ops = &uds_server_chnl_ops;
    g_uds_mgr.server.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_uds_mgr.server.fd < 0)
    {
        derror("uds socket create failed\n");
        return Fail;
    }

    unlink(UDS_PATH);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);
    if (bind(g_uds_mgr.server.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("uds bind failed\n");
        close(g_uds_mgr.server.fd);
        return Fail;
    }

    if (listen(g_uds_mgr.server.fd, CLIENT_MAXNUM) < 0)
    {
        derror("uds server cannot listen to client\n");
        close(g_uds_mgr.server.fd);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &g_uds_mgr.server);
    if (ret != Success)
    {
        derror("uds channel register failed\n");
        close(g_uds_mgr.server.fd);
        return Fail;
    }

    dprint("uds channel fd = %d\n", g_uds_mgr.server.fd);
    return Success;
}

void ch_uds_exit(void)
{
    if (atomic_load(&g_uds_mgr.client_inuse))
    {
        dchannel_unregister(&g_uds_mgr.client);
        close(g_uds_mgr.client.fd);
        g_uds_mgr.client.fd = -1;
        atomic_store(&g_uds_mgr.client_inuse, false);
    }
    dchannel_unregister(&g_uds_mgr.server);
    if (g_uds_mgr.server.fd >= 0)
    {
        close(g_uds_mgr.server.fd);
    }
    g_uds_mgr.server.fd = -1;
    unlink(UDS_PATH);
    dprint("uds channel exit\n");
}
