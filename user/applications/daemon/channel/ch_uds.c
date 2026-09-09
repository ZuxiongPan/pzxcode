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
#include "core/dchannel.h"
#include "channel/chnl_api.h"

typedef struct uds_mgr {
    dchannel_t server;
    dchannel_t clients[CLIENT_MAXNUM];
    atomic_int client_idx;
} uds_mgr_t;

static uds_mgr_t g_uds_mgr;

static int uds_client_chnl_callback(dchannel_t *chnl)
{
    char buf[TASK_DATA_MAXSIZE];
    memset(buf, 0, sizeof(buf));
    ssize_t len = 0;

    len = recv(chnl->fd, buf, sizeof(buf), 0);
    if (len == 0)
    {
        dprint("uds client closed by peer\n");
        close(chnl->fd);
        chnl->fd = -1;
        dchannel_unregister(chnl);
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
            derror("receive uds message failed, err: %d\n", errno);
        }
        
        return Fail;
    }

    // the message from uds is a control message, we do not know where to put it
    return task_enqueue(DataRawString, chnl->dcomp.dcompid,
        DCOMPID_NONE, 0, len, buf);
}

static int uds_client_chnl_write_to_outer(void *arg)
{
    dtask_t *task = (dtask_t *)arg;
    if (NULL == task || task->data_size == 0)
    {
        derror("there is no data to write\n");
        return Fail;
    }

    int idx = 0;
    while (idx < CLIENT_MAXNUM)
    {
        if (g_uds_mgr.clients[idx].dcomp.dcompid == task->dst_compid)
        {
            break;
        }
        idx++;
    }

    return send(g_uds_mgr.clients[idx].fd, task->data, task->data_size, 0);
}

const channel_ops_t uds_client_chnl_ops = {
    .read_from_outer = uds_client_chnl_callback,
    .write_to_outer = uds_client_chnl_write_to_outer,
};

static int uds_server_chnl_callback(dchannel_t *chnl)
{
    int client_fd = -1;
    int idx = 0;
    int compid = DCOMPID_NONE;

    while (idx < CLIENT_MAXNUM && g_uds_mgr.clients[idx].fd >= 0)
    {
        idx++;
    }

    if (idx < CLIENT_MAXNUM)
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

        compid = atomic_load(&g_uds_mgr.client_idx);
        dcomponent_init(&g_uds_mgr.clients[idx].dcomp, compid, "uds_client");
        g_uds_mgr.clients[idx].fd = client_fd;
        g_uds_mgr.clients[idx].ops = &uds_client_chnl_ops;
        if (dchannel_register(EPOLLIN, &g_uds_mgr.clients[idx]) != Success)
        {
            derror("uds channel register failed\n");
            close(client_fd);
            g_uds_mgr.clients[idx].fd = -1;
            return Fail;
        }
        atomic_fetch_add(&g_uds_mgr.client_idx, 1);
        dprint("uds client fd = %d, compid = 0x%x\n", client_fd, compid);
    }
    else
    {
        dprint("there is no available client slot\n");
    }

    return Success;
}

const channel_ops_t uds_server_chnl_ops = {
    .read_from_outer = uds_server_chnl_callback,
    .write_to_outer = NULL,
};

int ch_uds_init(void)
{
    int ret = Success;
    struct sockaddr_un addr;

    memset(&g_uds_mgr, 0, sizeof(uds_mgr_t));
    memset(&addr, 0, sizeof(addr));
    atomic_init(&g_uds_mgr.client_idx, UDSCLIENT_IDSTART);
    for (int i = 0; i < CLIENT_MAXNUM; i++)
    {
        g_uds_mgr.clients[i].fd = -1;
    }
    dcomponent_init(&g_uds_mgr.server.dcomp, ChannelIDUdsServer, "uds_server");
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

    if (listen(g_uds_mgr.server.fd, LISTENED_CLIENT_NUM) < 0)
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
    for (int i = 0; i < CLIENT_MAXNUM; i++)
    {
        if (g_uds_mgr.clients[i].fd >= 0)
        {
            dchannel_unregister(&g_uds_mgr.clients[i]);
            close(g_uds_mgr.clients[i].fd);
            g_uds_mgr.clients[i].fd = -1;
        }
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
