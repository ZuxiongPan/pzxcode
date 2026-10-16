#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dworker.h"
#include "core/dmodule.h"
#include "core/dchannel.h"
#include "core/dfuncalls.h"
#include "common/uk_netlink.h"

typedef enum genl_status {
    GenlStatusInvalid = 0,
    GenlStatusInit,
    GenlStatusRegister,
} genl_status_e;

typedef struct genl_info {
    uint16_t family_id;
    uint32_t group_id;
    genl_status_e status;
} genl_info_t;

#define PZX_NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define PZX_NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))
#define PZX_NLA_PAYLOAD(nla) ((int)((nla)->nla_len - NLA_HDRLEN))
#define PZX_NLA_OK(nla, rem) \
    ((rem) >= (int)sizeof(struct nlattr) && \
    (nla)->nla_len >= sizeof(struct nlattr) && \
    (nla)->nla_len <= (rem))
#define PZX_NLA_NEXT(nla, rem) \
    ((rem) -= PZX_NLA_ALIGN((nla)->nla_len), \
    (struct nlattr *)((char *)(nla) + PZX_NLA_ALIGN((nla)->nla_len)))

static dchannel_t genl_chnl;

static int genl_chnl_callback(dchannel_t *chnl)
{
    char buf[TASK_DATA_MAXSIZE];
    memset(buf, 0, sizeof(buf));
    struct sockaddr_nl peer;
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {
        .msg_name = (struct sockaddr *)&peer,
        .msg_namelen = sizeof(peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    ssize_t len = 0;

    len = recvmsg(chnl->fd, &msg, 0);
    if (len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            derror("genl message is empty\n");
        }
        else
        {
            derror("receive genl message failed, err: %d\n", errno);
        }
        
        return Fail;
    }

    // here priv must be valid because channel initialization checked
    genl_info_t *genl_info = (genl_info_t *)chnl->priv;
    switch (genl_info->status)
    {
        case GenlStatusInit:
            break;
        case GenlStatusRegister:
            break;
        default:
            break;
    }

    return task_enqueue(DataBinaryToModule, chnl->dcomp.dcompid,
        ModuleIDUevent, 0, len, buf);
}

const channel_ops_t genl_chnl_ops = {
    .read_from_outer = genl_chnl_callback,
    .write_to_outer = NULL,
};

static int genl_send_ctrl_req(int fd)
{
    char buf[512] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *ghdr;
    struct nlattr *nla;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    size_t attr_size = PZX_NLA_ALIGN(NLA_HDRLEN + sizeof(PZX_KEVENT_GENL_FAMILY));
    size_t total = NLMSG_HDRLEN + GENL_HDRLEN + attr_size;

    if (total > sizeof(buf))
    {
        derror("total = %lu, sizeof(buf) = %lu\n", total, sizeof(buf));
        return Fail;
    }

    nlh->nlmsg_len = (uint32_t)total;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;

    ghdr = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
    ghdr->cmd = CTRL_CMD_GETFAMILY;
    ghdr->version = PZX_KEVENT_GENL_VERSION;
    ghdr->reserved = 0;

    nla = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(PZX_KEVENT_GENL_FAMILY));
    memcpy(PZX_NLA_DATA(nla), PZX_KEVENT_GENL_FAMILY, sizeof(PZX_KEVENT_GENL_FAMILY));

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = total,
    };

    struct msghdr msg = {
        .msg_name = (struct sockaddr *)&kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t len = sendmsg(fd, &msg, 0);
    if (len < 0)
    {
        derror("sendmsg failed, err: %d\n", errno);
        return Fail;
    }

    return Success;
}

int ch_genl_init(void)
{
    genl_info_t *genl_info = genl_chnl.priv;
    int ret = Success;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
    };

    memset(&genl_chnl, 0, sizeof(dchannel_t));
    dcomponent_init(&genl_chnl.dcomp, ChannelIDGenNetlink, "ch_genl");
    genl_chnl.ops = &genl_chnl_ops;
    genl_chnl.priv = calloc(1, sizeof(genl_info_t));
    if (genl_chnl.priv == NULL)
    {
        derror("genl channel priv malloc failed\n");
        return Fail;
    }
    genl_chnl.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_GENERIC);
    if (genl_chnl.fd < 0)
    {
        derror("genl socket create failed\n");
        free(genl_chnl.priv);
        return Fail;
    }

    if (bind(genl_chnl.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("genl channel socket bind failed\n");
        close(genl_chnl.fd);
        free(genl_chnl.priv);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &genl_chnl);
    if (ret != Success)
    {
        derror("genl channel register failed\n");
        close(genl_chnl.fd);
        free(genl_chnl.priv);
        return Fail;
    }

    ret = genl_send_ctrl_req(genl_chnl.fd);
    if (ret != Success)
    {
        derror("genl send ctrl req failed\n");
        close(genl_chnl.fd);
        free(genl_chnl.priv);
        return Fail;
    }
    genl_info->status = GenlStatusInit;

    dprint("genl channel fd = %d\n", genl_chnl.fd);
    return Success;
}

void ch_genl_exit(void)
{
    dchannel_unregister(&genl_chnl);
    if (genl_chnl.fd >= 0)
    {
        close(genl_chnl.fd);
    }
    genl_chnl.fd = -1;
    if (genl_chnl.priv != NULL)
    {
        free(genl_chnl.priv);
        genl_chnl.priv = NULL;
    }
    dprint("genl channel exit\n");
}

DCOMP_INIT_HIGHPRIO(ch_genl_init);
DCOMP_EXIT_HIGHPRIO(ch_genl_exit);
