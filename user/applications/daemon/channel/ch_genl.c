#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

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
#include "module/dmsgid.h"
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

#define PZX_NLA_ALIGN(len) \
    (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))

#define PZX_NLA_DATA(nla) \
    ((void *)((char *)(nla) + NLA_HDRLEN))

#define PZX_NLA_PAYLOAD(nla) \
    ((int)((nla)->nla_len - NLA_HDRLEN))

#define PZX_NLA_OK(nla, rem) \
    ((rem) >= NLA_HDRLEN && \
     (nla)->nla_len >= NLA_HDRLEN && \
     (nla)->nla_len <= (rem))

#define PZX_NLA_NEXT(nla, rem) \
    ((rem) -= PZX_NLA_ALIGN((nla)->nla_len), \
     (struct nlattr *)((char *)(nla) + \
                       PZX_NLA_ALIGN((nla)->nla_len)))

#define PZX_NLA_TYPE(nla) ((nla)->nla_type & NLA_TYPE_MASK)

static dchannel_t genl_chnl;

static int genl_parse_attrs(const void *attrs, int len,
    struct nlattr **tb, size_t tb_size)
{
    const struct nlattr *nla = attrs;
    int rem = len;

    memset(tb, 0, tb_size * sizeof(tb[0]));
    while (rem > 0)
    {
        int type;
        int step;

        if (!PZX_NLA_OK(nla, rem))
            return Fail;

        type = PZX_NLA_TYPE(nla);
        if ((size_t)type < tb_size)
            tb[type] = (struct nlattr *)nla;

        step = PZX_NLA_ALIGN(nla->nla_len);
        if (step > rem)
        {
            if (nla->nla_len != rem)
                return Fail;

            rem = 0;
            break;
        }

        rem -= step;
        nla = (const struct nlattr *)((const char *)nla + step);
    }

    return rem == 0 ? Success : Fail;
}

int genl_parse_attrs_armd(const void *attrs, int len, struct nlattr **tb)
{
    return genl_parse_attrs(attrs, len, tb, NLATTR_MAX + 1);
}

static int genl_find_group(const struct nlattr *groups,
    const char *wanted_name, uint32_t *group_id)
{
    const struct nlattr *entry;
    int rem;

    if (groups == NULL || wanted_name == NULL || group_id == NULL)
        return Fail;

    entry = PZX_NLA_DATA(groups);
    rem = PZX_NLA_PAYLOAD(groups);

    while (rem > 0)
    {
        struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];
        const struct nlattr *group;
        int payload;

        if (!PZX_NLA_OK(entry, rem))
            return Fail;

        if (genl_parse_attrs(PZX_NLA_DATA(entry), PZX_NLA_PAYLOAD(entry),
                tb, CTRL_ATTR_MCAST_GRP_MAX + 1) == Success)
        {
            group = tb[CTRL_ATTR_MCAST_GRP_NAME];

            if (group != NULL && PZX_NLA_PAYLOAD(group) > 0 &&
                memchr(PZX_NLA_DATA(group), '\0', PZX_NLA_PAYLOAD(group)) != NULL &&
                !strcmp(PZX_NLA_DATA(group), wanted_name))
            {
                const struct nlattr *id = tb[CTRL_ATTR_MCAST_GRP_ID];

                if (id == NULL || PZX_NLA_PAYLOAD(id) != sizeof(uint32_t))
                    return Fail;

                memcpy(group_id, PZX_NLA_DATA(id), sizeof(*group_id));
                return *group_id != 0 ? Success : Fail;
            }
        }

        payload = PZX_NLA_ALIGN(entry->nla_len);
        if (payload > rem)
        {
            if (entry->nla_len != rem)
                return Fail;
            rem = 0;
            break;
        }

        rem -= payload;
        entry = (const struct nlattr *)((const char *)entry + payload);
    }

    return Fail;
}

static int genl_parse_ctrl_msg(const struct nlmsghdr *nlh,
                               genl_info_t *info)
{
    const struct genlmsghdr *ghdr;
    const struct nlattr *attrs;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    int attr_len;
    uint16_t family_id;
    uint32_t group_id;
    int ret;

    if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
        return Fail;

    ghdr = (const struct genlmsghdr *)((const char *)nlh + NLMSG_HDRLEN);
    attrs = (const struct nlattr *)((const char *)ghdr + GENL_HDRLEN);
    attr_len = (int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

    if (ghdr->cmd != CTRL_CMD_NEWFAMILY && ghdr->cmd != CTRL_CMD_GETFAMILY)
        return Fail;

    ret = genl_parse_attrs(attrs, attr_len, tb, CTRL_ATTR_MAX + 1);
    if (ret != Success)
    {
        derror("invalid generic netlink control attributes\n");
        return Fail;
    }

    if (tb[CTRL_ATTR_FAMILY_ID] == NULL ||
        PZX_NLA_PAYLOAD(tb[CTRL_ATTR_FAMILY_ID]) != sizeof(uint16_t))
    {
        derror("family ID missing in control response\n");
        return Fail;
    }

    memcpy(&family_id, PZX_NLA_DATA(tb[CTRL_ATTR_FAMILY_ID]), sizeof(family_id));

    if (family_id < GENL_MIN_ID)
    {
        derror("invalid family ID: %u\n", family_id);
        return Fail;
    }

    ret = genl_find_group(tb[CTRL_ATTR_MCAST_GROUPS],
        PZX_KEVENT_GENL_GROUP, &group_id);
    if (ret != Success)
    {
        derror("multicast group not found: %s\n", PZX_KEVENT_GENL_GROUP);
        return Fail;
    }

    ret = setsockopt(genl_chnl.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
        &group_id, sizeof(group_id));
    if (ret < 0)
    {
        derror("NETLINK_ADD_MEMBERSHIP failed: %d\n", errno);
        return Fail;
    }

    info->family_id = family_id;
    info->group_id = group_id;
    info->status = GenlStatusRegister;

    dprint("generic netlink registered: family=%u group=%u\n", info->family_id, info->group_id);
    return Success;
}

static int genl_parse_kmsg(const void *buf, ssize_t len,
                           genl_info_t *info)
{
    const struct nlmsghdr *nlh;
    int rem, ret = Success;

    if (buf == NULL || info == NULL || len < 0 || len > INT_MAX)
        return Fail;

    nlh = (const struct nlmsghdr *)buf;
    rem = (int)len;

    while (NLMSG_OK(nlh, rem))
    {
        switch (nlh->nlmsg_type)
        {
            case NLMSG_NOOP:
            case NLMSG_DONE:
                /* do nothing */
                break;
            case NLMSG_ERROR:
                if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr))
                {
                    derror("short NLMSG_ERROR message\n");
                    ret = Fail;
                }
                else
                {
                    const struct nlmsgerr *err = (const struct nlmsgerr *)
                        ((const char *)nlh + NLMSG_HDRLEN);
                    derror("NLMSG_ERROR: %d\n", err->error);
                    ret = Fail;
                }
                break;
            case GENL_ID_CTRL:
                if (info->status == GenlStatusInit)
                {
                    ret = genl_parse_ctrl_msg(nlh, info);
                }
                else
                {
                    derror("there is already a control message\n");
                    ret = Fail;
                }
                break;
            default:
                if (info->status == GenlStatusRegister &&
                    nlh->nlmsg_type == info->family_id)
                {
                    const char *attrs = ((const char *)nlh + NLMSG_HDRLEN + GENL_HDRLEN);
                    unsigned int attr_len = (unsigned int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
                    ret = task_enqueue(DataGenlAttrs, genl_chnl.dcomp.dcompid,
                        DCOMPID_NONE, MSGID_GENL_BIN, attr_len, (void *)(attrs));
                }
                else
                {
                    ddebug("unknown generic netlink message type: %u\n", nlh->nlmsg_type);
                }
                break;
        }
        nlh = NLMSG_NEXT(nlh, rem);
    }

    if (rem != 0)
    {
        ddebug("malformed generic netlink datagram: remaining=%d\n", rem);
    }
    return ret;
}

static int genl_chnl_callback(dchannel_t *chnl)
{
    char buf[TASK_DATA_MAXSIZE];
    struct sockaddr_nl peer;
    struct iovec iov;
    struct msghdr msg;
    ssize_t len;
    genl_info_t *info;

    if (chnl == NULL || chnl->priv == NULL)
        return Fail;

    info = (genl_info_t *)chnl->priv;

    memset(buf, 0, sizeof(buf));
    memset(&peer, 0, sizeof(peer));
    memset(&msg, 0, sizeof(msg));

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    len = recvmsg(chnl->fd, &msg, 0);
    if (len <= 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return Success;

        derror("receive generic netlink message failed: %d\n", errno);
        return Fail;
    }

    if (msg.msg_flags & MSG_TRUNC)
    {
        derror("generic netlink datagram truncated\n");
        return Fail;
    }

    if (peer.nl_family != AF_NETLINK || peer.nl_pid != 0)
    {
        derror("unexpected generic netlink sender: pid=%u\n", peer.nl_pid);
        return Success;
    }

    return genl_parse_kmsg(buf, len, info);
}

const channel_ops_t genl_chnl_ops = {
    .read_from_outer = genl_chnl_callback,
    .write_to_outer = NULL,
};

static int genl_send_ctrl_req(int fd)
{
    char buf[512] = {0};
    struct nlmsghdr *nlh;
    struct genlmsghdr *ghdr;
    struct nlattr *nla;
    struct sockaddr_nl kernel = {
        .nl_family = AF_NETLINK,
    };
    struct iovec iov;
    struct msghdr msg;
    size_t name_len = sizeof(PZX_KEVENT_GENL_FAMILY);
    size_t attr_size = PZX_NLA_ALIGN(NLA_HDRLEN + name_len);
    size_t total = NLMSG_HDRLEN + GENL_HDRLEN + attr_size;
    ssize_t sent;

    if (total > sizeof(buf))
        return Fail;

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = (uint32_t)total;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;

    ghdr = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
    ghdr->cmd = CTRL_CMD_GETFAMILY;
    ghdr->version = 1;
    ghdr->reserved = 0;

    nla = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = (uint16_t)(NLA_HDRLEN + name_len);
    memcpy(PZX_NLA_DATA(nla), PZX_KEVENT_GENL_FAMILY, name_len);

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buf;
    iov.iov_len = total;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &kernel;
    msg.msg_namelen = sizeof(kernel);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sent = sendmsg(fd, &msg, 0);
    if (sent < 0)
    {
        derror("send generic netlink control request failed: %d\n", errno);
        return Fail;
    }

    return Success;
}

int ch_genl_init(void)
{
    int ret;
    genl_info_t *info;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
    };

    memset(&genl_chnl, 0, sizeof(genl_chnl));
    dcomponent_init(&genl_chnl.dcomp, ChannelIDGenNetlink, "ch_genl");
    genl_chnl.ops = &genl_chnl_ops;
    info = calloc(1, sizeof(*info));
    if (info == NULL)
    {
        derror("genl channel priv allocation failed\n");
        return Fail;
    }

    info->status = GenlStatusInit;
    genl_chnl.priv = info;
    genl_chnl.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
        NETLINK_GENERIC);
    if (genl_chnl.fd < 0)
    {
        derror("create generic netlink socket failed: %d\n", errno);
        goto err_free;
    }

    if (bind(genl_chnl.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        derror("bind generic netlink socket failed: %d\n", errno);
        goto err_close;
    }

    ret = dchannel_register(EPOLLIN, &genl_chnl);
    if (ret != Success)
    {
        derror("register generic netlink channel failed\n");
        goto err_close;
    }

    ret = genl_send_ctrl_req(genl_chnl.fd);
    if (ret != Success)
    {
        derror("send generic netlink control request failed\n");
        goto err_unregister;
    }

    dprint("generic netlink channel initialized: fd=%d\n", genl_chnl.fd);
    return Success;

err_unregister:
    dchannel_unregister(&genl_chnl);
err_close:
    close(genl_chnl.fd);
    genl_chnl.fd = -1;
err_free:
    free(genl_chnl.priv);
    genl_chnl.priv = NULL;

    return Fail;
}

void ch_genl_exit(void)
{
    dchannel_unregister(&genl_chnl);

    if (genl_chnl.fd >= 0)
    {
        close(genl_chnl.fd);
        genl_chnl.fd = -1;
    }

    free(genl_chnl.priv);
    genl_chnl.priv = NULL;

    dprint("generic netlink channel exit\n");
}

DCOMP_INIT_HIGHPRIO(ch_genl_init);
DCOMP_EXIT_HIGHPRIO(ch_genl_exit);
