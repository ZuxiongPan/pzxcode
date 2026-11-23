#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "channel/chnl_api.h"
#include "dispatcher/ddispatcher.h"
#include "common/uk_netlink.h"

#define GENL_RECV_BATCH 8U
#define GENL_RECV_BUF_SIZE LINUX_PAGE_SIZE
#define GENL_TASK_DATA_MAX (LARGE_POOL_SLOT_SIZE - sizeof(struct dtask))
#define GENL_RCVBUF_SIZE (256 * 1024)

#define GENL_RETRY_MIN_MS 200U
#define GENL_RETRY_MAX_MS 5000U
#define GENL_RETRY_LOG_CNT 5U
#define GENL_CTRL_VERSION 0x2U

enum genl_state {
    GenlStateDown = 0,  /* no usable socket: closed, or the rebuild failed */
    GenlStateResolving, /* GETFAMILY request in flight, reply expected */
    GenlStateUp,        /* family resolved, multicast joined, events accepted */
    GenlStateBackoff,   /* resolve failed, a retry timer owns the next attempt */
};

struct genl_priv {
    /* guarded by lock: the epoll thread drives the receive path while the retry
     * handler runs on a worker thread */
    pthread_mutex_t lock;
    enum genl_state state;
    uint16_t family_id;
    uint32_t group_id;
    uint32_t seq;       /* seq of the request in flight, replies must match it */
    unsigned int attempts;  /* failed resolve attempts, drives the backoff */
    int retry_tid;      /* one shot retry timer, -1 when none is armed */
};

struct genl_chnl {
    struct dchannel ch;
    struct genl_priv priv;
};

static struct genl_chnl genl;

static const char *genl_state_name(enum genl_state state)
{
    switch (state)
    {
        case GenlStateDown:
            return "down";
        case GenlStateResolving:
            return "resolving";
        case GenlStateUp:
            return "up";
        case GenlStateBackoff:
            return "backoff";
        default:
            return "unknown";
    }
}

/* single transition point, keeps the log and the field in sync */
static void genl_set_state_locked(struct genl_chnl *ch, enum genl_state next)
{
    if (ch->priv.state == next)
    {
        return ;
    }

    dprint("[%s] state %s -> %s\n", ChGenericNetlinkName,
        genl_state_name(ch->priv.state), genl_state_name(next));
    ch->priv.state = next;

    return ;
}

static inline void *genl_nla_data(const struct nlattr *nla)
{
    return (void *)((char *)nla + NLA_HDRLEN);
}

static inline unsigned int genl_nla_payload(const struct nlattr *nla)
{
    return (unsigned int)nla->nla_len - NLA_HDRLEN;
}

/* an attribute that carries a NUL terminated string, without trusting it */
static bool genl_nla_is_str(const struct nlattr *nla)
{
    if (nla == NULL || nla->nla_len <= NLA_HDRLEN)
    {
        return false;
    }

    return memchr(genl_nla_data(nla), '\0', genl_nla_payload(nla)) != NULL;
}

static int genl_attr_parse(const void *attrs, unsigned int len,
    struct nlattr **tb, unsigned int tb_max)
{
    const struct nlattr *nla = attrs;
    unsigned int rem = len;

    memset(tb, 0, tb_max * sizeof(tb[0]));

    while (rem > 0)
    {
        unsigned int type = 0;
        unsigned int step = 0;

        if (rem < NLA_HDRLEN || nla->nla_len < NLA_HDRLEN || nla->nla_len > rem)
        {
            return Fail;
        }

        type = nla->nla_type & NLA_TYPE_MASK;
        if (type < tb_max)
        {
            tb[type] = (struct nlattr *)nla;
        }

        step = NLA_ALIGN(nla->nla_len);
        if (step > rem)
        {
            // the trailing attribute is allowed to come without its padding
            step = rem;
        }

        rem -= step;
        nla = (const struct nlattr *)((const char *)nla + step);
    }

    return Success;
}

static int genl_find_mcgrp(const struct nlattr *groups, const char *wanted,
    uint32_t *group_id)
{
    const struct nlattr *entry = NULL;
    unsigned int rem = 0;

    if (groups == NULL || wanted == NULL || group_id == NULL)
    {
        return Fail;
    }

    entry = genl_nla_data(groups);
    rem = genl_nla_payload(groups);

    while (rem > 0)
    {
        struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];
        unsigned int step = 0;

        if (rem < NLA_HDRLEN || entry->nla_len < NLA_HDRLEN || entry->nla_len > rem)
        {
            return Fail;
        }

        if (genl_attr_parse(genl_nla_data(entry), genl_nla_payload(entry),
                tb, ARRAY_SIZE(tb)) == Success)
        {
            const struct nlattr *name = tb[CTRL_ATTR_MCAST_GRP_NAME];
            const struct nlattr *id = tb[CTRL_ATTR_MCAST_GRP_ID];

            if (genl_nla_is_str(name) && id != NULL &&
                genl_nla_payload(id) == sizeof(*group_id) &&
                !strcmp(genl_nla_data(name), wanted))
            {
                memcpy(group_id, genl_nla_data(id), sizeof(*group_id));
                return *group_id != 0 ? Success : Fail;
            }
        }

        step = NLA_ALIGN(entry->nla_len);
        if (step > rem)
        {
            step = rem;
        }

        rem -= step;
        entry = (const struct nlattr *)((const char *)entry + step);
    }

    return Fail;
}

static unsigned int genl_retry_delay(unsigned int failures)
{
    unsigned int delay = GENL_RETRY_MIN_MS;

    for (unsigned int i = 1; i < failures && delay < GENL_RETRY_MAX_MS; i++)
    {
        delay *= 2;
    }

    return delay < GENL_RETRY_MAX_MS ? delay : GENL_RETRY_MAX_MS;
}

/* caller must hold priv.lock */
static int genl_req_send_locked(struct genl_chnl *ch)
{
    char buf[128] = { 0 };
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *ghdr = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
    struct nlattr *nla = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = buf };
    struct msghdr msg = { .msg_name = &kernel, .msg_namelen = sizeof(kernel) };
    size_t name_len = sizeof(PZX_KEVENT_GENL_FAMILY);
    size_t total = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(NLA_HDRLEN + name_len);
    ssize_t sent = 0;

    if (unlikely(ch->ch.fd < 0))
    {
        derror("[%s] no socket to send the family request on\n", ChGenericNetlinkName);
        return Fail;
    }

    if (unlikely(total > sizeof(buf)))
    {
        derror("[%s] family request does not fit the buffer\n", ChGenericNetlinkName);
        return Fail;
    }

    nlh->nlmsg_len = (uint32_t)total;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    ch->priv.seq++;
    nlh->nlmsg_seq = ch->priv.seq;
    nlh->nlmsg_pid = 0;     /* let the kernel fill in our port id */

    ghdr->cmd = CTRL_CMD_GETFAMILY;
    ghdr->version = GENL_CTRL_VERSION;
    ghdr->reserved = 0;

    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = (uint16_t)(NLA_HDRLEN + name_len);
    memcpy(genl_nla_data(nla), PZX_KEVENT_GENL_FAMILY, name_len);

    iov.iov_len = total;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sent = sendmsg(ch->ch.fd, &msg, 0);
    if (unlikely(sent < 0))
    {
        derror("[%s] send family request failed, errno: %d\n", ChGenericNetlinkName, errno);
        return Fail;
    }

    if (unlikely((size_t)sent != total))
    {
        derror("[%s] short send on family request: %zd of %zu\n",
            ChGenericNetlinkName, sent, total);
        return Fail;
    }

    return Success;
}

/* caller must hold priv.lock */
static void genl_enter_backoff_locked(struct genl_chnl *ch, int code)
{
    unsigned int delay = 0;
    int tid = -1;

    ch->priv.attempts++;

    if (ch->priv.attempts <= GENL_RETRY_LOG_CNT)
    {
        if (code != 0)
        {
            derror("[%s] link setup failed: %d, retrying\n", ChGenericNetlinkName, code);
        }
        else
        {
            derror("[%s] link setup failed, retrying\n", ChGenericNetlinkName);
        }
    }

    if (ch->priv.retry_tid >= 0)
    {
        // a retry is already armed, do not stack a second timer on top of it
        genl_set_state_locked(ch, GenlStateBackoff);
        return ;
    }

    delay = genl_retry_delay(ch->priv.attempts);
    tid = timer_add(delay, 0, false, ch->ch.comp.dcompid, MSGID_CHANNEL_GENL_RETRY);
    if (unlikely(tid < 0))
    {
        derror("[%s] no timer available for the retry, the link stays down\n",
            ChGenericNetlinkName);
        genl_set_state_locked(ch, GenlStateDown);
        return ;
    }

    ch->priv.retry_tid = tid;
    ddebug("[%s] attempt %u scheduled in %u ms\n", ChGenericNetlinkName,
        ch->priv.attempts, delay);
    genl_set_state_locked(ch, GenlStateBackoff);

    return ;
}

/* caller must hold priv.lock */
static int genl_socket_open_locked(struct genl_chnl *ch)
{
    struct sockaddr_nl addr;
    int rcvbuf = GENL_RCVBUF_SIZE;
    int fd = -1;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (unlikely(fd < 0))
    {
        derror("[%s] create generic netlink socket failed, errno: %d\n",
            ChGenericNetlinkName, errno);
        return Fail;
    }

    // multicast is not flow controlled: a bigger receive buffer absorbs a burst
    // instead of dropping datagrams with ENOBUFS, best effort only
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
    {
        ddebug("[%s] SO_RCVBUF not applied, errno: %d\n", ChGenericNetlinkName, errno);
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;        // the kernel assigns our port id
    addr.nl_groups = 0;     // membership is joined once the group id is known

    if (unlikely(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0))
    {
        derror("[%s] bind generic netlink socket failed, errno: %d\n",
            ChGenericNetlinkName, errno);
        close(fd);
        return Fail;
    }

    ch->ch.fd = fd;
    if (unlikely(dchannel_register(EPOLLIN, &ch->ch) != Success))
    {
        derror("[%s] register channel failed\n", ChGenericNetlinkName);
        close(fd);
        ch->ch.fd = -1;
        return Fail;
    }

    return Success;
}

/* caller must hold priv.lock */
static void genl_socket_close_locked(struct genl_chnl *ch)
{
    dchannel_unregister(&ch->ch);

    if (ch->ch.fd >= 0)
    {
        close(ch->ch.fd);
        ch->ch.fd = -1;
    }

    return ;
}

/* caller must hold priv.lock, the reply was already matched on seq */
static int genl_ctrl_resolve_locked(struct genl_chnl *ch, const struct nlmsghdr *nlh)
{
    const struct genlmsghdr *ghdr = NULL;
    const struct nlattr *attrs = NULL;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    unsigned int attr_len = 0;
    uint16_t family_id = 0;
    uint32_t group_id = 0;

    if (unlikely(nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN))
    {
        derror("[%s] short control reply\n", ChGenericNetlinkName);
        return Fail;
    }

    ghdr = (const struct genlmsghdr *)NLMSG_DATA(nlh);
    if (unlikely(ghdr->cmd != CTRL_CMD_NEWFAMILY))
    {
        derror("[%s] unexpected control command: %u\n", ChGenericNetlinkName, ghdr->cmd);
        return Fail;
    }

    attrs = (const struct nlattr *)((const char *)ghdr + GENL_HDRLEN);
    attr_len = (unsigned int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

    if (unlikely(genl_attr_parse(attrs, attr_len, tb, ARRAY_SIZE(tb)) != Success))
    {
        derror("[%s] malformed control attributes\n", ChGenericNetlinkName);
        return Fail;
    }

    // a family with a different name means somebody else owns this id
    if (genl_nla_is_str(tb[CTRL_ATTR_FAMILY_NAME]) &&
        strcmp(genl_nla_data(tb[CTRL_ATTR_FAMILY_NAME]), PZX_KEVENT_GENL_FAMILY))
    {
        derror("[%s] resolved [%s] instead of [%s]\n", ChGenericNetlinkName,
            (char *)genl_nla_data(tb[CTRL_ATTR_FAMILY_NAME]), PZX_KEVENT_GENL_FAMILY);
        return Fail;
    }

    if (tb[CTRL_ATTR_FAMILY_ID] == NULL ||
        genl_nla_payload(tb[CTRL_ATTR_FAMILY_ID]) != sizeof(family_id))
    {
        derror("[%s] family id missing in control reply\n", ChGenericNetlinkName);
        return Fail;
    }

    memcpy(&family_id, genl_nla_data(tb[CTRL_ATTR_FAMILY_ID]), sizeof(family_id));
    if (unlikely(family_id < GENL_MIN_ID))
    {
        derror("[%s] invalid family id: %u\n", ChGenericNetlinkName, family_id);
        return Fail;
    }

    if (unlikely(genl_find_mcgrp(tb[CTRL_ATTR_MCAST_GROUPS],
            PZX_KEVENT_GENL_GROUP, &group_id) != Success))
    {
        derror("[%s] multicast group [%s] not found\n", ChGenericNetlinkName,
            PZX_KEVENT_GENL_GROUP);
        return Fail;
    }

    if (unlikely(setsockopt(ch->ch.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
            &group_id, sizeof(group_id)) < 0))
    {
        derror("[%s] join multicast group failed, errno: %d\n",
            ChGenericNetlinkName, errno);
        return Fail;
    }

    ch->priv.family_id = family_id;
    ch->priv.group_id = group_id;
    ch->priv.attempts = 0;
    genl_set_state_locked(ch, GenlStateUp);

    dprint("[%s] link up: family[%s] id[%u] group[%u]\n", ChGenericNetlinkName,
        PZX_KEVENT_GENL_FAMILY, family_id, group_id);

    return Success;
}

/* flatten the attributes into the dispatcher envelope and queue it */
static int genl_forward(struct genl_chnl *ch, const struct nlmsghdr *nlh)
{
    const struct genlmsghdr *ghdr = NULL;
    struct nlattr *tb[NLATTR_MAX + 1];
    const struct nlattr *target_nla = NULL;
    const struct nlattr *data_nla = NULL;
    const char *target = NULL;
    const void *data = NULL;
    struct genl_upmsg *up = NULL;
    char payload[GENL_TASK_DATA_MAX];
    unsigned int attr_len = 0;
    unsigned int target_len = 0;
    unsigned int data_len = 0;
    unsigned int total = 0;

    if (unlikely(nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN))
    {
        derror("[%s] short event message\n", ChGenericNetlinkName);
        return Fail;
    }

    ghdr = (const struct genlmsghdr *)NLMSG_DATA(nlh);
    if (unlikely(ghdr->cmd != NLCMD_INFORM || ghdr->version != PZX_KEVENT_GENL_VERSION))
    {
        ddebug("[%s] unexpected genl message cmd[%u] version[%u], dropped\n",
            ChGenericNetlinkName, ghdr->cmd, ghdr->version);
        return Success;
    }

    attr_len = (unsigned int)nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
    if (unlikely(genl_attr_parse((const char *)ghdr + GENL_HDRLEN, attr_len,
            tb, ARRAY_SIZE(tb)) != Success))
    {
        derror("[%s] malformed event attributes, message dropped\n", ChGenericNetlinkName);
        return Fail;
    }

    target_nla = tb[NLATTR_TARGET];
    if (unlikely(!genl_nla_is_str(target_nla)))
    {
        // without a target the dispatcher cannot route the payload anywhere
        derror("[%s] event without a target string, message dropped\n", ChGenericNetlinkName);
        return Fail;
    }

    target = genl_nla_data(target_nla);
    target_len = (unsigned int)strlen(target);

    data_nla = tb[NLATTR_DATA];
    if (data_nla != NULL)
    {
        data = genl_nla_data(data_nla);
        data_len = genl_nla_payload(data_nla);
    }

    total = (unsigned int)sizeof(*up) + target_len + 1 + data_len;
    if (unlikely(total > sizeof(payload)))
    {
        derror("[%s] event for [%s] too large: %u bytes, dropped\n",
            ChGenericNetlinkName, target, total);
        return Fail;
    }

    up = (struct genl_upmsg *)payload;
    up->target_len = (uint16_t)target_len;
    up->data_len = (uint16_t)data_len;
    memcpy(up->body, target, target_len);
    up->body[target_len] = '\0';
    if (data_len > 0)
    {
        memcpy(up->body + target_len + 1, data, data_len);
    }

    if (unlikely(task_enqueue_by_id(ch->ch.comp.dcompid, ModDispatcherId,
            MSGID_INPUT_GENERIC_NETLINK, total, payload) != Success))
    {
        derror("[%s] task queue rejected the event for [%s]\n",
            ChGenericNetlinkName, target);
        return Fail;
    }

    return Success;
}

static int genl_handle_error(struct genl_chnl *ch, const struct nlmsghdr *nlh)
{
    const struct nlmsgerr *err = NULL;
    const char *state = NULL;
    bool ours = false;
    int code = 0;

    if (unlikely(nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr)))
    {
        derror("[%s] short NLMSG_ERROR message\n", ChGenericNetlinkName);
        return Fail;
    }

    err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
    code = err->error;

    pthread_mutex_lock(&ch->priv.lock);
    ours = (ch->priv.state == GenlStateResolving && err->msg.nlmsg_seq == ch->priv.seq);
    state = genl_state_name(ch->priv.state);
    if (ours)
    {
        genl_enter_backoff_locked(ch, code);
    }
    pthread_mutex_unlock(&ch->priv.lock);

    if (unlikely(!ours))
    {
        // never sent anything that could fail outside the resolving state
        derror("[%s] netlink error %d in state %s, ignored\n",
            ChGenericNetlinkName, code, state);
    }

    return Success;
}

static int genl_handle_ctrl(struct genl_chnl *ch, const struct nlmsghdr *nlh)
{
    const char *state = NULL;
    bool ours = false;
    int ret = Success;

    pthread_mutex_lock(&ch->priv.lock);
    ours = (ch->priv.state == GenlStateResolving && nlh->nlmsg_seq == ch->priv.seq);
    if (ours)
    {
        ret = genl_ctrl_resolve_locked(ch, nlh);
        if (unlikely(ret != Success))
        {
            genl_enter_backoff_locked(ch, 0);
        }
    }
    state = genl_state_name(ch->priv.state);
    pthread_mutex_unlock(&ch->priv.lock);

    if (unlikely(!ours))
    {
        ddebug("[%s] control reply ignored, state %s\n", ChGenericNetlinkName, state);
    }

    return ret;
}

static int genl_handle_event(struct genl_chnl *ch, const struct nlmsghdr *nlh)
{
    unsigned short family_id = 0;
    const char *state = NULL;
    bool accepted = false;

    pthread_mutex_lock(&ch->priv.lock);
    family_id = ch->priv.family_id;
    state = genl_state_name(ch->priv.state);
    accepted = (ch->priv.state == GenlStateUp && nlh->nlmsg_type == family_id);
    pthread_mutex_unlock(&ch->priv.lock);

    if (unlikely(!accepted))
    {
        // events that arrive before the membership exists, or for a family id
        // that was already rebuilt, are not ours to keep
        ddebug("[%s] message type %u dropped in state %s\n",
            ChGenericNetlinkName, nlh->nlmsg_type, state);
        return Success;
    }

    return genl_forward(ch, nlh);
}

static int genl_handle_datagram(struct genl_chnl *ch, const void *buf, unsigned int len)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
    int rem = (int)len;
    int ret = Success;

    while (NLMSG_OK(nlh, rem))
    {
        switch (nlh->nlmsg_type)
        {
            case NLMSG_NOOP:
            case NLMSG_DONE:
                break;
            case NLMSG_ERROR:
                if (unlikely(genl_handle_error(ch, nlh) != Success))
                {
                    ret = Fail;
                }
                break;
            case GENL_ID_CTRL:
                if (unlikely(genl_handle_ctrl(ch, nlh) != Success))
                {
                    ret = Fail;
                }
                break;
            default:
                if (unlikely(genl_handle_event(ch, nlh) != Success))
                {
                    ret = Fail;
                }
                break;
        }

        nlh = NLMSG_NEXT(nlh, rem);
    }

    if (unlikely(rem != 0))
    {
        ddebug("[%s] malformed datagram: %d bytes left\n", ChGenericNetlinkName, rem);
    }

    return ret;
}

static int ch_genl_read_from_out(struct dchannel *chnl)
{
    struct genl_chnl *ch = container_of(chnl, struct genl_chnl, ch);
    char buf[GENL_RECV_BUF_SIZE];
    struct sockaddr_nl peer;
    struct iovec iov;
    struct msghdr msg;
    unsigned int handled = 0;
    ssize_t len = 0;

    while (handled < GENL_RECV_BATCH)
    {
        memset(&peer, 0, sizeof(peer));
        memset(&msg, 0, sizeof(msg));

        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        msg.msg_name = &peer;
        msg.msg_namelen = sizeof(peer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // MSG_TRUNC: get the real length so an oversized datagram can be
        // dropped as a whole instead of being parsed half truncated
        len = recvmsg(chnl->fd, &msg, MSG_TRUNC);
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
            if (errno == ENOBUFS)
            {
                // the kernel dropped events because our buffer was full, the
                // socket is still usable
                derror("[%s] receive buffer overflow, events were dropped\n",
                    ChGenericNetlinkName);
                break;
            }
            derror("[%s] receive failed, errno: %d\n", ChGenericNetlinkName, errno);
            return Fail;
        }

        if (len == 0)
        {
            break;
        }

        handled++;

        if (unlikely(msg.msg_flags & MSG_TRUNC))
        {
            derror("[%s] datagram of %zd bytes exceeds %zu, dropped\n",
                ChGenericNetlinkName, len, sizeof(buf));
            continue;
        }

        if (unlikely(peer.nl_family != AF_NETLINK || peer.nl_pid != 0))
        {
            // only the kernel is supposed to talk on this family
            derror("[%s] unexpected sender pid[%u], dropped\n",
                ChGenericNetlinkName, peer.nl_pid);
            continue;
        }

        genl_handle_datagram(ch, buf, (unsigned int)len);
    }

    return Success;
}

static int ch_genl_retry_handler(const struct dcomp *self, unsigned int srcid,
    unsigned int data_size, const char *data)
{
    struct genl_chnl *ch = container_of(self, struct genl_chnl, ch.comp);
    int ret = Success;

    UNUSED(srcid);
    UNUSED(data_size);
    UNUSED(data);

    pthread_mutex_lock(&ch->priv.lock);

    // the timer id is consumed, whether this attempt is still needed or not
    ch->priv.retry_tid = -1;

    if (ch->priv.state != GenlStateBackoff)
    {
        // already resolved, or the channel is going down: stale timer
        pthread_mutex_unlock(&ch->priv.lock);
        return Success;
    }

    if (ch->ch.fd < 0 && genl_socket_open_locked(ch) != Success)
    {
        genl_enter_backoff_locked(ch, 0);
        ret = Fail;
    }
    else if (genl_req_send_locked(ch) != Success)
    {
        genl_enter_backoff_locked(ch, 0);
        ret = Fail;
    }
    else
    {
        genl_set_state_locked(ch, GenlStateResolving);
    }

    pthread_mutex_unlock(&ch->priv.lock);

    return ret;
}

static void ch_genl_hangup(struct dchannel *chnl)
{
    struct genl_chnl *ch = container_of(chnl, struct genl_chnl, ch);

    derror("[%s] socket hangup, rebuilding the link\n", ChGenericNetlinkName);

    pthread_mutex_lock(&ch->priv.lock);

    genl_socket_close_locked(ch);
    genl_set_state_locked(ch, GenlStateDown);
    ch->priv.family_id = 0;
    ch->priv.group_id = 0;
    ch->priv.seq = 0;
    ch->priv.attempts = 0;

    if (genl_socket_open_locked(ch) != Success || genl_req_send_locked(ch) != Success)
    {
        genl_enter_backoff_locked(ch, 0);
    }
    else
    {
        genl_set_state_locked(ch, GenlStateResolving);
    }

    pthread_mutex_unlock(&ch->priv.lock);

    return ;
}

static const struct msg_handler genl_handlers[] = {
    { .name = "genl-retry", .msgid = MSGID_CHANNEL_GENL_RETRY, .func = ch_genl_retry_handler },
};

static int ch_genl_init(void)
{
    int ret = Success;

    memset(&genl, 0, sizeof(genl));
    genl.ch.fd = -1;
    genl.priv.retry_tid = -1;
    genl.priv.state = GenlStateDown;
    pthread_mutex_init(&genl.priv.lock, NULL);

    dcomp_init(&genl.ch.comp, ChGenericNetlinkName, ChGenericNetlinkId);
    dcomp_set_handlers(&genl.ch.comp, ARRAY_SIZE(genl_handlers), genl_handlers);
    genl.ch.read_from_out = ch_genl_read_from_out;
    genl.ch.on_hangup = ch_genl_hangup;

    pthread_mutex_lock(&genl.priv.lock);
    if (unlikely(genl_socket_open_locked(&genl) != Success))
    {
        ret = Fail;
    }
    else if (genl_req_send_locked(&genl) != Success)
    {
        // the socket is fine, only the first request failed
        genl_enter_backoff_locked(&genl, 0);
    }
    else
    {
        genl_set_state_locked(&genl, GenlStateResolving);
    }
    pthread_mutex_unlock(&genl.priv.lock);

    if (unlikely(ret != Success))
    {
        goto err_destroy;
    }

    dprint("[%s] info: fd[%d], id[%u]\n", ChGenericNetlinkName,
        genl.ch.fd, genl.ch.comp.dcompid);

    return Success;

err_destroy:
    genl.ch.fd = -1;
    pthread_mutex_destroy(&genl.priv.lock);

    return ret;
}

static void ch_genl_exit(void)
{
    int tid = -1;

    pthread_mutex_lock(&genl.priv.lock);
    genl_set_state_locked(&genl, GenlStateDown);
    tid = genl.priv.retry_tid;
    genl.priv.retry_tid = -1;
    pthread_mutex_unlock(&genl.priv.lock);

    // a pending retry must not fire into a channel that is being removed
    if (tid >= 0)
    {
        timer_del(tid);
    }

    if (genl.ch.fd >= 0)
    {
        genl_socket_close_locked(&genl);
    }

    genl.priv.family_id = 0;
    genl.priv.group_id = 0;
    genl.priv.seq = 0;
    genl.priv.attempts = 0;

    pthread_mutex_destroy(&genl.priv.lock);

    dprint("[%s] exit\n", ChGenericNetlinkName);
    return ;
}

DCOMP_INIT_LOWPRIO(ch_genl_init);
DCOMP_EXIT_LOWPRIO(ch_genl_exit);
