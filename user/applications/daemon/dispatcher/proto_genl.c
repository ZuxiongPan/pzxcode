/*
 * generic netlink wire format, MSGID_INPUT_GENL
 *
 *     struct nlmsghdr
 *     struct genlmsghdr
 *     nlattr DIN_GENL_ATTR_TARGET   string, destination component, required
 *     nlattr DIN_GENL_ATTR_DATA     binary payload, optional
 *     nlattr DIN_GENL_ATTR_MSGID    u32, msgid for the destination, optional
 *
 * the kernel side sends binary, so nothing here treats the payload as text: it
 * is forwarded as is, payload_len is the exact attribute length and the bytes
 * may contain NUL. unknown attributes are skipped, which keeps the format
 * forward compatible with a newer kernel module talking to an older daemon.
 *
 * the destination msgid defaults to MSGID_EVENT_GENL(genlmsghdr.cmd). that is
 * the event kind the kernel encoded, and it is *not* used as a raw msgid: cmd
 * values start at 1 and would collide with the internal MSGID_SYS_* range, so
 * they are shifted into their own range. a sender that needs a specific msgid
 * (a control request rather than an event) sets DIN_GENL_ATTR_MSGID.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dispatcher/dinput.h"

#define DIN_GENL_HDRLEN (NLMSG_HDRLEN + GENL_HDRLEN)

int din_parse_genl(const char *data, unsigned int size, struct dinput *in)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)data;
    const struct genlmsghdr *ghdr = NULL;
    const struct nlattr *nla = NULL;
    const char *target = NULL;
    unsigned int target_len = 0;
    const char *payload = "";
    unsigned int payload_len = 0;
    unsigned int msgid = 0;
    int rem = 0;

    if (unlikely(size < DIN_GENL_HDRLEN))
    {
        snprintf(in->reason, sizeof(in->reason), "genl message shorter than header");
        return Fail;
    }

    // nlmsg_len is the length of this message only, a buffer may hold more than
    // one, so the parser stays inside nlmsg_len and ignores the rest
    if (unlikely(nlh->nlmsg_len < DIN_GENL_HDRLEN || nlh->nlmsg_len > size))
    {
        snprintf(in->reason, sizeof(in->reason), "bad nlmsg_len %u, buffer %u",
            nlh->nlmsg_len, size);
        return Fail;
    }

    ghdr = (const struct genlmsghdr *)NLMSG_DATA(nlh);
    // the daemon never answers the kernel, so every message that arrives here is
    // an event and cmd tells which one. DIN_GENL_ATTR_MSGID can override it.
    msgid = MSGID_EVENT_GENL(ghdr->cmd);

    nla = (const struct nlattr *)((const char *)ghdr + GENL_HDRLEN);
    rem = (int)(nlh->nlmsg_len - DIN_GENL_HDRLEN);

    while (rem >= (int)NLA_HDRLEN)
    {
        unsigned int type = 0;
        unsigned int alen = 0;
        const char *val = NULL;
        int step = 0;

        if (unlikely(nla->nla_len < NLA_HDRLEN || (int)nla->nla_len > rem))
        {
            snprintf(in->reason, sizeof(in->reason),
                "malformed attribute, nla_len %u of %d left", nla->nla_len, rem);
            return Fail;
        }

        type = nla->nla_type & NLA_TYPE_MASK;
        alen = nla->nla_len - NLA_HDRLEN;
        val = (const char *)nla + NLA_HDRLEN;

        switch (type)
        {
            case DIN_GENL_ATTR_TARGET:
                target = val;
                target_len = alen;
                break;
            case DIN_GENL_ATTR_DATA:
                payload = val;
                payload_len = alen;
                break;
            case DIN_GENL_ATTR_MSGID:
                if (unlikely(alen != sizeof(uint32_t)))
                {
                    snprintf(in->reason, sizeof(in->reason),
                        "msgid attribute is %u bytes, expected %u",
                        alen, (unsigned int)sizeof(uint32_t));
                    return Fail;
                }
                memcpy(&msgid, val, sizeof(msgid));
                break;
            default:
                // not ours, a newer sender may add attributes
                break;
        }

        step = (int)NLA_ALIGN(nla->nla_len);
        rem -= step;
        nla = (const struct nlattr *)((const char *)nla + step);
    }

    if (unlikely(target == NULL || target_len == 0))
    {
        snprintf(in->reason, sizeof(in->reason), "genl attribute [target] is missing");
        return Fail;
    }
    // a netlink string attribute carries its own terminator, a truncated one
    // would make the name lookup read past the attribute
    if (unlikely(target_len > DIN_TARGET_MAXLEN ||
        memchr(target, '\0', target_len) == NULL))
    {
        snprintf(in->reason, sizeof(in->reason),
            "genl attribute [target] is not a terminated string of %u bytes",
            target_len);
        return Fail;
    }

    in->target = target;
    in->msgid = msgid;
    in->payload = payload;
    in->payload_len = payload_len;

    // nothing is allocated, the bytes stay in the task slot of the caller
    in->priv = NULL;
    in->release = NULL;

    return Success;
}
