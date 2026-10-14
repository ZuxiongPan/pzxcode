#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "common/uk_netlink.h"
#include "kernel/pzxktools.h"

#define PZX_KEVENT_GENL_VERSION 1

static const struct genl_multicast_group pzx_mcgrps[] = {
    { .name = "pzx_kevent" },
};

static struct genl_family pzx_genl_family __ro_after_init = {
    .name = "pzx_kfamily",
    .version = PZX_KEVENT_GENL_VERSION,
    .maxattr = NLATTR_MAX,
    .n_mcgrps = ARRAY_SIZE(pzx_mcgrps),
    .mcgrps = pzx_mcgrps,
    .module = THIS_MODULE,
};

int pzx_netlink_async_send(u32 cmd, const char *target, const void *data, size_t data_len)
{
    if (NULL == target)
    {
        pr_err("target is NULL\n");
        return -EINVAL;
    }

    struct sk_buff *skb = NULL;
    void *hdr = NULL;
    int ret = 0;

    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (NULL == skb)
    {
        pr_err("genlmsg_new failed\n");
        return -ENOMEM;
    }

    hdr = genlmsg_put(skb, 0, 0, &pzx_genl_family, 0, cmd);
    if (NULL == hdr)
    {
        pr_err("genlmsg_put failed\n");
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    ret = nla_put_string(skb, NLATTR_TARGET, target);
    if (ret)
    {
        pr_err("put target failed\n");
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return ret;
    }

    if (NULL != data && data_len > 0)
    {
        ret = nla_put(skb, NLATTR_DATA, data_len, data);
        if (ret)
        {
            pr_err("put data failed\n");
            genlmsg_cancel(skb, hdr);
            nlmsg_free(skb);
            return ret;
        }
    }

    genlmsg_end(skb, hdr);
    ret = genlmsg_multicast(&pzx_genl_family, skb, 0, 0, GFP_KERNEL);

    return ret;
}
EXPORT_SYMBOL(pzx_netlink_async_send);

static int __init pzx_netlink_init(void)
{
    int ret = genl_register_family(&pzx_genl_family);

    pr_info("pzx_netlink_init: ret = %d\n", ret);
    return ret;
}

subsys_initcall(pzx_netlink_init);
