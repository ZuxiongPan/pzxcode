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

static int __init pzx_netlink_init(void)
{
    int ret = genl_register_family(&pzx_genl_family);
    pr_info("pzx_netlink_init: ret = %d\n", ret);

    return ret;
}

subsys_initcall(pzx_netlink_init);
