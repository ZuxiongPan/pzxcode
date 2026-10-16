#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "common/uk_netlink.h"
#include "kernel/pzxktools.h"

#define NETLINK_TIMER_TEST 0

#if NETLINK_TIMER_TEST
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#endif

static const struct genl_multicast_group pzx_mcgrps[] = {
    { .name = PZX_KEVENT_GENL_GROUP },
};

static struct genl_family pzx_genl_family __ro_after_init = {
    .name = PZX_KEVENT_GENL_FAMILY,
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

#if NETLINK_TIMER_TEST
static struct delayed_work timer_work;
static int ticks = 0;
static const int timeout = 3000;
static bool running = false;
static struct proc_dir_entry *pzxnetlink = NULL;

static void timer_work_func(struct work_struct *work)
{
    char payload[128] = {0};
    int len = 0, ret = 0;

    ticks++;
    len = snprintf(payload, sizeof(payload), "ABCD ticks = %d wxyz", ticks);
    ret = pzx_netlink_async_send(10, "timer_test", payload, len + 1);
    if (ret && ret != -ESRCH)
        pr_err("pzx_netlink_async_send failed: ret = %d\n", ret);

    if (READ_ONCE(running))
        schedule_delayed_work(&timer_work, msecs_to_jiffies(timeout));
}

static void timer_start(void)
{
    if (READ_ONCE(running))
        return;

    WRITE_ONCE(running, true);
    schedule_delayed_work(&timer_work, msecs_to_jiffies(timeout));
    pr_info("timer_start: timeout = %d\n", timeout);
}

static void timer_stop(void)
{
    if (!READ_ONCE(running))
        return;

    WRITE_ONCE(running, false);
    cancel_delayed_work(&timer_work);
    pr_info("timer_stop: ticks = %d\n", ticks);
}

static ssize_t pzxnetlink_proc_write(struct file *file, const char __user *buf,
    size_t count, loff_t *ppos)
{
    char kbuf[16] = {0};
    int ret = 0;

    if (count == 0 || count > sizeof(kbuf))
    {
        pr_err("count = %ld, sizeof(kbuf) = %ld\n", count, sizeof(kbuf));
        return -EINVAL;
    }

    ret = copy_from_user(kbuf, buf, count);
    if (ret)
    {
        pr_err("copy_from_user failed: ret = %d\n", ret);
        return ret;
    }
    kbuf[count - 1] = '\0';

    if (!strcmp(kbuf, "start"))
        timer_start();
    else if (!strcmp(kbuf, "stop"))
        timer_stop();
    else
    {
        pr_err("kbuf = %s\n", kbuf);
        return -EINVAL;
    }

    return count;
}

static const struct proc_ops pzxnetlink_proc_ops = {
    .proc_write = pzxnetlink_proc_write,
};
#endif

static int __init pzx_netlink_init(void)
{
    int ret = genl_register_family(&pzx_genl_family);

#if NETLINK_TIMER_TEST
    INIT_DELAYED_WORK(&timer_work, timer_work_func);
    pzxnetlink = proc_create("pzx_netlink", 0222, NULL, &pzxnetlink_proc_ops);
    if (NULL == pzxnetlink)
    {
        genl_unregister_family(&pzx_genl_family);
        pr_err("proc_create failed\n");
        return -ENOMEM;
    }
#endif

    pr_info("pzx_netlink_init: ret = %d\n", ret);
    return ret;
}

subsys_initcall(pzx_netlink_init);
