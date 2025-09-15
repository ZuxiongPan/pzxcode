#include <linux/printk.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

const char *softversion = NULL;
const char *builddate = NULL;
const char *curidx = NULL;
const char *backidx = NULL;
const char *backstate = NULL;

static int verinfo_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Software Version Number: %s\n", softversion ? softversion : "unknown");
    seq_printf(m, "Software Build Date: %s\n", builddate ? builddate : "unknown");
    seq_printf(m, "Current Version Index: %s\n", curidx);
    seq_printf(m, "Backup Version Index: %s\n", backidx);
    seq_printf(m, "Backup Version State: %s\n", backstate);

    return 0;
}

static int verinfo_proc_open(struct inode *nodep, struct file *filp)
{
    return single_open(filp, verinfo_proc_show, NULL);
}

static const struct proc_ops verinfo_fops = {
    .proc_flags = PROC_ENTRY_PERMANENT,
    .proc_open = verinfo_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init verinfo_init(void)
{
    int ret = 0;
    struct device_node *verinfo_np = of_find_node_by_path("/verinfo");
    if(NULL == verinfo_np)
    {
        pr_err("no verinfo node found in dtb\n");
        return -ENODEV;
    }

    ret = of_property_read_string(verinfo_np, "versionnumber", &softversion);
    if(ret)
        pr_err("read versionnumber property failed, ret %d\n", ret);
    
    ret = of_property_read_string(verinfo_np, "builddate", &builddate);
    if(ret)
        pr_err("read builddate property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "bootverindex", &curidx);
    if(ret)
        pr_err("read bootverindex property failed, ret %d\n", ret);
    
    ret = of_property_read_string(verinfo_np, "backverindex", &backidx);
    if(ret)
        pr_err("read backverindex property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "backverstate", &backstate);
    if(ret)
        pr_err("read backverstate property failed, ret %d\n", ret);

    proc_create("verinfo", 0, NULL, &verinfo_fops);

	return 0;
}
fs_initcall(verinfo_init);