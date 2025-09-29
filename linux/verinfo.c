#include <linux/printk.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

const char *softversion = NULL;
const char *curbuilddate = NULL;
const char *backbuilddate = NULL;
const char *backstate = NULL;
const char *curveroff = NULL;
const char *backveroff = NULL;

// verinfo format: [Key: Value]
// the Key is followed by a COLON and then a SPACE, last is the Value
// Key may include SPACE but Value SPACE is forbidden
static int verinfo_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Software Version Number: %s\n", softversion ? softversion : "unknown");
    seq_printf(m, "Current Build Date: %s\n", curbuilddate ? curbuilddate : "unknown");
    seq_printf(m, "Backup Build Date: %s\n", backbuilddate ? backbuilddate : "unknown");
    seq_printf(m, "Backup Version State: %s\n", backstate ? backstate : "unknown");
    seq_printf(m, "Current Version Offset: %s\n", curveroff ? curveroff : "unknown");
    seq_printf(m, "Backup Version Offset: %s\n", backveroff ? backveroff : "unknown");

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
    
    ret = of_property_read_string(verinfo_np, "curbuilddate", &curbuilddate);
    if(ret)
        pr_err("read builddate property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "backbuilddate", &backbuilddate);
    if(ret)
        pr_err("read builddate property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "backverstate", &backstate);
    if(ret)
        pr_err("read backverstate property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "bootveroff", &curveroff);
    if(ret)
        pr_err("read bootveroff property failed, ret %d\n", ret);

    ret = of_property_read_string(verinfo_np, "backveroff", &backveroff);
    if(ret)
        pr_err("read bootveroff property failed, ret %d\n", ret);

    proc_create("verinfo", 0, NULL, &verinfo_fops);

	return 0;
}
fs_initcall(verinfo_init);