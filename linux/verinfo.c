#include <linux/printk.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "common/version_info.h"

const char *softversion = NULL;
const char *curbuilddate = NULL;
const char *backbuilddate = NULL;
const char *backstate = NULL;
const char *curveroff = NULL;
const char *backveroff = NULL;
const char *curheaderver = NULL;
const char *backheaderver = NULL;

// verinfo format: [Key: Value]
// the Key is followed by a COLON and then a SPACE, last is the Value
// Key may include SPACE but Value SPACE is forbidden
static int verinfo_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%s: %s\n", PROC_VERNUM_NAME, softversion ? softversion : STATES_INVALID);
    seq_printf(m, "%s: %s\n", PROC_CURVERDATE_NAME, curbuilddate ? curbuilddate : STATES_INVALID);
    seq_printf(m, "%s: %s\n", PROC_CURVEROFF_NAME, curveroff ? curveroff : STATES_INVALID);
    seq_printf(m, "%s: %s\n", PROC_CURHEADVER_NAME, curheaderver ? curheaderver : STATES_INVALID);
    seq_printf(m, "%s: %s\n", PROC_BACKVERSTAT_NAME, backstate ? backstate : STATES_INVALID);
    seq_printf(m, "%s: %s\n", PROC_BACKVEROFF_NAME, backveroff ? backveroff : STATES_INVALID);
    if(NULL != backstate && !strncmp(backstate, STATES_VALID, sizeof(STATES_VALID)))
    {
        seq_printf(m, "%s: %s\n", PROC_BACKVERDATE_NAME, backbuilddate ? backbuilddate : STATES_INVALID);
        seq_printf(m, "%s: %s\n", PROC_BACKHEADVER_NAME, backheaderver ? backheaderver : STATES_INVALID);
    }

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
    struct device_node *verinfo_np = of_find_node_by_path("/chosen");
    if(NULL == verinfo_np)
    {
        pr_err("no verinfo node found in dtb\n");
        return -ENXIO;
    }

    ret = of_property_read_string(verinfo_np, DTB_VERNUM_NAME, &softversion);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_VERNUM_NAME, ret);
    
    ret = of_property_read_string(verinfo_np, DTB_CURVERDATE_NAME, &curbuilddate);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_CURVERDATE_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_BACKVERDATE_NAME, &backbuilddate);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_BACKVERDATE_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_BACKVERSTAT_NAME, &backstate);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_BACKVERSTAT_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_CURVEROFF_NAME, &curveroff);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_CURVEROFF_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_BACKVEROFF_NAME, &backveroff);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_BACKVEROFF_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_CURHEADVER_NAME, &curheaderver);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_CURHEADVER_NAME, ret);

    ret = of_property_read_string(verinfo_np, DTB_BACKHEADVER_NAME, &backheaderver);
    if(ret)
        pr_err("read %s property failed, ret %d\n", DTB_BACKHEADVER_NAME, ret);

    proc_create("pzxver", 0, NULL, &verinfo_fops);

	return 0;
}
fs_initcall(verinfo_init);