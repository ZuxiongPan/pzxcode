#include <command.h>
#include <vsprintf.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <blk.h>
#include <env.h>

#ifdef CONFIG_USB_STORAGE
#include <usb.h>
#endif

#include "pzxboot.h"
#include "common/version_header.h"
#include "common/version_partition.h"

#define CURRENT_IPADDR "10.0.2.15"
#define SERVER_IPADDR "10.0.2.2"

static int download_upgrade_file(const char *upgrade_filename)
{
    static char ipset = 0;
    int ret = -EBADR;
    char buf[PZXBOOTSTRS_MAXLEN] = {0};

    if(!ipset)
    {
        snprintf(buf, sizeof(buf), "setenv ipaddr %s", CURRENT_IPADDR);
        ret = run_command(buf, 0);
        snprintf(buf, sizeof(buf), "setenv serverip %s", SERVER_IPADDR);
        ret |= run_command(buf, 0);

        if(ret)
        {
            pzxboot_error("set ip address failed\n");
            return ret;
        }

        ipset = 1;
    }

#ifdef CONFIG_CMD_TFTPBOOT
    snprintf(buf, sizeof(buf), "tftp 0x%x %s", CONFIG_SYS_LOAD_ADDR, upgrade_filename);
    ret = run_command(buf, 0);
#endif

    return ret;
}   

static int write_upgrade_to_storage(unsigned int filesize)
{
    int ret = 0;
#ifdef CONFIG_USB_STORAGE
    struct blk_desc *stor_desc = NULL;

    ret = blk_get_desc(UCLASS_USB, 0, &stor_desc);
    if(ret || (NULL == stor_desc))
    {
        pzxboot_error("get usb storage device %d failed\n", 0);
        return -EBADFD;
    }

    ulong write_blks = filesize / stor_desc->blksz, count = 0;
    lbaint_t start_blk = VERSION0_PARTITION_OFFSET / stor_desc->blksz;
    count = blk_dwrite(stor_desc, start_blk, write_blks, (void *)CONFIG_SYS_LOAD_ADDR);
    if(count != write_blks)
    {
        pzxboot_error("write upgrade file from offset 0x%08x in [%s]-[%s] device failed\n",
            VERSION1_PARTITION_OFFSET,  strlen(stor_desc->vendor) ? stor_desc->vendor : "none",
            strlen(stor_desc->product) ? stor_desc->product : "none");
        return -EIO;
    }
#endif

    pzxboot_info("write upgrade file success\n");
    return 0;
}

static int do_upgrade(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
    int ret = download_upgrade_file("upgrade.bin");
    unsigned long filesize = 0;
    char *filesize_str = NULL;
    if(ret)
    {
        pzxboot_error("tftp download upgrade file failed, ret %d\n", ret);
        return ret;
    }

    ret = pzx_rsa_check((void *)CONFIG_SYS_LOAD_ADDR, (void *)(CONFIG_SYS_LOAD_ADDR + VERSION_HEADER_OFFSET));
    if(ret != 1)
    {
        pzxboot_error("rsa sign check for upgrade file failed\n");
        return ret;
    }

    filesize_str = env_get("filesize");
    if(NULL == filesize_str)
    {
        pzxboot_error("get upgrade file size failed\n");
        return -ENOMSG;
    }

    filesize = hextoul(filesize_str, NULL);
    if(filesize % STORDEV_PHYSICAL_BLKSIZE || filesize > VERSION_PARTITION_SIZE)
    {
        pzxboot_error("file size %s is invalid\n", filesize_str);
        return -EINVAL;
    }

    pzxboot_info("upgrade file size is 0x%lx\n", filesize);

    ret = write_upgrade_to_storage(filesize);
    if(ret)
    {
        pzxboot_error("write upgrade file to storage device failed\n");
        return ret;
    }

    pzxboot_info("upgrade success\n");

    return 0;
}

U_BOOT_CMD(
    upgrade, 1, 0, do_upgrade,
    "upgrade file by tftp protocol, filename must be upgrade.bin",
    "upgrade"
);