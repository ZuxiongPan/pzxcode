#include <env.h>
#include <gzip.h>
#include <stdio.h>
#include <linux/errno.h>
#include <mapmem.h>
#include <command.h>
#include <bootm.h>
#include <image.h>
#include <linux/string.h>
#include <linux/libfdt.h>
#include <u-boot/sha256.h>
#include <u-boot/rsa.h>
#include "pzxboot.h"

#ifdef CONFIG_USB_STORAGE
#include <usb.h>
#endif

static struct boot_param parameter;

static void parse_version_header(int index, void *vaddr);

int boot_parameter_init(void)
{
    int ret = 0;
    memset(&parameter, 0, sizeof(struct boot_param));
    parameter.bootidx = -1;

#ifdef CONFIG_USB_STORAGE
    int usb_storage = usb_stor_scan(1);
    if(usb_storage < 0)
    {
        pzxboot_error("no usb storage device found\n");
        return -ENODEV;
    }
    pzxboot_info("boot from usb storage device, dev number %d\n", usb_storage);
    //blk_common_cmd(argc, argv, UCLASS_USB, &usb_storage);
    ret = blk_get_desc(UCLASS_USB, usb_storage, &parameter.stor_desc);
    if(ret || (NULL == parameter.stor_desc))
    {
        pzxboot_error("get usb storage device %d failed\n", usb_storage);
        return -EBADFD;
    }
    pzxboot_info("current block size of this storage device is 0x%08lx\n", parameter.stor_desc->blksz);
#endif

    return 0;
}

int version_check(int index)
{
    unsigned int offset = index ? VERSION1_PARTITION_OFFSET : VERSION0_PARTITION_OFFSET;
    ulong read_blks = 0, count = 0;
    lbaint_t start_blk = offset / parameter.stor_desc->blksz;
    phys_addr_t loadaddr = CONFIG_SYS_LOAD_ADDR;
    void *vaddr = map_sysmem(loadaddr, VERSION_PARTITION_SIZE);

    // 1. read the whole version to memory
    read_blks = VERSION_PARTITION_SIZE / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read header from offset 0x%08x in [%s]-[%s] device failed\n", index + 1, offset, 
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none",
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return -EIO;
    }

    // 1. check rsa sign
    parameter.valid_mask |= (1 << index);

    // 2. parse headers
    parse_version_header(index, vaddr + VERSION_HEADER_OFFSET);

    unmap_sysmem(vaddr);

    return 0;
}

void set_partition_table(void)
{
    struct part_info {
        char name[32];
        unsigned int size;  // in MiB
    };
    char partstr[4096] = { 0 };

    struct part_info parts[] = {
        { "kernel0", parameter.headers[0].kpart_size / 0x100000 },
        { "rootfs0", parameter.headers[0].rpart_size / 0x100000 },
        { "kernel1", parameter.headers[1].kpart_size / 0x100000 },
        { "rootfs1", parameter.headers[1].rpart_size / 0x100000 },
    };

    snprintf(partstr, 4096,"gpt write %s %d " "name=%s,size=%uMiB\\;name=%s,size=%uMiB\\;"
        "name=%s,size=%uMiB\\;name=%s,size=%uMiB\\;name=remainder,size=0",
        "usb", 0, parts[0].name, parts[0].size, parts[1].name, parts[1].size,
        parts[2].name, parts[2].size, parts[3].name, parts[3].size);

    pzxboot_info("gpt command %s\n", partstr);
    run_command(partstr, 0);
    return ;
}

int select_boot_version(void)
{
    switch(parameter.valid_mask)
    {
        case 0:
            pzxboot_emergency("version 0 and version 1 are both bad, fail\n");
            parameter.bootidx = -1;
            break;
        case 1:
            pzxboot_error("version 0 is ok, version 1 is bad\n");
            parameter.bootidx = 0;
            break;
        case 2:
            pzxboot_error("version 0 is bad, version 1 is ok\n");
            parameter.bootidx = 1;
            break;
        case 3:
            pzxboot_info("version 0 and version 1 are both ok\n");
            parameter.bootidx = (strncmp(parameter.headers[0].build_date, parameter.headers[1].build_date, 
                    sizeof(parameter.headers[0].build_date)) < 0) ? 1 : 0;
            break;
        default:
            pzxboot_emergency("invalid mask, fail\n");
            parameter.bootidx = -1;
            break;
    }

    if(parameter.bootidx == 0)
    {
        snprintf(parameter.bootargs, sizeof(parameter.bootargs), 
            "init=/linuxrc console=ttyAMA0,115200 root=%s rootwait ro", VERSION0_ROOTFS_PARTITION);
    }
    else if(parameter.bootidx == 1)
    {
        snprintf(parameter.bootargs, sizeof(parameter.bootargs), 
            "init=/linuxrc console=ttyAMA0,115200 root=%s rootwait ro", VERSION1_ROOTFS_PARTITION);
    }

    return parameter.bootidx;
}

void boot_kernel(void)
{
    int index = parameter.bootidx;
    phys_addr_t loadaddr = KERNEL_MEMADDRESS;
    unsigned long kernsize = parameter.headers[index].kernel_size;
    void *vaddr = map_sysmem(loadaddr, kernsize);
    char bootcmd[PZXBOOTSTRS_MAXLEN] = {0};
    ulong count = 0, read_blks = 0;
    lbaint_t start_blk = 0;
    unsigned int kernoff = index ? VERSION1_PARTITION_OFFSET : VERSION0_PARTITION_OFFSET;

    pzxboot_info("boot version %d kernel\n", index);
    // load kernel
    read_blks = parameter.headers[index].kernel_size / parameter.stor_desc->blksz;
    start_blk = (kernoff + KERNEL_OFFSET) / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("read kernel failed\n");
        return ;
    }
    unmap_sysmem(vaddr);

    // jump to kernel
    snprintf(bootcmd, sizeof(bootcmd), "bootm 0x%08x", KERNEL_MEMADDRESS);
    pzxboot_info("run command: %s\n", bootcmd);
    run_command(bootcmd, 0);

    //never come here
    return ;
}

static void parse_version_header(int index, void *vaddr)
{
    const struct version_header *verhead = (struct version_header *)(vaddr);
    pzxboot_info("\nversion %d header info:\n \
        magic[0]: %x, maigc[1]: %x\n \
        head version: %d.%d.%d.%d\n \
        build date: %s\n \
        verison number: %s\n", index, verhead->magic[0], verhead->magic[1],
        VERNUM_RESERVE(verhead->header_version), VERNUM_MAJOR(verhead->header_version),
        VERNUM_MINOR(verhead->header_version), VERNUM_PATCH(verhead->header_version),
        verhead->build_date, verhead->soft_version);
    
    memcpy(&parameter.headers[index], verhead, sizeof(struct version_header));

    return ;
}

#ifdef CONFIG_OF_BOARD_SETUP
int ft_board_setup(void *blob, struct bd_info *bd)
{
    int nodeoff = -1;
    char buf[16];
    int index = parameter.bootidx;

    pzxboot_info("start set bootargs and verinfo\n");
    // add an information node under "/chosen" path
    nodeoff = fdt_path_offset(blob, "/chosen");
    if(nodeoff < 0)
    {
        pzxboot_error("find chosen node failed in fdt\n");
        return -1;
    }

    fdt_setprop(blob, nodeoff, "bootargs", parameter.bootargs, sizeof(parameter.bootargs));
    fdt_setprop(blob, nodeoff, "versionnumber", parameter.headers[index].soft_version, 
        sizeof(parameter.headers[index].soft_version));
    fdt_setprop(blob, nodeoff, "curbuilddate", parameter.headers[index].build_date, 
        sizeof(parameter.headers[index].build_date));
    fdt_setprop(blob, nodeoff, "backbuilddate", parameter.headers[!index].build_date, 
        sizeof(parameter.headers[index].build_date));
    
    memset(buf, 0, sizeof(buf));
    if(3 == parameter.valid_mask)
        strncpy(buf, "Valid", sizeof(buf));
    else
        strncpy(buf, "Invalid", sizeof(buf));
    fdt_setprop(blob, nodeoff, "backverstate", buf, sizeof(buf));

    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", 
        VERNUM_RESERVE(parameter.headers[index].header_version),
        VERNUM_MAJOR(parameter.headers[index].header_version),
        VERNUM_MINOR(parameter.headers[index].header_version),
        VERNUM_PATCH(parameter.headers[index].header_version));
    fdt_setprop(blob, nodeoff, "curheaderver", buf, sizeof(buf));
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", 
        VERNUM_RESERVE(parameter.headers[!index].header_version),
        VERNUM_MAJOR(parameter.headers[!index].header_version),
        VERNUM_MINOR(parameter.headers[!index].header_version),
        VERNUM_PATCH(parameter.headers[!index].header_version));
    fdt_setprop(blob, nodeoff, "backheaderver", buf, sizeof(buf));

    if(index)
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION0_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, "backveroff", buf, sizeof(buf));
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION0_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, "backveroff", buf, sizeof(buf));
    }

    return 0;
}
#endif