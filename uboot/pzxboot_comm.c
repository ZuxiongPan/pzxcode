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

static int check_header(unsigned int index, void *vaddr);
static int check_rsa_sign(unsigned int index, void *vaddr);
static int version_check(unsigned int index, unsigned int offset);
static void pass_infomation_to_kernel_by_dtb(int index);

int boot_parameter_init(void)
{
    int ret = 0;
    memset(&parameter, 0, sizeof(struct boot_param));

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

int find_valid_version(unsigned int offset)
{
    int ret = 0;

    if(offset == VERSION1_PARTITION_OFFSET)
    {
        ret = version_check(0, offset);
        pzxboot_info("version 1 check ret %d\n", ret);
    }
    else
    {
        ret = version_check(1, offset);
        pzxboot_info("version 2 check ret %d\n", ret);
    }

    return ret;
}

static inline void set_bootargs(int index)
{
    if(index == 0)
    {
        snprintf(parameter.bootargs, sizeof(parameter.bootargs),
            "init=/linuxrc console=ttyAMA0,115200 root=%s rootwait ro", VERSION1_ROOTFS_PARTITION);
    }
    else
    {
        snprintf(parameter.bootargs, sizeof(parameter.bootargs),
            "init=/linuxrc console=ttyAMA0,115200 root=%s rootwait ro", VERSION2_ROOTFS_PARTITION);
    }

    return ;
}

int select_boot_version(void)
{
    int ret = (strncmp(parameter.info[0].header.build_date, parameter.info[1].header.build_date, 
        sizeof(parameter.info[0].header.build_date)) < 0) ? 1 : 0;
    if((parameter.info[ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        pzxboot_info("version %d is valid, version date %s\n", ret + 1, parameter.info[ret].header.build_date);
        set_bootargs(ret);
    }
    else if((parameter.info[!ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        ret = !ret;
        pzxboot_info("version %d is valid, header index %s\n", ret + 1, parameter.info[ret].header.build_date);
        set_bootargs(ret);
    }
    else
    {
        pzxboot_emergency("no valid version, version valid mask %x %x\n",
            parameter.info[0].valid_version, parameter.info[1].valid_version);
        ret = -1;
    }
    pzxboot_info("bootargs: %s\n", parameter.bootargs);
    env_set("bootargs", parameter.bootargs);

    return ret;
}

void boot_kernel(int index)
{
    phys_addr_t loadaddr = CONFIG_SYS_LOAD_ADDR;
    unsigned long kernsize = parameter.info[index].header.kernel_size;
    void *vaddr = map_sysmem(loadaddr, kernsize);
    char bootcmd[PZXBOOTSTRS_MAXLEN] = {0};
    ulong count = 0, read_blks = 0;
    lbaint_t start_blk = 0;
    unsigned int kernoff = index ? VERSION2_PARTITION_OFFSET : VERSION1_PARTITION_OFFSET;

    pzxboot_info("boot version %d kernel\n", index + 1);
    // load kernel
    read_blks = parameter.info[index].header.kernel_size / parameter.stor_desc->blksz;
    start_blk = (kernoff + ALL_HEADERS_SIZE) / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("read kernel failed\n");
        return ;
    }
    unmap_sysmem(vaddr);

    // unzip kernel
    if (gunzip(map_sysmem(KERNEL_MEMADDRESS, ~0UL), ~0U, map_sysmem(loadaddr, 0), &kernsize) != 0)
	{
        pzxboot_error("unzip kernel failed\n");
        return ;
    }

    pzxboot_info("unzip kernel success, kernel size %lu-0x%lx\n", kernsize, kernsize);

#ifdef CONFIG_OF_LIBFDT
    // modify dtb, add version info
    pass_infomation_to_kernel_by_dtb(index);
#endif
    // jump to kernel
    snprintf(bootcmd, sizeof(bootcmd), "booti 0x%08x - 0x%08x", KERNEL_MEMADDRESS, DTB_MEMADDRESS);
    pzxboot_info("run command: %s\n", bootcmd);
    run_command(bootcmd, 0);

    //never come here
    return ;
}

static int check_header(unsigned int index, void *vaddr)
{
    unsigned int crc = 0;

    const struct version_header *verhead = (struct version_header *)(vaddr + VERSION_HEADER_OFFSET);
    if((verhead->magic[0] != VERSION_HEADER_MAGIC0) || (verhead->magic[1] != VERSION_HEADER_MAGIC1))
    {
        pzxboot_error("version %u header magic 0x%08x 0x%08x is invalid\n", index + 1,
            verhead->magic[0], verhead->magic[1]);
        return -EKEYEXPIRED;
    }
    
    crc = pzx_crc32((unsigned char*)verhead,
        sizeof(struct version_header) - sizeof(unsigned int));
    pzxboot_info("version %u header crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, verhead->header_crc);
    if(crc != verhead->header_crc)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return -EKEYEXPIRED;
    }

    parameter.info[index].valid_version |= HEADER_ISVALID;
    memcpy(&parameter.info[index].header, verhead, sizeof(struct version_header));

    return 0;
}

static int check_rsa_sign(unsigned int index, void *vaddr)
{
    parameter.info[index].valid_version |= SIGN_ISVALID;

    return 0;
}

static int version_check(unsigned int index, unsigned int offset)
{
    ulong read_blks = 0, count = 0;
    lbaint_t start_blk = offset / parameter.stor_desc->blksz;
    int ret = 0;
    unsigned int crc = 0;
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

    // 1. check headers
    ret = check_header(index, vaddr);
    if(ret != 0)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return ret;
    }

    // 2. check rsa signature
    ret = check_rsa_sign(index, vaddr);
    if(ret != 0)
    {
        pzxboot_error("rsa sign verify %u is failed\n", index + 1);
        return ret;
    }

    // 3. check kernel
    crc = pzx_crc32(vaddr + ALL_HEADERS_SIZE, parameter.info[index].header.kernel_size);
    pzxboot_info("version %u kernel crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.kernel_crc);
    if(crc != parameter.info[index].header.kernel_crc)
    {
        pzxboot_error("version %u kernel crc is invalid\n", index + 1);
        return -EKEYEXPIRED;
    }
    parameter.info[index].valid_version |= KERNEL_ISVALID;

    // 4. check rootfs
    crc = pzx_crc32(vaddr + KERNEL_PARTITION_SIZE, parameter.info[index].header.rootfs_size);
    pzxboot_info("version %u rootfs crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.rootfs_crc);
    if(crc != parameter.info[index].header.rootfs_crc)
    {
        pzxboot_error("version %u rootfs crc is invalid\n", index + 1);
        return -EKEYEXPIRED;
    }
    parameter.info[index].valid_version |= ROOTFS_ISVALID;

    unmap_sysmem(vaddr);

    return 0;
}

static void pass_infomation_to_kernel_by_dtb(int index)
{
    int nodeoff = -1;
    int tmp = 0;
    char buf[16];
    struct fdt_header *fdt = map_sysmem(DTB_MEMADDRESS, 0);

    // add an information node under "/" path
    nodeoff = fdt_path_offset(fdt, "/");
    if(nodeoff < 0)
    {
        pzxboot_error("find root node failed in fdt\n");
        return ;
    }
    tmp = fdt_add_subnode(fdt, nodeoff, "verinfo");
    if(tmp < 0)
    {
        pzxboot_error("add node verinfo failed\n");
        return ;
    }
    
    // verinfo node is valid, so do not check return value
    nodeoff = fdt_path_offset(fdt, "/verinfo");
    fdt_setprop(fdt, nodeoff, "versionnumber", parameter.info[index].header.soft_version_number, 
        sizeof(parameter.info[index].header.soft_version_number));
    fdt_setprop(fdt, nodeoff, "curbuilddate", parameter.info[index].header.build_date, 
        sizeof(parameter.info[index].header.build_date));
    fdt_setprop(fdt, nodeoff, "backbuilddate", parameter.info[!index].header.build_date, 
        sizeof(parameter.info[index].header.build_date));
    
    memset(buf, 0, sizeof(buf));
    tmp = (parameter.info[!index].valid_version == VERSION_ISVALID);
    if(tmp)
        strncpy(buf, "Valid", sizeof(buf));
    else
        strncpy(buf, "Invalid", sizeof(buf));
    fdt_setprop(fdt, nodeoff, "backverstate", buf, sizeof(buf));

    if(index)
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION2_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "backveroff", buf, sizeof(buf));
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION2_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "backveroff", buf, sizeof(buf));
    }
    
    unmap_sysmem(fdt);

    return ;
}
