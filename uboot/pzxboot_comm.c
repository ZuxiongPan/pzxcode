#include <env.h>
#include <gzip.h>
#include <stdio.h>
#include <mapmem.h>
#include <command.h>
#include <bootm.h>
#include <image.h>
#include <linux/string.h>
#include <linux/libfdt.h>
#include "pzxboot.h"

#ifdef CONFIG_USB_STORAGE
#include <usb.h>
#endif

static struct boot_param parameter;

static enum boot_errors check_header(unsigned int index, struct version_header *pheader);
static enum boot_errors version_check(unsigned int index, unsigned int offset);
static void pass_infomation_to_kernel_by_dtb(int index);

enum boot_errors boot_parameter_init(void)
{
    int ret = 0;
    memset(&parameter, 0, sizeof(struct boot_param));

#ifdef CONFIG_USB_STORAGE
    int usb_storage = usb_stor_scan(1);
    if(usb_storage < 0)
    {
        pzxboot_error("no usb storage device found\n");
        return ERROR_NODEVICE;
    }
    pzxboot_info("boot from usb storage device, dev number %d\n", usb_storage);
    //blk_common_cmd(argc, argv, UCLASS_USB, &usb_storage);
    ret = blk_get_desc(UCLASS_USB, usb_storage, &parameter.stor_desc);
    if(ret || (NULL == parameter.stor_desc))
    {
        pzxboot_error("get usb storage device %d failed\n", usb_storage);
        return ERROR_NODEVICE;
    }
    strncpy(parameter.bootargs, "init=/linuxrc console=ttyAMA0,115200", sizeof(parameter.bootargs) - 1);
    pzxboot_info("current block size of this storage device is 0x%08lx\n", parameter.stor_desc->blksz);
#endif

    return NO_ERRORS;
}

enum boot_errors find_valid_version(unsigned int offset)
{
    enum boot_errors ret = NO_ERRORS;

    if(offset == KERNEL1_PARTITION_OFFSET)
    {
        ret = version_check(0, offset);
        pzxboot_info("version 1 check ret %u\n", ret);
    }
    else
    {
        ret = version_check(1, offset);
        pzxboot_info("version 2 check ret %u\n", ret);
    }

    return ret;
}

static inline void set_bootargs(int index)
{
    if(index == 0)
    {
        strncat(parameter.bootargs, " root=/dev/sda2 rootwait ro", 
            sizeof(parameter.bootargs) - strlen(parameter.bootargs) - 1);
    }
    else
    {
        strncat(parameter.bootargs, " root=/dev/sda4 rootwait ro", 
            sizeof(parameter.bootargs) - strlen(parameter.bootargs) - 1);
    }

    return ;
}

int select_boot_version(void)
{
    int ret = parameter.info[0].header.common.header_index > parameter.info[1].header.common.header_index ? 0 : 1;
    if((parameter.info[ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        pzxboot_info("version %d is valid, header index %d\n", ret + 1, parameter.info[ret].header.common.header_index);
        set_bootargs(ret);
    }
    else if((parameter.info[!ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        ret = !ret;
        pzxboot_info("version %d is valid, header index %d\n", ret + 1, parameter.info[ret].header.common.header_index);
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
    void *vaddr = map_sysmem(loadaddr, parameter.info[index].header.common.kernel_size);
    ulong read_blks = 0, count = 0, kernsize = parameter.info[index].header.common.kernel_size;
    lbaint_t start_blk = 0;
    char bootcmd[PZXBOOTSTRS_MAXLEN] = {0};

    pzxboot_info("boot version %d kernel\n", index + 1);
    // load kernel
    read_blks = parameter.info[index].header.common.kernel_size / parameter.stor_desc->blksz;
    start_blk = parameter.info[index].header.common.kernel_offset / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("read kernel failed\n");
        return ;
    }
    unmap_sysmem(vaddr);

    // unzip kernel
    if (gunzip(map_sysmem(KERNEL_MEMADDRESS, ~0UL), ~0UL, map_sysmem(loadaddr, 0), &kernsize) != 0)
	{
        pzxboot_error("unzip kernel failed\n");
        return ;
    }

    pzxboot_info("unzip kernel success, kernel size %lu-0x%lx\n", kernsize);

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

static enum boot_errors check_header(unsigned int index, struct version_header *pheader)
{
    if((pheader->common.magic[0] != VERSION_HEADER_MAGIC0) ||
        (pheader->common.magic[1] != VERSION_HEADER_MAGIC1) ||
        (pheader->common.magic[2] != VERSION_HEADER_MAGIC2) ||
        (pheader->common.magic[3] != VERSION_HEADER_MAGIC3))
        {
            pzxboot_error("version %u header magic 0x%08x 0x%08x 0x%08x 0x%08x is invalid\n", index + 1,
                pheader->common.magic[0], pheader->common.magic[1],
                pheader->common.magic[2], pheader->common.magic[3]);
            return ERROR_HEADER;
        }
    
    unsigned int crc = pzx_crc32((unsigned char*)pheader, sizeof(struct common_version_header));
    pzxboot_info("version %u header crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, pheader->header_crc);
    if(crc != pheader->header_crc)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return ERROR_HEADER;
    }

    parameter.info[index].valid_version |= HEADER_ISVALID;
    memcpy(&parameter.info[index].header, pheader, sizeof(struct version_header));

    return NO_ERRORS;
}

static enum boot_errors version_check(unsigned int index, unsigned int offset)
{
    ulong read_blks = 0, count = 0;
    lbaint_t start_blk = 0;
    enum boot_errors ret = NO_ERRORS;
    phys_addr_t loadaddr = CONFIG_SYS_LOAD_ADDR;
    void *vaddr = map_sysmem(loadaddr, ROOTFS_PARTITION_SIZE);

    // 1. check headers
    read_blks = VER_HEADER_BLOCK_SIZE / parameter.stor_desc->blksz;
    start_blk = offset / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read header from offset 0x%08x in [%s]-[%s] device failed\n", index + 1, offset, 
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none",
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return ERROR_OPSTORDEVICE;
    }
    ret = check_header(index, vaddr);
    if(ret != NO_ERRORS)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return ret;
    }

    // 2. check kernel
    read_blks = parameter.info[index].header.common.kernel_size / parameter.stor_desc->blksz;
    start_blk = parameter.info[index].header.common.kernel_offset / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read kernel from offset 0x%08x in [%s]-[%s] device failed\n", index + 1, 
            parameter.info[index].header.common.kernel_offset,
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none",
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return ERROR_OPSTORDEVICE;
    }
    unsigned int crc = pzx_crc32(vaddr, parameter.info[index].header.common.kernel_size);
    pzxboot_info("version %u kernel crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.common.kernel_crc);
    if(crc != parameter.info[index].header.common.kernel_crc)
    {
        pzxboot_error("version %u kernel crc is invalid\n", index + 1);
        return ERROR_KERNEL;
    }
    parameter.info[index].valid_version |= KERNEL_ISVALID;

    // 3. check rootfs
    read_blks = parameter.info[index].header.common.rootfs_size / parameter.stor_desc->blksz;
    start_blk = parameter.info[index].header.common.rootfs_offset / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read rootfs from offset 0x%08x in [%s]-[%s] device failed\n", index + 1, 
            parameter.info[index].header.common.rootfs_offset,
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none", 
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return ERROR_OPSTORDEVICE;
    }
    crc = pzx_crc32(vaddr, parameter.info[index].header.common.rootfs_size);
    pzxboot_info("version %u rootfs crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.common.rootfs_crc);
    if(crc != parameter.info[index].header.common.rootfs_crc)
    {
        pzxboot_error("version %u rootfs crc is invalid\n", index + 1);
        return ERROR_ROOTFS;
    }
    parameter.info[index].valid_version |= ROOTFS_ISVALID;

    unmap_sysmem(vaddr);

    return NO_ERRORS;
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
    fdt_setprop(fdt, nodeoff, "versionnumber", parameter.info[index].header.common.soft_version_number, 
        sizeof(parameter.info[index].header.common.soft_version_number));
    fdt_setprop(fdt, nodeoff, "builddate", parameter.info[index].header.common.build_date, 
        sizeof(parameter.info[index].header.common.build_date));
    
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%08x", parameter.info[index].header.common.header_index);
    fdt_setprop(fdt, nodeoff, "bootverindex", buf, sizeof(buf));
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%08x", parameter.info[!index].header.common.header_index);
    fdt_setprop(fdt, nodeoff, "backverindex", buf, sizeof(buf));
    
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
        strncpy(buf, "/dev/sda3", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "bootospart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda4", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "bootfspart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda1", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "backospart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda2", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "backfspart", buf, sizeof(buf));
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda1", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "bootospart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda2", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "bootfspart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda3", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "backospart", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "/dev/sda4", sizeof(buf));
        fdt_setprop(fdt, nodeoff, "backfspart", buf, sizeof(buf));
    }
    
    unmap_sysmem(fdt);

    return ;
}