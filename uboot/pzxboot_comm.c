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
#include "common/pzx_stat.h"

#ifdef CONFIG_USB_STORAGE
#include <usb.h>
#endif

static struct boot_param parameter;

static int check_header(unsigned int index, struct version_header *pheader);
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
        return ERR_NODEVICE;
    }
    pzxboot_info("boot from usb storage device, dev number %d\n", usb_storage);
    //blk_common_cmd(argc, argv, UCLASS_USB, &usb_storage);
    ret = blk_get_desc(UCLASS_USB, usb_storage, &parameter.stor_desc);
    if(ret || (NULL == parameter.stor_desc))
    {
        pzxboot_error("get usb storage device %d failed\n", usb_storage);
        return ERR_NODEVICE;
    }
    strncpy(parameter.bootargs, "init=/linuxrc console=ttyAMA0,115200", sizeof(parameter.bootargs) - 1);
    pzxboot_info("current block size of this storage device is 0x%08lx\n", parameter.stor_desc->blksz);
#endif

    return SUCCESS;
}

int find_valid_version(unsigned int offset)
{
    int ret = SUCCESS;

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
    int ret = (strncmp(parameter.info[0].header.common.build_date, parameter.info[1].header.common.build_date, 
        sizeof(parameter.info[0].header.common.build_date)) < 0) ? 1 : 0;
    if((parameter.info[ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        pzxboot_info("version %d is valid, version date %s\n", ret + 1, parameter.info[ret].header.common.build_date);
        set_bootargs(ret);
    }
    else if((parameter.info[!ret].valid_version & VERSION_ISVALID) == VERSION_ISVALID)
    {
        ret = !ret;
        pzxboot_info("version %d is valid, header index %s\n", ret + 1, parameter.info[ret].header.common.build_date);
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
    unsigned int kernoff = index ? KERNEL2_PARTITION_OFFSET : KERNEL1_PARTITION_OFFSET;

    pzxboot_info("boot version %d kernel\n", index + 1);
    // load kernel
    read_blks = parameter.info[index].header.common.kernel_size / parameter.stor_desc->blksz;
    start_blk = (kernoff + VER_HEADER_BLOCK_SIZE) / parameter.stor_desc->blksz;
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

static int check_header(unsigned int index, struct version_header *pheader)
{
    if((pheader->common.magic[0] != VERSION_HEADER_MAGIC0) ||
        (pheader->common.magic[1] != VERSION_HEADER_MAGIC1) ||
        (pheader->common.magic[2] != VERSION_HEADER_MAGIC2) ||
        (pheader->common.magic[3] != VERSION_HEADER_MAGIC3))
        {
            pzxboot_error("version %u header magic 0x%08x 0x%08x 0x%08x 0x%08x is invalid\n", index + 1,
                pheader->common.magic[0], pheader->common.magic[1],
                pheader->common.magic[2], pheader->common.magic[3]);
            return ERR_VERIFY_FAILED;
        }
    
    unsigned int crc = pzx_crc32((unsigned char*)pheader, sizeof(struct common_version_header));
    pzxboot_info("version %u header crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, pheader->header_crc);
    if(crc != pheader->header_crc)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return ERR_VERIFY_FAILED;
    }

    parameter.info[index].valid_version |= HEADER_ISVALID;
    memcpy(&parameter.info[index].header, pheader, sizeof(struct version_header));

    return SUCCESS;
}

static int version_check(unsigned int index, unsigned int offset)
{
    ulong read_blks = 0, count = 0;
    lbaint_t start_blk = 0;
    int ret = SUCCESS;
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
        return ERR_READ_FAIED;
    }
    ret = check_header(index, vaddr);
    if(ret != SUCCESS)
    {
        pzxboot_error("version %u header is invalid\n", index + 1);
        return ret;
    }

    // 2. check kernel
    read_blks = parameter.info[index].header.common.kernel_size / parameter.stor_desc->blksz;
    start_blk = (offset + VER_HEADER_BLOCK_SIZE) / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read kernel from offset 0x%08x in [%s]-[%s] device failed\n", 
            index + 1, offset + VER_HEADER_BLOCK_SIZE,
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none",
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return ERR_READ_FAIED;
    }
    unsigned int crc = pzx_crc32(vaddr, parameter.info[index].header.common.kernel_size);
    pzxboot_info("version %u kernel crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.common.kernel_crc);
    if(crc != parameter.info[index].header.common.kernel_crc)
    {
        pzxboot_error("version %u kernel crc is invalid\n", index + 1);
        return ERR_VERIFY_FAILED;
    }
    parameter.info[index].valid_version |= KERNEL_ISVALID;

    // 3. check rootfs
    read_blks = parameter.info[index].header.common.rootfs_size / parameter.stor_desc->blksz;
    start_blk = (offset + KERNEL_PARTITION_SIZE) / parameter.stor_desc->blksz;
    count = blk_dread(parameter.stor_desc, start_blk, read_blks, vaddr);
    if(count != read_blks)
    {
        pzxboot_error("version %u read rootfs from offset 0x%08x in [%s]-[%s] device failed\n",
            index + 1, offset + KERNEL_PARTITION_SIZE,
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none", 
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return ERR_READ_FAIED;
    }
    crc = pzx_crc32(vaddr, parameter.info[index].header.common.rootfs_size);
    pzxboot_info("version %u rootfs crc 0x%08x, expect crc 0x%08x\n", index + 1, crc, 
        parameter.info[index].header.common.rootfs_crc);
    if(crc != parameter.info[index].header.common.rootfs_crc)
    {
        pzxboot_error("version %u rootfs crc is invalid\n", index + 1);
        return ERR_VERIFY_FAILED;
    }
    parameter.info[index].valid_version |= ROOTFS_ISVALID;

    unmap_sysmem(vaddr);

    return SUCCESS;
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
    fdt_setprop(fdt, nodeoff, "curbuilddate", parameter.info[index].header.common.build_date, 
        sizeof(parameter.info[index].header.common.build_date));
    fdt_setprop(fdt, nodeoff, "backbuilddate", parameter.info[!index].header.common.build_date, 
        sizeof(parameter.info[index].header.common.build_date));
    
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
        snprintf(buf, sizeof(buf), "0x%x", KERNEL2_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", KERNEL1_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "backveroff", buf, sizeof(buf));
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", KERNEL1_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "bootveroff", buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", KERNEL2_PARTITION_OFFSET);
        fdt_setprop(fdt, nodeoff, "backveroff", buf, sizeof(buf));
    }
    
    unmap_sysmem(fdt);

    return ;
}