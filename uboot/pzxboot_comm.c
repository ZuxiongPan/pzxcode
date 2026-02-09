#include <env.h>
#include <gzip.h>
#include <stdio.h>
#include <linux/errno.h>
#include <mapmem.h>
#include <command.h>
#include <bootm.h>
#include <image.h>
#include <part.h>
#include <asm/global_data.h>
#include <linux/string.h>
#include <linux/libfdt.h>
#include <u-boot/sha256.h>
#include <u-boot/rsa.h>
#include "pzxboot.h"
#include "common/version_info.h"
#include "boot/partition_info.h"

#ifdef CONFIG_VERHEADER_ENCRYPT
#include "common/aes_key.h"
#include <uboot_aes.h>
#endif

#ifdef CONFIG_USB_STORAGE
#include <usb.h>
#endif

DECLARE_GLOBAL_DATA_PTR;
static struct boot_param parameter;

static void parse_version_header(int index, void *vaddr);

extern uint32_t pzx_crc32(const uint8_t *data, uint32_t length);
extern int rsa_verify_with_keynode(struct image_sign_info *info,
			const void *hash, uint8_t *sig, uint sig_len, int node);

int boot_parameter_init(void)
{
    int ret = 0;
    memset(&parameter, 0, sizeof(struct boot_param));
    parameter.bootidx = -1;

#ifdef CONFIG_USB_STORAGE
    //blk_common_cmd(argc, argv, UCLASS_USB, &usb_storage);
    ret = blk_get_desc(UCLASS_USB, 0, &parameter.stor_desc);
    if(ret || (NULL == parameter.stor_desc))
    {
        pzxboot_error("get usb storage device 0 failed\n");
        return -EBADFD;
    }
    pzxboot_info("current block size of this storage device is 0x%08lx\n", parameter.stor_desc->blksz);
#endif

/*
    pzxboot_info("global data info:\n \
            bd: 0x%lx, flags: 0x%lx, baudrate: 0x%x\n \
            cpu_clk: 0x%lx, bus_clk: 0x%lx, pci_clk: 0x%lx, mem_clk: 0x%lx\n \
            have_console: %lu, env_addr: 0x%lx, env_valid: %lu, env_has_init: %lu\n \
            env_load_prio: %d, ram_base: 0x%lx, ram_top: 0x%lx, relocaddr: 0x%lx\n \
            ram_size: 0x%lx, mon_len: 0x%lx, irq_sp: 0x%lx, start_addr_sp: 0x%lx\n \
            reloc_off: 0x%lx, new_gd: 0x%lx, fdt_blob: 0x%lx, new_fdt: 0x%lx\n \
            fdt_size: 0x%x, fdt_src: %u\n", (unsigned long)gd->bd, gd->flags, gd->baudrate,
            gd->cpu_clk, gd->bus_clk, gd->pci_clk, gd->mem_clk, gd->have_console,
            gd->env_addr, gd->env_valid, gd->env_has_init, gd->env_load_prio,
            gd->ram_base, gd->ram_top, gd->relocaddr, gd->ram_size, gd->mon_len,
            gd->irq_sp, gd->start_addr_sp, gd->reloc_off, (unsigned long)gd->new_gd,
            (unsigned long)gd->fdt_blob, (unsigned long)gd->new_fdt, gd->fdt_size, gd->fdt_src);
*/

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
        pzxboot_error("version %u read header from offset 0x%08x in [%s]-[%s] device failed\n", index , offset, 
            strlen(parameter.stor_desc->vendor) ? parameter.stor_desc->vendor : "none",
            strlen(parameter.stor_desc->product) ? parameter.stor_desc->product : "none");
        return -EIO;
    }

    // 1. check rsa sign
    int ret = pzx_rsa_check(vaddr + SIGN_HEADER_OFFSET, vaddr + VERSION_HEADER_OFFSET);
    parameter.valid_mask |= (ret << index);
    if(0 == ret)
    {
        pzxboot_error("version %u rsa sign check is invalid\n", index);
        return -EKEYEXPIRED;
    }

#ifdef CONFIG_VERHEADER_ENCRYPT
    struct signature_header *sighead = (struct signature_header *)vaddr;
    u8 exp_key[AES256_EXPAND_KEY_LENGTH];
    u8 aes_key_bak[32];
    memcpy(aes_key_bak, aes_key, 32);
    aes_expand_key(aes_key_bak, AES256_KEY_LENGTH, exp_key);
    aes_cbc_decrypt_blocks(AES256_KEY_LENGTH, exp_key, sighead->aes_iv,
        vaddr + VERSION_HEADER_OFFSET, vaddr + VERSION_HEADER_OFFSET,
        HEADER_SIZE / AES_BLOCK_LENGTH);
#endif
    // 2. parse headers
    parse_version_header(index, vaddr + VERSION_HEADER_OFFSET);

    unmap_sysmem(vaddr);

    return 0;
}

void set_partition_table(void)
{
    char partstr[4096] = {0};
    struct disk_partition partinfo = {0};
    bool change = false;
    int i = 0;

    // modify simple_partitions table
    if(parameter.valid_mask & 0x1)
    {
        simple_partitions[0].size = parameter.headers[0].kpart_size / MEGABYTES;
        simple_partitions[1].size = parameter.headers[0].rpart_size / MEGABYTES;
    }
    if(parameter.valid_mask & 0x2)
    {
        simple_partitions[2].size = parameter.headers[1].kpart_size / MEGABYTES;
        simple_partitions[3].size = parameter.headers[1].rpart_size / MEGABYTES;
    }

    // last partition do not check
    for(i = 0; i < part_nums - 1; i++)
    {
        if(part_get_info(parameter.stor_desc, i + 1, &partinfo) != 0)
        {
            pzxboot_warn("get GPT partition %d failed, need change GPT table\n", i);
            change = true;
            break;
        }

        if(strcmp(partinfo.name, simple_partitions[i].name) != 0)
        {
            pzxboot_warn("partition %d name %s is invalid, need change GPT table\n", i, partinfo.name);
            change = true;
            break;
        }

        lbaint_t partsize = partinfo.size * partinfo.blksz;
        if(partsize != (simple_partitions[i].size * MEGABYTES))
        {
            pzxboot_warn("partition %d size %lx is invalid, need change GPT table\n", i, partinfo.size);
            change = true;
            break;
        }

        lbaint_t partstart = partinfo.start * partinfo.blksz;
        if(partstart != (simple_partitions[i].start * MEGABYTES))
        {
            pzxboot_warn("partition %d start %lx is invalid, need change GPT table\n", i, partinfo.start);
            change = true;
            break;
        }
    }

    pzxboot_info("%s GPT table\n", change ? "CHANGE" : "NO CHANGE");
    if(change)
    {
        int writelen = snprintf(partstr, 4096, "gpt write usb 0 ");
        for(i = 0; i < part_nums; i++)
        {
            writelen += snprintf(partstr + writelen, 4096 - writelen, "name=%s,size=%uM,start=%uM\\;",
                simple_partitions[i].name, simple_partitions[i].size , simple_partitions[i].start);
        }
        pzxboot_info("gpt command length %d, content:\n[%s]\n", writelen, partstr);
        run_command(partstr, 0);
    }

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
            pzxboot_warn("version 0 is ok, version 1 is bad\n");
            parameter.bootidx = 0;
            break;
        case 2:
            pzxboot_warn("version 0 is bad, version 1 is ok\n");
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
            "init=/linuxrc root=%s rootwait ro console=ttyAMA0,115200 earlycon", VERSION0_ROOTFS_PARTITION);
    }
    else if(parameter.bootidx == 1)
    {
        snprintf(parameter.bootargs, sizeof(parameter.bootargs), 
            "init=/linuxrc root=%s rootwait ro console=ttyAMA0,115200 earlycon", VERSION1_ROOTFS_PARTITION);
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
    pzxboot_info("version %d header info:\n \
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

int pzx_rsa_check(void *sighead_addr, void *sigdata_addr)
{
    unsigned int crc = 0;
    struct signature_header *sighead = (struct signature_header *)sighead_addr;

    if(SIGN_HEADER_MAGIC0 != sighead->magic[0] || SIGN_HEADER_MAGIC1 != sighead->magic[1])
    {
        pzxboot_error("signature header is invalid, need 0x%08x 0x%08x, real 0x%08x 0x%08x\n",
            SIGN_HEADER_MAGIC0, SIGN_HEADER_MAGIC1, sighead->magic[0], sighead->magic[1]);
        return 0;
    }

    crc = pzx_crc32(sighead_addr, sizeof(struct signature_header) - sizeof(uint32_t));
    if(crc != sighead->header_crc)
    {
        pzxboot_error("header crc is invalid, need 0x%08x, real 0x%08x\n", crc, sighead->header_crc);
        return 0;
    }

    pzxboot_info("signature info:\n \
        magic[0]: %x magic[1]: %x\n \
        head version: %d.%d.%d.%d\n \
        signed data size %u, signature size %u\n \
        signature:\n",
        sighead->magic[0], sighead->magic[1],
        VERNUM_RESERVE(sighead->header_version), VERNUM_MAJOR(sighead->header_version),
        VERNUM_MINOR(sighead->header_version), VERNUM_PATCH(sighead->header_version),
        sighead->signed_size, sighead->sig_size);
    
    for(uint32_t i = 0; i < sighead->sig_size; i++)
    {
        printf("%02x", sighead->signature[i]);
    }
    printf("\n");

    int ret = 0;
    struct image_sign_info info = {0};
    struct image_region region = { sigdata_addr, sighead->signed_size };
    info.name = RSASIGN_NAME;
    info.keyname = "rsapub";
    info.checksum = image_get_checksum_algo(RSASIGN_NAME);
    info.crypto = image_get_crypto_algo(RSASIGN_NAME);
    info.padding = image_get_padding_algo(RSA_DEFAULT_PADDING_NAME);
    info.fdt_blob = gd->fdt_blob;
    info.required_keynode = fdt_subnode_offset(info.fdt_blob, 0, "rsapub");

    if(info.required_keynode < 0 || NULL == info.checksum || NULL == info.crypto || NULL == info.padding)
    {
        pzxboot_error("pubkey/checksum/crypto/padding is invalid\n");
        return false;
    }

    unsigned char hash[info.crypto->key_len];
    ret = info.checksum->calculate(info.checksum->name, &region, 1, hash);
    if(ret < 0)
    {
        pzxboot_error("calculate image hash failed\n");
        return false;
    }

    ret = rsa_verify_with_keynode(&info, hash, sighead->signature, sighead->sig_size, info.required_keynode);
    pzxboot_info("rsa_verify_with_keynode return %d\n", ret);

    return (ret == 0);
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
    fdt_setprop(blob, nodeoff, DTB_VERNUM_NAME, parameter.headers[index].soft_version, 
        sizeof(parameter.headers[index].soft_version));
    fdt_setprop(blob, nodeoff, DTB_CURVERDATE_NAME, parameter.headers[index].build_date, 
        sizeof(parameter.headers[index].build_date));
    
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", 
        VERNUM_RESERVE(parameter.headers[index].header_version),
        VERNUM_MAJOR(parameter.headers[index].header_version),
        VERNUM_MINOR(parameter.headers[index].header_version),
        VERNUM_PATCH(parameter.headers[index].header_version));
    fdt_setprop(blob, nodeoff, DTB_CURHEADVER_NAME, buf, sizeof(buf));
    
    if(index)
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, DTB_CURVEROFF_NAME, buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION0_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, DTB_BACKVEROFF_NAME, buf, sizeof(buf));
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION0_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, DTB_CURVEROFF_NAME, buf, sizeof(buf));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "0x%x", VERSION1_PARTITION_OFFSET);
        fdt_setprop(blob, nodeoff, DTB_BACKVEROFF_NAME, buf, sizeof(buf));
    }

    if(3 == parameter.valid_mask)
    {
        fdt_setprop(blob, nodeoff, DTB_BACKVERSTAT_NAME, STATES_VALID, sizeof(STATES_VALID));
        fdt_setprop(blob, nodeoff, DTB_BACKVERDATE_NAME, parameter.headers[!index].build_date, 
            sizeof(parameter.headers[index].build_date));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", 
            VERNUM_RESERVE(parameter.headers[!index].header_version),
            VERNUM_MAJOR(parameter.headers[!index].header_version),
            VERNUM_MINOR(parameter.headers[!index].header_version),
            VERNUM_PATCH(parameter.headers[!index].header_version));
        fdt_setprop(blob, nodeoff, DTB_BACKHEADVER_NAME, buf, sizeof(buf));
    }
    else
    {
        fdt_setprop(blob, nodeoff, DTB_BACKVERDATE_NAME, STATES_INVALID, sizeof(STATES_INVALID));
        fdt_setprop(blob, nodeoff, DTB_BACKVERSTAT_NAME, STATES_INVALID, sizeof(STATES_INVALID));
        fdt_setprop(blob, nodeoff, DTB_BACKHEADVER_NAME, STATES_INVALID, sizeof(STATES_INVALID));
    }

    return 0;
}
#endif