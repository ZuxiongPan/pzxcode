#ifndef __PZXBOOT_H__
#define __PZXBOOT_H__

#include <asm/types.h>
#include <blk.h>

#include "common/version_header.h"
#include "common/version_partition.h"

#define HEADER_ISVALID 0x01
#define SIGN_ISVALID 0x02
#define KERNEL_ISVALID 0x04
#define ROOTFS_ISVALID 0x08

#define VERSION_ISVALID (HEADER_ISVALID | SIGN_ISVALID | KERNEL_ISVALID | ROOTFS_ISVALID)

#define PZXBOOTSTRS_MAXLEN 256

#define KERNEL_MEMADDRESS 0x44000000

#define pzxboot_debug(fmt, ...) \
    printf("[%s](Debug)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define pzxboot_info(fmt, ...) \
    printf("[%s](Info)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define pzxboot_error(fmt, ...) \
    printf("[%s](Error)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define pzxboot_emergency(fmt, ...) \
    printf("[%s](Emergency)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct boot_param {
    struct version_header headers[VERSION_COUNTS];
    unsigned char valid_mask;
    int bootidx;
    struct blk_desc *stor_desc;
    char bootargs[PZXBOOTSTRS_MAXLEN];
};

int boot_parameter_init(void);
int version_check(int index);
void set_partition_table(void);
int select_boot_version(void);
void boot_kernel(void);

#endif