#ifndef __PZXBOOT_H__
#define __PZXBOOT_H__

#include <asm/types.h>
#include <blk.h>

#include "pzx_config.h"
#include "common/version_header.h"
#include "common/version_partition.h"

#define PZXBOOTSTRS_MAXLEN 256

#define KERNEL_MEMADDRESS 0x42000000

#define pzxboot_debug(fmt, ...) \
    printf("[%s](Debug)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define pzxboot_info(fmt, ...) \
    printf("[%s](Info)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define pzxboot_warn(fmt, ...) \
    printf("[%s](Warn)@%d# " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
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
int pzx_rsa_check(void *sighead_addr, void *sigdata_addr);
void boot_kernel(void);

#endif