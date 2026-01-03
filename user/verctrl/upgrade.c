#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "pzx_aes.h"
#include "common/version_header.h"
#include "common/version_partition.h"

const int MegaByte = 1024 * 1024;

extern int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize);
extern unsigned int pzx_crc32(const unsigned char *data, unsigned int length);
unsigned int pzx_crc32_segment(const unsigned char *data, unsigned int length, unsigned int crc);

static int version_check(int fd)
{
    unsigned int crc = 0, size = 0;
    unsigned char buf[STORDEV_PHYSICAL_BLKSIZE];
    struct version_header header;
    struct aes_ctx ctx;
    memset(&header, 0, sizeof(header));

    read(fd, buf, STORDEV_PHYSICAL_BLKSIZE);
    aes_init_ctx_iv(&ctx, (unsigned char *)AESKEY, (unsigned char *)AESIV);
    aes_cbc_decrypt_buffer(&ctx, (unsigned char *)buf, VER_HEADER_BLOCK_SIZE);

    memcpy(&header, buf, sizeof(struct version_header));
    // 1. check header
    if((header.common.magic[0] != VERSION_HEADER_MAGIC0) || (header.common.magic[1] != VERSION_HEADER_MAGIC1) ||
        (header.common.magic[2] != VERSION_HEADER_MAGIC2) || (header.common.magic[3] != VERSION_HEADER_MAGIC3))
    {
        printf("invalid header magic %x %x %x %x\n", header.common.magic[0], header.common.magic[1], 
            header.common.magic[2], header.common.magic[3]);
        return -EKEYEXPIRED;
    }
    crc = pzx_crc32(buf, sizeof(struct common_version_header));
    printf("calculated header crc is 0x%x, stored header crc is 0x%x\n", crc, header.header_crc);
    if(crc != header.header_crc)
    {
        printf("header crc is error!\n");
        return -EKEYEXPIRED;
    }

    // 2. check kernel
    size = 0, crc = 0;
    lseek(fd, VER_HEADER_BLOCK_SIZE, SEEK_SET);
    while(size < header.common.kernel_size)
    {
        read(fd, buf, STORDEV_PHYSICAL_BLKSIZE);
        crc = pzx_crc32_segment(buf, STORDEV_PHYSICAL_BLKSIZE, crc);
        size += STORDEV_PHYSICAL_BLKSIZE;
    }
    printf("calculated kernel crc is 0x%x, stored kernel crc is 0x%x\n", crc, header.common.kernel_crc);
    if(crc != header.common.kernel_crc)
    {
        printf("kernel crc is error!\n");
        return -EKEYEXPIRED;
    }

    // 3. check rootfs
    size = 0, crc = 0;
    lseek(fd, KERNEL_PARTITION_SIZE, SEEK_SET);
    while(size < header.common.rootfs_size)
    {
        read(fd, buf, STORDEV_PHYSICAL_BLKSIZE);
        crc = pzx_crc32_segment(buf, STORDEV_PHYSICAL_BLKSIZE, crc);
        size += STORDEV_PHYSICAL_BLKSIZE;
    }
    printf("calculated rootfs crc is 0x%x, stored rootfs crc is 0x%x\n", crc, header.common.rootfs_crc);
    if(crc != header.common.rootfs_crc)
    {
        printf("rootfs crc is error!\n");
        return -EKEYEXPIRED;
    }

    return 0;
}

static int write_version(int rfd, int wfd)
{
    char buf[32];
    unsigned int woff;
    char *tmp = (char*)malloc(MegaByte);
    if(NULL == tmp)
    {
        printf("malloc buffer memory failed\n");
        return -ENOMEM;
    }

    if(true != get_value_from_verinfo("Backup Version Offset", buf, sizeof(buf)))
    {
        printf("get Backup Version Offset failed\n");
        free(tmp);
        return -EACCES;
    }

    sscanf(buf, "0x%x", &woff);
    printf("version will write to offset %x in /dev/sda\n", woff);

    lseek(wfd, woff, SEEK_SET);
    lseek(rfd, 0, SEEK_SET);

    woff = 0;
    while(0 < read(rfd, tmp, MegaByte))
    {
        write(wfd, tmp, MegaByte);
        woff += MegaByte;
    }

    printf("write %d Bytes success\n", woff);
    free(tmp);

    return 0;
}

int do_upgrade_version(const char *filepath)
{
    int ret = 0;
    int rfd = open(filepath, O_RDONLY);
    if(rfd < 0)
    {
        printf("open file %s failed\n", filepath);
        return -EACCES;
    }

    int wfd = open(STORDEV_NAME, O_WRONLY);
    if(wfd < 0)
    {
        printf("open file %s failed\n", STORDEV_NAME);
        close(rfd);
        return -EACCES;
    }

    ret = version_check(rfd);
    if(ret != 0)
    {
        printf("version check failed, ret %d\n", ret);
        close(rfd);
        close(wfd);
        return ret;
    }

    ret = write_version(rfd, wfd);
    printf("write version ret %d\n", ret);

    close(rfd);
    close(wfd);
    return ret;
}