#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <linux/errno.h>

#include "common/version_partition.h"
#include "common/version_header.h"
#include "pzx_aes.h"
#define FILEPATH_MAXLEN 256

char kernel_filepath[FILEPATH_MAXLEN] = {0};
char rootfs_filepath[FILEPATH_MAXLEN] = {0};
char version_filepath[FILEPATH_MAXLEN] = {0};
char upgrade_filepath[FILEPATH_MAXLEN] = {0};

extern unsigned int pzx_crc32(const unsigned char *data, unsigned int length);
extern unsigned int pzx_crc32_segment(const unsigned char *data, unsigned int length, unsigned int crc);
int get_options(int argc, char *const *argv);
void print_usage(void);
void header_init(struct version_header *pheader);
unsigned int write_file_aligned(FILE *in, FILE *out, unsigned int outpos, unsigned int *size);
int build_upgrade_file(void);
int build_version_file(void);
int encrypt_kernel(void);

int main(int argc, char *argv[])
{
    int ret = 0;

    ret = get_options(argc, argv);
    if(ret != 0)
    {
        print_usage();
        return ret;
    }

    ret = encrypt_kernel();
    if(ret != 0)
    {
        printf("encrypt kernel failed\n");
        return ret;
    }

    ret = build_upgrade_file();
    if(ret != 0)
    {
        printf("build upgrade file %s error\n", upgrade_filepath);
        return ret;
    }

    ret = build_version_file();
    if(ret != 0)
    {
        printf("build version file %s error\n", version_filepath);
        return ret;
    }
    
    return ret;
}

void header_init(struct version_header *pheader)
{
    // pheader is valid, do not check
    pheader->common.magic[0] = VERSION_HEADER_MAGIC0;
    pheader->common.magic[1] = VERSION_HEADER_MAGIC1;
    pheader->common.magic[2] = VERSION_HEADER_MAGIC2;
    pheader->common.magic[3] = VERSION_HEADER_MAGIC3;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(pheader->common.build_date, sizeof(pheader->common.build_date), "%04u%02u%02u%02u%02u%02u", 
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    snprintf(pheader->common.soft_version_number, sizeof(pheader->common.soft_version_number), VERSION_NUMBER);

    pheader->header_crc = 0;

    return ;
}

unsigned int write_file_aligned(FILE *in, FILE *out, unsigned int outpos, unsigned int *size)
{
    unsigned char buf[STORDEV_PHYSICAL_BLKSIZE];
    unsigned int blk_num = 0;
    unsigned int crc = 0;

    memset(buf, 0, sizeof(buf));
    fseek(in, 0, SEEK_SET);
    fseek(out, outpos, SEEK_SET);

    while(fread(buf, 1, STORDEV_PHYSICAL_BLKSIZE, in) > 0)
    {
        fwrite(buf, 1, STORDEV_PHYSICAL_BLKSIZE, out);
        blk_num++;
        crc = pzx_crc32_segment(buf, STORDEV_PHYSICAL_BLKSIZE, crc);
        memset(buf, 0, sizeof(buf));
    }

    *size = blk_num * STORDEV_PHYSICAL_BLKSIZE;
    printf("write %u blocks, total size %u bytes, crc 0x%08x\n", blk_num, *size, crc);

    return crc;
}

static void encrypt(unsigned char *buf, unsigned int len)
{
    struct aes_ctx ctx;

    aes_init_ctx_iv(&ctx, (unsigned char *)AESKEY, (unsigned char *)AESIV);
    aes_cbc_encrypt_buffer(&ctx, buf, len);
}

int encrypt_kernel(void)
{
    FILE *kernel = fopen(kernel_filepath, "rb+");
    if(NULL == kernel)
    {
        printf("file %s is not found, please check\n", kernel_filepath);
        return -EACCES;
    }

    fseek(kernel, 0, SEEK_END);
    unsigned int size = ftell(kernel);
    unsigned int aligned = (size + STORDEV_PHYSICAL_BLKSIZE - 1) & ~(STORDEV_PHYSICAL_BLKSIZE -1);
    unsigned char *buf = malloc(aligned);
    if(NULL == buf)
    {
        printf("alloc memory for encrypt failed\n");
        fclose(kernel);
        return -ENOMEM;
    }
    memset(buf, 0xff, aligned);
    fseek(kernel, 0, SEEK_SET);
    if(size != fread(buf, sizeof(unsigned char), size, kernel))
    {
        printf("read kernel failed\n");
        free(buf);
        fclose(kernel);
        return -EACCES;
    }

    encrypt(buf, aligned);
    fseek(kernel, 0, SEEK_SET);
    fwrite(buf, sizeof(unsigned char), aligned, kernel);

    free(buf);
    fclose(kernel);
    return 0;
}

int build_upgrade_file(void)
{
    FILE *upgrade = NULL;
    FILE *kernel = NULL;
    FILE *rootfs = NULL;

    unsigned char headbuf[VER_HEADER_BLOCK_SIZE];
    memset(headbuf, 0xff, sizeof(headbuf));
    struct version_header *pheader = (struct version_header *)headbuf;
    header_init(pheader);

    kernel = fopen(kernel_filepath, "rb");
    if(NULL == kernel)
    {
        printf("file %s is not found, please check\n", kernel_filepath);
        return -EACCES;
    }

    rootfs = fopen(rootfs_filepath, "rb");
    if(NULL == rootfs)
    {
        printf("file %s is not found, please check\n", rootfs_filepath);
        fclose(kernel);
        return -EACCES;
    }

    upgrade = fopen(upgrade_filepath, "wb+");
    if(NULL == upgrade)
    {
        printf("file %s create failed\n", upgrade_filepath);
        fclose(kernel);
        fclose(rootfs);
        return -EACCES;
    }

    /**
     * upgrade file content: header(blk aligned) + kernel(blk aligned) + rootfs(blk aligned)
     * 1. write kernel to upgrade & update version upgrade
     * 2. write rootfs to upgrade & update version upgrade
     * 3. encrypt header and write header to upgrade
     */
    printf("!!! write kernel image to upgrade file start ...\n");
    pheader->common.kernel_crc = write_file_aligned(kernel, upgrade, 
        VER_HEADER_BLOCK_SIZE, &pheader->common.kernel_size);
    printf("... write kernel finish, kernel size is %d, kernel crc is 0x%08x !!!\n", 
        pheader->common.kernel_size, pheader->common.kernel_crc);

    printf("!!! write rootfs image to upgrade file start ...\n");
    pheader->common.rootfs_crc = write_file_aligned(rootfs, upgrade, 
        KERNEL_PARTITION_SIZE, &pheader->common.rootfs_size);
    printf("... write rootfs finish, rootfs size is %d, rootfs crc is 0x%08x !!!\n", 
        pheader->common.rootfs_size, pheader->common.rootfs_crc);

    pheader->header_crc = pzx_crc32((const unsigned char *)pheader, sizeof(struct common_version_header));
    printf("... header crc 0x%08x !!!\n", pheader->header_crc);
    encrypt(headbuf, VER_HEADER_BLOCK_SIZE);
    fseek(upgrade, 0, SEEK_SET);
    fwrite(headbuf, 1, VER_HEADER_BLOCK_SIZE, upgrade);

    fclose(kernel);
    fclose(rootfs);
    fclose(upgrade);

    return 0;
}

int build_version_file(void)
{
    FILE *version = NULL;
    FILE *upgrade = NULL;
    unsigned char *buf = NULL;
    unsigned int upgrade_size = KERNEL_PARTITION_SIZE + ROOTFS_PARTITION_SIZE;

    upgrade = fopen(upgrade_filepath, "rb");
    if(NULL == upgrade)
    {
        printf("file %s is not found, please check\n", upgrade_filepath);
        return -EACCES;
    }

    version = fopen(version_filepath, "rb+");
    if(NULL == version)
    {
        printf("file %s create failed\n", version_filepath);
        fclose(upgrade);
        return -EACCES;
    }

    buf = (unsigned char *)malloc(upgrade_size);
    if(NULL == buf)
    {
        printf("malloc %u bytes memory failed\n", upgrade_size);
        fclose(upgrade);
        fclose(version);
        return -ENOMEM;
    }
    memset(buf, 0, upgrade_size);

    // write upgrade to version file
    fseek(upgrade, 0, SEEK_SET);
    printf("start read upgrade file\n");
    upgrade_size = fread(buf, 1, upgrade_size, upgrade);
    printf("upgrade file real size is %d\n", upgrade_size);
    
    printf("write upgrade file to image1\n");
    fseek(version, KERNEL1_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    printf("write upgrade file to image2\n");
    fseek(version, KERNEL2_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    free(buf);
    fclose(upgrade);
    fclose(version);

    return 0;
}

int get_options(int argc, char *const *argv)
{
    extern char *optarg;
    extern int optopt;
    int opt = getopt(argc, argv, "k:r:v:u:");
    int ret = 0;
    
    while(opt != -1 && ret == 0)
    {
        switch(opt)
        {
            case 'k':
                strncpy(kernel_filepath, optarg, FILEPATH_MAXLEN - 1);
                kernel_filepath[FILEPATH_MAXLEN - 1] = '\0';
                break;
            case 'r':
                strncpy(rootfs_filepath, optarg, FILEPATH_MAXLEN - 1);
                rootfs_filepath[FILEPATH_MAXLEN - 1] = '\0';
                break;
            case 'v':
                strncpy(version_filepath, optarg, FILEPATH_MAXLEN - 1);
                version_filepath[FILEPATH_MAXLEN - 1] = '\0';
                break;
            case 'u':
                strncpy(upgrade_filepath, optarg, FILEPATH_MAXLEN - 1);
                upgrade_filepath[FILEPATH_MAXLEN - 1] = '\0';
                break;
            case '?':
                printf("unknown option %c\n", optopt);
                ret = -EINVAL;
                break;
            default:
                break;
        }
        opt = getopt(argc, argv, "k:r:v:u:");
    }

    return ret;
}

void print_usage(void)
{
    printf("buildversion help\n");
    printf("  -k <kernel image>   : specify kernel image filepath\n");
    printf("  -r <rootfs image>   : specify rootfs image filepath\n");
    printf("  -v <version file>   : specify whole image filepath\n");
    printf("  -u <upgrade file>   : specify upgrade filepath\n");

    return ;
}
