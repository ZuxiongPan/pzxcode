#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <linux/errno.h>

#include "common/version_partition.h"
#include "common/version_header.h"
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
int rsasign_upgrade_file(void);

int main(int argc, char *argv[])
{
    int ret = 0;

    ret = get_options(argc, argv);
    if(ret != 0)
    {
        print_usage();
        return ret;
    }

    ret = build_upgrade_file();
    if(ret != 0)
    {
        printf("build upgrade file %s error\n", upgrade_filepath);
        return ret;
    }

    ret = rsasign_upgrade_file();
    if(ret != 0)
    {
        printf("rsa sign file %s failed\n", upgrade_filepath);
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
    pheader->magic[0] = VERSION_HEADER_MAGIC0;
    pheader->magic[1] = VERSION_HEADER_MAGIC1;
    pheader->header_version = VERSION_HEADER_VERNUM;
    pheader->header_size = sizeof(struct version_header);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(pheader->build_date, sizeof(pheader->build_date), "%04u%02u%02u%02u%02u%02u", 
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    snprintf(pheader->soft_version_number, sizeof(pheader->soft_version_number), VERSION_NUMBER);

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
    printf("write %u blocks, crc 0x%08x\n", blk_num, crc);

    return crc;
}

int build_upgrade_file(void)
{
    FILE *upgrade = NULL;
    FILE *kernel = NULL;
    FILE *rootfs = NULL;

    unsigned char headbuf[STORDEV_PHYSICAL_BLKSIZE];
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
     * upgrade file content:
     * signature(one block) + header(one block) + kernel + rootfs
     * 1. write kernel to upgrade & update version upgrade
     * 2. write rootfs to upgrade & update version upgrade
     */
    printf("!!! write kernel image to upgrade file start ...\n");
    pheader->kernel_crc = write_file_aligned(kernel, upgrade, 
        ALL_HEADERS_SIZE, &pheader->kernel_size);
    printf("... write kernel finish, kernel size is %d, kernel crc is 0x%08x !!!\n", 
        pheader->kernel_size, pheader->kernel_crc);

    printf("!!! write rootfs image to upgrade file start ...\n");
    pheader->rootfs_crc = write_file_aligned(rootfs, upgrade, 
        KERNEL_PARTITION_SIZE, &pheader->rootfs_size);
    printf("... write rootfs finish, rootfs size is %d, rootfs crc is 0x%08x !!!\n", 
        pheader->rootfs_size, pheader->rootfs_crc);

    pheader->header_crc = pzx_crc32((const unsigned char *)pheader,
        sizeof(struct version_header) - sizeof(unsigned int));
    printf("... header crc 0x%08x !!!\n", pheader->header_crc);
    fseek(upgrade, VERSION_HEADER_OFFSET, SEEK_SET);
    fwrite(headbuf, 1, STORDEV_PHYSICAL_BLKSIZE, upgrade);

    fclose(kernel);
    fclose(rootfs);
    fclose(upgrade);

    // until here, the first 512Bytes of version.bin is empty
    return 0;
}

int rsasign_upgrade_file(void)
{
    FILE *upgrade = NULL;
    unsigned char sigbuf[STORDEV_PHYSICAL_BLKSIZE];
    unsigned char hash[32];
    unsigned int signed_size = 0;
    memset(sigbuf, 0, STORDEV_PHYSICAL_BLKSIZE);
    struct signature_header *pheader = (struct signature_header *)sigbuf;

    upgrade = fopen(upgrade_filepath, "rb+");
    if(NULL == upgrade)
    {
        printf("file %s is not found, please check\n", upgrade_filepath);
        return -EACCES;
    }

    fseek(upgrade, 0, SEEK_END);
    signed_size = ftell(upgrade);
    signed_size -= STORDEV_PHYSICAL_BLKSIZE; // sign header do not verify

    //rsa_sign_buffer(upgrade, sizeof(struct signature_header), signed_size, hash, pheader->signature);
    pheader->magic[0] = SIGN_HEADER_MAGIC0;
    pheader->magic[1] = SIGN_HEADER_MAGIC1;
    pheader->header_version = SIGN_HEADER_VERNUM;
    pheader->header_size = sizeof(struct signature_header);
    pheader->hash_algo = SIGN_HASH_SHA256;
    pheader->sign_algo = SIGN_RSA2048;
    pheader->padding = SIGN_PADDING_PKCS15;
    pheader->signed_data_size = signed_size;
    pheader->header_crc = pzx_crc32((const unsigned char *)pheader,
        sizeof(struct signature_header) - sizeof(unsigned int));

    fseek(upgrade, 0, SEEK_SET);
    fwrite(sigbuf, 1, STORDEV_PHYSICAL_BLKSIZE, upgrade);

    fclose(upgrade);

    return 0;
}

int build_version_file(void)
{
    FILE *version = NULL;
    FILE *upgrade = NULL;
    unsigned char *buf = NULL;
    unsigned int upgrade_size = VERSION_PARTITION_SIZE;

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
    fseek(version, VERSION1_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    printf("write upgrade file to image2\n");
    fseek(version, VERSION2_PARTITION_OFFSET, SEEK_SET);
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
