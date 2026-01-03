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
char rsakey_filepath[FILEPATH_MAXLEN] = {0};

int get_options(int argc, char *const *argv);
void print_usage(void);
int build_upgrade_file(void);
int build_version_file(void);

extern int rsa_sign(char *filepath, char *keypath);

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

    ret = rsa_sign(upgrade_filepath, rsakey_filepath);
    if(ret != 0)
    {
        printf("sign upgrade file %s error\n", upgrade_filepath);
        return ret;
    }

    if(0 == strlen(version_filepath))
    {
        printf("do not create version file\n");
        return 0;
    }

    ret = build_version_file();
    if(ret != 0)
    {
        printf("build version file %s error\n", version_filepath);
        return ret;
    }
    
    return ret;
}

static void version_header_init(struct version_header *pheader)
{
    // pheader is valid, do not check
    pheader->magic[0] = VERSION_HEADER_MAGIC0;
    pheader->magic[1] = VERSION_HEADER_MAGIC1;
    pheader->header_version = VERSION_HEADER_VERNUM;
    pheader->kpart_size = KERNEL_PARTITION_SIZE;
    pheader->kernel_size = 0;
    pheader->rpart_size = ROOTFS_PARTITION_SIZE;
    pheader->rootfs_size = 0;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(pheader->build_date, sizeof(pheader->build_date), "%04u%02u%02u%02u%02u%02u", 
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    snprintf(pheader->soft_version, sizeof(pheader->soft_version), VERSION_NUMBER);

    return ;
}

int build_upgrade_file(void)
{
    FILE *upgrade = NULL;
    FILE *kernel = NULL;
    FILE *rootfs = NULL;
    unsigned int file_size = 0;
    unsigned char *buf = NULL;
    unsigned char headbuf[STORDEV_PHYSICAL_BLKSIZE];
    memset(headbuf, 0xff, sizeof(headbuf));
    struct version_header *pheader = (struct version_header *)headbuf;
    version_header_init(pheader);

    buf = malloc(STORDEV_PHYSICAL_BLKSIZE);
    if(NULL == buf)
    {
        printf("cannot get %u Bytes memory\n", STORDEV_PHYSICAL_BLKSIZE);
        return -ENOMEM;
    }

    /**
     * upgrade file content:
     * signature(one block) + header(one block) + kernel + rootfs
     */
    upgrade = fopen(upgrade_filepath, "wb+");
    if(NULL == upgrade)
    {
        printf("file %s create failed\n", upgrade_filepath);
        free(buf);
        return -EACCES;
    }

    kernel = fopen(kernel_filepath, "rb");
    if(NULL == kernel)
    {
        printf("file %s is not found, please check\n", kernel_filepath);
        fclose(upgrade);
        free(buf);
        return -EACCES;
    }

    printf("!!! write kernel image to upgrade file start ...\n");
    fseek(upgrade, KERNEL_OFFSET, SEEK_SET);
    fseek(kernel, 0, SEEK_SET);
    memset(buf, 0, STORDEV_PHYSICAL_BLKSIZE);
    while(fread(buf, 1, STORDEV_PHYSICAL_BLKSIZE, kernel) > 0)
    {
        fwrite(buf, 1, STORDEV_PHYSICAL_BLKSIZE, upgrade);
        pheader->kernel_size += STORDEV_PHYSICAL_BLKSIZE;
        memset(buf, 0, STORDEV_PHYSICAL_BLKSIZE);
    }
    printf("... write kernel image to upgrade file end, kernel size %u !!!\n",
        pheader->kernel_size);
    fclose(kernel);

    rootfs = fopen(rootfs_filepath, "rb");
    if(NULL == rootfs)
    {
        printf("file %s is not found, please check\n", rootfs_filepath);
        fclose(upgrade);
        free(buf);
        return -EACCES;
    }

    printf("!!! write rootfs image to upgrade file start ...\n");
    fseek(upgrade, KERNEL_PARTITION_SIZE, SEEK_SET);
    fseek(rootfs, 0, SEEK_SET);
    memset(buf, 0, STORDEV_PHYSICAL_BLKSIZE);
    while(fread(buf, 1, STORDEV_PHYSICAL_BLKSIZE, rootfs) > 0)
    {
        fwrite(buf, 1, STORDEV_PHYSICAL_BLKSIZE, upgrade);
        pheader->rootfs_size += STORDEV_PHYSICAL_BLKSIZE;
        memset(buf, 0, STORDEV_PHYSICAL_BLKSIZE);
    }
    printf("... write rootfs image to upgrade file end, rootfs size %u !!!\n",
        pheader->rootfs_size);
    fclose(rootfs);
    free(buf);

    fseek(upgrade, VERSION_HEADER_OFFSET, SEEK_SET);
    fwrite(headbuf, 1, STORDEV_PHYSICAL_BLKSIZE, upgrade);

    fclose(upgrade);
    // until here, the first 512Bytes of version.bin is empty
    file_size = KERNEL_OFFSET + pheader->kernel_size + pheader->rootfs_size;
    if(file_size > VERSION_PARTITION_SIZE)
    {
        printf("upgrade file size is %u, larger than partition\n", file_size);
        return -EINVAL;
    }

    return 0;
}

int build_version_file(void)
{
    FILE *version = NULL;
    FILE *upgrade = NULL;
    unsigned char *buf = NULL;
    unsigned int upgrade_size = VERSION_PARTITION_SIZE;
    unsigned int rdsize = 0;

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
    rdsize = fread(buf, 1, upgrade_size, upgrade);
    printf("upgrade file real size is %u\n", rdsize);
    fclose(upgrade);
    
    printf("write upgrade file to image1\n");
    fseek(version, VERSION0_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    printf("write upgrade file to image2\n");
    fseek(version, VERSION1_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    free(buf);
    fclose(version);

    return 0;
}

int get_options(int argc, char *const *argv)
{
    extern char *optarg;
    extern int optopt;
    int opt = getopt(argc, argv, "k:r:v:u:p:");
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
            case 'p':
                strncpy(rsakey_filepath, optarg, FILEPATH_MAXLEN - 1);
                rsakey_filepath[FILEPATH_MAXLEN - 1] = '\0';
                break;
            case '?':
                printf("unknown option %c\n", optopt);
                ret = -EINVAL;
                break;
            default:
                break;
        }
        opt = getopt(argc, argv, "k:r:v:u:p:");
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
    printf("  -p <rsa key file>   : specify rsa key filepath\n");

    return ;
}
