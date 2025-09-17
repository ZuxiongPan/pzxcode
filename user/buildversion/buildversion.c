#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "common/version_partition.h"
#include "common/version_header.h"
#include "common/pzx_crc32.h"

#define FILEPATH_MAXLEN 256

char kernel_filepath[FILEPATH_MAXLEN] = {0};
char rootfs_filepath[FILEPATH_MAXLEN] = {0};
char version_filepath[FILEPATH_MAXLEN] = {0};
char upgrade_filepath[FILEPATH_MAXLEN] = {0};

int get_options(int argc, char *const *argv);
void print_usage(void);
void header_init(struct version_header *pheader);
unsigned int write_file_aligned(FILE *in, FILE *out, unsigned int outpos, unsigned int *size);
int build_upgrade_file(void);
int build_version_file(void);

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

    ret = build_version_file();
    if(ret != 0)
    {
        printf("build version file %s error\n", version_filepath);
        return ret;
    }
    
    return 0;
}

void header_init(struct version_header *pheader)
{
    // pheader is valid, do not check
    pheader->common.magic[0] = VERSION_HEADER_MAGIC0;
    pheader->common.magic[1] = VERSION_HEADER_MAGIC1;
    pheader->common.magic[2] = VERSION_HEADER_MAGIC2;
    pheader->common.magic[3] = VERSION_HEADER_MAGIC3;

    pheader->common.header_index = 0;

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
    unsigned char buf[STORAGE_DEVICE_BLOCK_SIZE];
    unsigned int blk_num = 0;
    unsigned int crc = 0;

    memset(buf, 0, sizeof(buf));
    fseek(in, 0, SEEK_SET);
    fseek(out, outpos, SEEK_SET);

    while(fread(buf, 1, STORAGE_DEVICE_BLOCK_SIZE, in) > 0)
    {
        fwrite(buf, 1, STORAGE_DEVICE_BLOCK_SIZE, out);
        blk_num++;
        crc = pzx_crc32_segment(buf, STORAGE_DEVICE_BLOCK_SIZE, crc);
        memset(buf, 0, sizeof(buf));
    }

    *size = blk_num * STORAGE_DEVICE_BLOCK_SIZE;
    printf("write %u blocks, total size %u bytes, crc 0x%08x\n", blk_num, *size, crc);

    return crc;
}

int build_upgrade_file(void)
{
    FILE *upgrade = NULL;
    FILE *kernel = NULL;
    FILE *rootfs = NULL;

    struct version_header header;
    struct version_header *pheader = &header;
    memset(pheader, 0, sizeof(header));
    header_init(pheader);

    kernel = fopen(kernel_filepath, "rb");
    if(NULL == kernel)
    {
        printf("file %s is not found, please check\n", kernel_filepath);
        return -1;
    }

    rootfs = fopen(rootfs_filepath, "rb");
    if(NULL == rootfs)
    {
        printf("file %s is not found, please check\n", rootfs_filepath);
        fclose(kernel);
        return -1;
    }

    upgrade = fopen(upgrade_filepath, "wb+");
    if(NULL == upgrade)
    {
        printf("file %s create failed\n", upgrade_filepath);
        fclose(kernel);
        fclose(rootfs);
        return -1;
    }

    /**
     * upgrade structure: header(blk aligned) + kernel(blk aligned) + rootfs(blk aligned)
     * 1. write kernel to upgrade & update version upgrade
     * 2. write rootfs to upgrade & update version upgrade
     * 3. write header to upgrade
     */
    printf("------ write kernel image to upgrade file start ------\n");
    pheader->common.kernel_offset = VER_HEADER_BLOCK_SIZE;
    pheader->common.kernel_crc = write_file_aligned(kernel, upgrade, 
        pheader->common.kernel_offset, &pheader->common.kernel_size);
    printf("------ write kernel image to upgrade file finish ------\n");

    printf("------ write rootfs image to upgrade file start ------\n");
    pheader->common.rootfs_offset = KERNEL1_PARTITION_SIZE;
    pheader->common.rootfs_crc = write_file_aligned(rootfs, upgrade, 
        pheader->common.rootfs_offset, &pheader->common.rootfs_size);
    printf("------ write rootfs image to upgrade file finish ------\n");

    pheader->header_crc = pzx_crc32((const unsigned char *)pheader, sizeof(struct common_version_header));
    printf("header crc 0x%08x\n", pheader->header_crc);
    fseek(upgrade, 0, SEEK_SET);
    fwrite(pheader, 1, sizeof(*pheader), upgrade);

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
    unsigned int upgrade_size = 0;

    struct version_header header;
    struct version_header *pheader = &header;
    memset(pheader, 0, sizeof(header));

    upgrade = fopen(upgrade_filepath, "rb");
    if(NULL == upgrade)
    {
        printf("file %s is not found, please check\n", upgrade_filepath);
        return -1;
    }

    version = fopen(version_filepath, "rb+");
    if(NULL == version)
    {
        printf("file %s create failed\n", version_filepath);
        fclose(upgrade);
        return -1;
    }

    fseek(upgrade, 0, SEEK_SET);
    if(fread(pheader, 1, sizeof(*pheader), upgrade) < sizeof(*pheader))
    {
        printf("read upgrade file %s header failed\n", upgrade_filepath);
        fclose(upgrade);
        fclose(version);
        return -1;
    }

    upgrade_size = pheader->common.rootfs_offset + pheader->common.rootfs_size;
    buf = (unsigned char *)malloc(upgrade_size);
    if(NULL == buf)
    {
        printf("malloc %u bytes memory failed\n", upgrade_size);
        fclose(upgrade);
        fclose(version);
        return -1;
    }
    memset(buf, 0, upgrade_size);

    // write upgrade to version file
    fseek(upgrade, 0, SEEK_SET);
    if(fread(buf, 1, upgrade_size, upgrade) < upgrade_size)
    {
        printf("read upgrade file %s data failed\n", upgrade_filepath);
        free(buf);
        fclose(upgrade);
        fclose(version);
        return -1;
    }
    
    printf("write upgrade file to image1\n");
    fseek(version, KERNEL1_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    printf("write upgrade file to image2\n");
    fseek(version, KERNEL2_PARTITION_OFFSET, SEEK_SET);
    fwrite(buf, 1, upgrade_size, version);

    free(buf);
    fclose(upgrade);

    // update version header
    printf("update image1 header\n");
    pheader->common.kernel_offset = KERNEL1_PARTITION_OFFSET + VER_HEADER_BLOCK_SIZE;
    pheader->common.rootfs_offset = ROOTFS1_PARTITION_OFFSET;
    pheader->common.header_index = 1;   // set as start image
    pheader->header_crc = pzx_crc32((const unsigned char *)pheader, sizeof(struct common_version_header));
    fseek(version, KERNEL1_PARTITION_OFFSET, SEEK_SET);
    fwrite(pheader, 1, sizeof(*pheader), version);

    printf("update image2 header\n");
    pheader->common.kernel_offset = KERNEL2_PARTITION_OFFSET + VER_HEADER_BLOCK_SIZE;
    pheader->common.rootfs_offset = ROOTFS2_PARTITION_OFFSET;
    pheader->common.header_index = 2;   // set as backup image
    pheader->header_crc = pzx_crc32((const unsigned char *)pheader, sizeof(struct common_version_header));
    fseek(version, KERNEL2_PARTITION_OFFSET, SEEK_SET);
    fwrite(pheader, 1, sizeof(*pheader), version);

    fclose(version);

    return 0;
}

int get_options(int argc, char *const *argv)
{
    int opt = getopt(argc, argv, "k:r:v:u:");
    int ret = 0;
    
    while(opt != -1 && ret != -1)
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
                ret = -1;
                break;
            default:
                printf("unknown option %c\n", ret);
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
