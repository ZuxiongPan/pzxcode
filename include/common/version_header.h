#ifndef __VERSION_HEADER_H__
#define __VERSION_HEADER_H__

#define VERSION_HEADER_MAGIC0 0x33333333
#define VERSION_HEADER_MAGIC1 0x55555555
#define VERSION_HEADER_MAGIC2 0xaaaaaaaa
#define VERSION_HEADER_MAGIC3 0xcccccccc

#define VERSION_NUMBERS 2

struct common_version_header {
    unsigned int magic[4];

    unsigned int kernel_size;
    unsigned int kernel_phyblks;
    unsigned int kernel_crc;
    unsigned int rootfs_size;
    unsigned int rootfs_phyblks;
    unsigned int rootfs_crc;

    char build_date[16];    // according to date decide boot version
    char soft_version_number[32];
};

struct version_header {
    struct common_version_header common;
    unsigned int header_crc;
};

#endif