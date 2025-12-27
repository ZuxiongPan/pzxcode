#ifndef __VERSION_HEADER_H__
#define __VERSION_HEADER_H__

#define VERSION_HEADER_MAGIC0 0x53524556  // 'VERS'
#define VERSION_HEADER_MAGIC1 0x534e4f49  // 'IONS'

#define SIGN_HEADER_MAGIC0 0x4e474953  // 'SIGN'
#define SIGN_HEADER_MAGIC1 0x44414548  // 'HEAD'

// version header numbers 0xrrMMmmpp
// r-reserved M-Major m-minor p-patch
#define VERSION_HEADER_VERNUM 0x00010000
#define SIGN_HEADER_VERNUM 0x00010000
#define VERNUM_RESERVE(vernum) (((vernum) & 0xff000000) >> 24)
#define VERNUM_MAJOR(vernum) (((vernum) & 0x00ff0000) >> 16)
#define VERNUM_MINOR(vernum) (((vernum) & 0x0000ff00) >> 8)
#define VERNUM_PATCH(vernum) ((vernum) & 0x000000ff)

#define VERSION_COUNTS 2

struct version_header {
    unsigned int magic[2];

    unsigned int header_version;
    unsigned int kpart_size;
    unsigned int kernel_size;
    unsigned int rpart_size;
    unsigned int rootfs_size;

    char build_date[16];    // according to date decide boot version
    char soft_version[32];
};

struct signature_header {
    unsigned int magic[2];

    unsigned int header_version;
    unsigned int signed_data_size;

    unsigned int header_crc;    // do not calculate crc
};

#endif