#ifndef __VERSION_HEADER_H__
#define __VERSION_HEADER_H__

#include "data_type.h"

#define VERSION_HEADER_MAGIC0 0x53524556  // 'VERS'
#define VERSION_HEADER_MAGIC1 0x534e4f49  // 'IONS'

#define SIGN_HEADER_MAGIC0 0x4e474953  // 'SIGN'
#define SIGN_HEADER_MAGIC1 0x44414548  // 'HEAD'

// version header numbers 0xrrMMmmpp
// r-reserved M-Major m-minor p-patch
#define VERSION_HEADER_VERNUM 0x00010000
#define SIGN_HEADER_VERNUM 0x00020000
#define VERNUM_RESERVE(vernum) (((vernum) & 0xff000000) >> 24)
#define VERNUM_MAJOR(vernum) (((vernum) & 0x00ff0000) >> 16)
#define VERNUM_MINOR(vernum) (((vernum) & 0x0000ff00) >> 8)
#define VERNUM_PATCH(vernum) ((vernum) & 0x000000ff)

#define VERSION_COUNTS 2
#define RSASIGN_NAME "sha256,rsa2048"

struct version_header {
    uint32_t magic[2];

    uint32_t header_version;
    uint32_t kpart_size;
    uint32_t kernel_size;
    uint32_t rpart_size;
    uint32_t rootfs_size;

    char build_date[16];    // according to date decide boot version
    char soft_version[32];
};

struct signature_header {
    uint32_t magic[2];

    uint32_t header_version;
    uint32_t signed_size;
    uint32_t sig_size;
    uint8_t signature[256];
    uint8_t aes_iv[16];

    uint32_t header_crc;    // do not calculate crc
};

#endif