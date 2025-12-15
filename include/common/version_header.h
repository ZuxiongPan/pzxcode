#ifndef __VERSION_HEADER_H__
#define __VERSION_HEADER_H__

#define VERSION_HEADER_MAGIC0 0x55555555
#define VERSION_HEADER_MAGIC1 0xaaaaaaaa

#define SIGN_HEADER_MAGIC0 0x4e474953  // 'SIGN'
#define SIGN_HEADER_MAGIC1 0x44414548  // 'HEAD'
#define SIGN_HASH_SHA256 1
#define SIGN_RSA2048 1
#define SIGN_PADDING_PKCS15 1
#define RSA2048_SIGN_LEN 256

// version header numbers 0xrrMMmmpp
// r-reserved M-Major m-minor p-patch
#define VERSION_HEADER_VERNUM 0x00010000
#define SIGN_HEADER_VERNUM 0x00010000

#define VERSION_NUMBERS 2

struct version_header {
    unsigned int magic[2];

    unsigned int header_version;
    unsigned int header_size;
    unsigned int kernel_size;
    unsigned int kernel_crc;
    unsigned int rootfs_size;
    unsigned int rootfs_crc;

    char build_date[16];    // according to date decide boot version
    char soft_version_number[32];

    unsigned int header_crc;    // do not calculate crc
};

struct signature_header {
    unsigned int magic[2];
    unsigned int header_version;
    unsigned int header_size;

    unsigned int hash_algo;
    unsigned int sign_algo;
    unsigned int padding;
    unsigned int signed_data_size;
    
    unsigned char signature[RSA2048_SIGN_LEN];

    unsigned int header_crc;    // do not calculate crc
};

#endif