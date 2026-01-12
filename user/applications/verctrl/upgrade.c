#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/errno.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "common/version_info.h"
#include "common/version_header.h"
#include "common/version_partition.h"

#define PUBKEY_FILEPATH "/etc/pzx.pub"

extern int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize);
extern uint32_t pzx_crc32(const uint8_t *data, uint32_t length);

#ifdef CONFIG_UPGRADE_FRAGMENT
static int upgrade_fragment(char *upgfile_name)
{
    int ret = 0;
    int ufd = 0; // upgrde file fd
    int dfd = 0; // device fd
    char buf[16] = {0};
    bool rdok = true;
    uint8_t *verbuf = NULL;
    uint8_t sighead_buf[VERSION_HEADER_OFFSET];
    uint32_t signed_size = 0, rdbytes = 0, crc = 0;
    int toread = 0;
    const struct signature_header *sighead = NULL;
    unsigned int offset = 0;
    unsigned char hash[32];
    struct stat upg_stat = {0};
    mbedtls_sha256_context sha_ctx;
    mbedtls_pk_context pk;

    memset(buf, 0, sizeof(buf));
    ret = get_value_from_verinfo(PROC_BACKVEROFF_NAME, buf, sizeof(buf));
    if(!ret)
    {
        printf("get %s failed\n", PROC_BACKVEROFF_NAME);
        return -EINVAL;
    }
    if(sscanf(buf, "0x%x", &offset) != 1)
    {
        printf("invalid version offset %s\n", buf);
        return -EINVAL;
    }

    ufd = open(upgfile_name, O_RDONLY);
    if(ufd < 0)
    {
        printf("open %s failed\n", upgfile_name);
        return -ENOENT;
    }

    ret = fstat(ufd, &upg_stat);
    if(ret < 0 || upg_stat.st_size > VERSION_PARTITION_SIZE)
    {
        printf("get file %s state failed\n", upgfile_name);
        close(ufd);
        return -EACCES;
    }

    lseek(ufd, 0, SEEK_SET);
    ret = read(ufd, sighead_buf, VERSION_HEADER_OFFSET);
    if(VERSION_HEADER_OFFSET != ret)
    {
        printf("read %u/0x%x bytes from file %s failed, real readlen %u/0x%x\n", 
            VERSION_HEADER_OFFSET, VERSION_HEADER_OFFSET, upgfile_name, ret, ret);
        close(ufd);
        return -EIO;
    }
    printf("read %u/0x%x bytes from file %s\n", ret, ret, upgfile_name);

    // check signature and write
    sighead = (struct signature_header *)sighead_buf;
    if(SIGN_HEADER_MAGIC0 != sighead->magic[0] || SIGN_HEADER_MAGIC1 != sighead->magic[1])
    {
        printf("signature header is invalid, value: 0x%x, 0x%x\n",
            sighead->magic[0], sighead->magic[1]);
        return false;
    }
    crc = pzx_crc32(sighead_buf, sizeof(struct signature_header) - sizeof(uint32_t));
    printf("signature header crc is 0x%x, calculated crc is 0x%x\n", sighead->header_crc, crc);
    if(crc != sighead->header_crc)
    {
        printf("upgrade file signature is invalid\n");
        close(ufd);
        return -EPROTO;
    }

    dfd = open(STORDEV_NAME, O_RDWR);
    if(dfd < 0)
    {
        printf("open storage device failed\n");
        close(ufd);
        return -ENOENT;
    }
    lseek(dfd, offset, SEEK_SET);
    ret = write(dfd, sighead_buf, VERSION_HEADER_OFFSET);
    printf("write %u bytes to device %s ret %u\n", VERSION_HEADER_OFFSET, STORDEV_NAME, ret);

    signed_size = sighead->signed_size;
    lseek(ufd, VERSION_HEADER_OFFSET, SEEK_SET);
    verbuf = malloc(FRAGMENT_SIZE);
    if(NULL == verbuf)
    {
        printf("get fragment buffer faied\n");
        close(ufd);
        close(dfd);
        return -ENOMEM;
    }

    // check and write
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    while(rdbytes < signed_size)
    {
        toread = (signed_size - rdbytes > FRAGMENT_SIZE) ?
            FRAGMENT_SIZE : (signed_size - rdbytes);
        ret = read(ufd, verbuf, toread);
        if(ret != toread)
        {
            rdok = false;
            break;
        }
        mbedtls_sha256_update(&sha_ctx, verbuf, toread);
        rdbytes += toread;
        ret = write(dfd, verbuf, toread);
    }
    printf("write %u bytes to device %s ret %u\n", rdbytes, STORDEV_NAME, ret);

    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);
    close(ufd);
    close(dfd);
    free(verbuf);

    if(!rdok)
    {
        printf("read file %s failed, already read %u/0x%x bytes\n", upgfile_name, rdbytes, rdbytes);
        return -EIO;
    }

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, PUBKEY_FILEPATH);
    if(ret)
    {
        printf("failed get pub key from file %s, ret %d\n", PUBKEY_FILEPATH, ret);
        mbedtls_pk_free(&pk);
        return ret;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0,
        sighead->signature, sighead->sig_size);
    if(ret)
    {
        printf("rsa verify failed, ret %d\n", ret);
    }
    else
    {
        printf("rsa verify success\n");
    }

    mbedtls_pk_free(&pk);
    return ret;
}

#else

static int signature_header_check(const uint8_t *buf)
{
    uint32_t crc = 0;
    const struct signature_header *sighead = (struct signature_header *)buf;

    if(SIGN_HEADER_MAGIC0 != sighead->magic[0] || SIGN_HEADER_MAGIC1 != sighead->magic[1])
    {
        printf("signature header is invalid, value: 0x%x, 0x%x\n",
            sighead->magic[0], sighead->magic[1]);
        return false;
    }

    crc = pzx_crc32(buf, sizeof(struct signature_header) - sizeof(uint32_t));
    printf("signature header crc is 0x%x, calculated crc is 0x%x\n", sighead->header_crc, crc);

    return (crc == sighead->header_crc);
}

static int upgrade_version_check_normal(const uint8_t *buf, uint32_t size)
{
    int ret = signature_header_check(buf);
    if(!ret)
    {
        printf("upgrade file signature is invalid\n");
        return -EPROTO;
    }

    mbedtls_pk_context pk;
    unsigned char hash[32];
    const struct signature_header *sighead = (struct signature_header *)buf;

    ret = mbedtls_sha256_ret(buf + VERSION_HEADER_OFFSET, size - VERSION_HEADER_OFFSET, hash, 0);
    if(ret)
    {
        printf("sha256 calculation failed, ret %d\n", ret);
        return ret;
    }

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, PUBKEY_FILEPATH);
    if(ret)
    {
        printf("failed get pub key from file %s, ret %d\n", PUBKEY_FILEPATH, ret);
        mbedtls_pk_free(&pk);
        return ret;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0,
        sighead->signature, sighead->sig_size);
    if(ret)
    {
        printf("rsa verify failed, ret %d\n", ret);
    }
    else
    {
        printf("rsa verify success\n");
    }

    mbedtls_pk_free(&pk);
    return ret;
}

static int upgrade_normal(char *upgfile_name)
{
    int ret = 0;
    int fd = 0;
    char buf[16] = {0};
    uint8_t *verbuf = NULL;
    unsigned int offset = 0;
    struct stat upg_stat = {0};

    memset(buf, 0, sizeof(buf));
    ret = get_value_from_verinfo(PROC_BACKVEROFF_NAME, buf, sizeof(buf));
    if(!ret)
    {
        printf("get %s failed\n", PROC_BACKVEROFF_NAME);
        return -EINVAL;
    }
    if(sscanf(buf, "0x%x", &offset) != 1)
    {
        printf("invalid version offset %s\n", buf);
        return -EINVAL;
    }

    fd = open(upgfile_name, O_RDONLY);
    if(fd < 0)
    {
        printf("open %s failed\n", upgfile_name);
        return -ENOENT;
    }

    ret = fstat(fd, &upg_stat);
    if(ret < 0 || upg_stat.st_size > VERSION_PARTITION_SIZE)
    {
        printf("get file %s state failed\n", upgfile_name);
        close(fd);
        return -EACCES;
    }

    verbuf = malloc(upg_stat.st_size);
    if(NULL == verbuf)
    {
        printf("there is no enough memory for upgrade\n");
        close(fd);
        return -ENOMEM;
    }

    lseek(fd, 0, SEEK_SET);
    ret = read(fd, verbuf, upg_stat.st_size);
    if(upg_stat.st_size != ret)
    {
        printf("read %lu/0x%lx bytes from file %s failed, real readlen %u/0x%x\n", 
            upg_stat.st_size, upg_stat.st_size, upgfile_name, ret, ret);
        free(verbuf);
        close(fd);
        return -EIO;
    }
    printf("read %u/0x%x bytes from file %s\n", ret, ret, upgfile_name);
    close(fd);

    if(upgrade_version_check_normal(verbuf, upg_stat.st_size))
    {
        printf("check version failed\n");
        free(verbuf);
        return -ECANCELED;
    }

    fd = open(STORDEV_NAME, O_RDWR);
    if(fd < 0)
    {
        printf("open storage device failed\n");
        free(verbuf);
        return -ENOENT;
    }
    lseek(fd, offset, SEEK_SET);
    ret = write(fd, verbuf, upg_stat.st_size);
    printf("write %u/0x%x bytes to offset 0x%x\n", ret, ret, offset);

    free(verbuf);
    close(fd);
    return 0;
}
#endif

int upgrade(char *upgfile_name)
{
#ifdef CONFIG_UPGRADE_FRAGMENT
    return upgrade_fragment(upgfile_name);
#else
    return upgrde_normal(upgfile_name);
#endif
}