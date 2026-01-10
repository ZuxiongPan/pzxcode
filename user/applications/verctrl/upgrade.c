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

static int upgrade_version_check(const uint8_t *buf, uint32_t size)
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

int upgrade(char *upgfile_name)
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

    if(upgrade_version_check(verbuf, upg_stat.st_size))
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