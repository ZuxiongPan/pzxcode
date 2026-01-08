#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/errno.h>
#include "common/version_info.h"
#include "common/version_header.h"
#include "common/version_partition.h"

extern int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize);

static int simple_check_version(const unsigned char *buf)
{
    bool ret = false;
    struct signature_header *sighead = (struct signature_header *)buf;
    struct version_header *verhead = (struct version_header *)(buf + VERSION_HEADER_OFFSET);

    if(SIGN_HEADER_MAGIC0 == sighead->magic[0] && SIGN_HEADER_MAGIC1 == sighead->magic[1]
        && VERSION_HEADER_MAGIC0 == verhead->magic[0] && VERSION_HEADER_MAGIC1 == verhead->magic[1])
    {
        printf("this version is valid\n");
        ret = true;
    }
    else
    {
        printf("this version is invalid\n");
        ret = false;
    }

    return ret;
}

int version_sync(void)
{
    int ret = 0;
    int fd = 0;
    char buf[16] = {0};
    unsigned char *verbuf = NULL;
    unsigned int curoff = 0;
    unsigned int backoff = 0;

    // get version offset in storage device
    memset(buf, 0, sizeof(buf));
    ret = get_value_from_verinfo(PROC_CURVEROFF_NAME, buf, sizeof(buf));
    if(!ret)
    {
        printf("get %s failed\n", PROC_CURVEROFF_NAME);
        return -EINVAL;
    }
    if(sscanf(buf, "0x%x", &curoff) != 1)
    {
        printf("invalid version offset %s\n", buf);
        return -EINVAL;
    }

    memset(buf, 0, sizeof(buf));
    ret = get_value_from_verinfo(PROC_BACKVEROFF_NAME, buf, sizeof(buf));
    if(!ret)
    {
        printf("get %s failed\n", PROC_BACKVEROFF_NAME);
        return -EINVAL;
    }
    if(sscanf(buf, "0x%x", &backoff) != 1)
    {
        printf("invalid version offset %s\n", buf);
        return -EINVAL;
    }

    fd = open(STORDEV_NAME, O_RDWR);
    if(fd < 0)
    {
        printf("open %s failed\n", STORDEV_NAME);
        return -ENOENT;
    }

    verbuf = malloc(VERSION_PARTITION_SIZE);
    if(NULL == verbuf)
    {
        printf("there is no enough memory for sync\n");
        close(fd);
        return -ENOMEM;
    }

    lseek(fd, curoff, SEEK_SET);
    ret = read(fd, verbuf, VERSION_PARTITION_SIZE);
    if(VERSION_PARTITION_SIZE != ret)
    {
        printf("read %u/0x%x bytes from offset 0x%x failed, real readlen %u/0x%x\n", 
            VERSION_PARTITION_SIZE, VERSION_PARTITION_SIZE, curoff, ret, ret);
        free(verbuf);
        close(fd);
        return -EIO;
    }
    printf("read %u/0x%x bytes from offset 0x%x\n", ret, ret, curoff);

    if(!simple_check_version(verbuf))
    {
        printf("cannot synchronize version\n");
        free(verbuf);
        close(fd);
        return -ECANCELED;
    }

    lseek(fd, backoff, SEEK_SET);
    ret = write(fd, verbuf, VERSION_PARTITION_SIZE);
    printf("write %u/0x%x bytes to offset 0x%x\n", ret, ret, backoff);

    free(verbuf);
    close(fd);
    return 0;
}