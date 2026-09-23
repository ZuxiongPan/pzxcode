#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/errno.h>
#include "verctrl.h"
#include "common/version_info.h"
#include "common/version_header.h"
#include "common/version_partition.h"

#define MEGABYTES (1024 * 1024)

int version_sync(void)
{
    int ret = 0;
    int fd = 0;
    char buf[16] = {0};
    uint8_t *verbuf = NULL;
    unsigned int curoff = 0;
    unsigned int backoff = 0;
    int total = 0;

    inform_to_armd(UPG_BEGIN);
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

    inform_to_armd(UPG_WRITING);
    fd = open(IMGSTOR_DEVNAME, O_RDWR);
    if(fd < 0)
    {
        printf("open %s failed\n", IMGSTOR_DEVNAME);
        return -ENOENT;
    }

    verbuf = malloc(MEGABYTES);
    if(NULL == verbuf)
    {
        printf("there is no enough memory for sync\n");
        close(fd);
        return -ENOMEM;
    }

    while (total < VERSION_PARTITION_SIZE)
    {
        lseek(fd, curoff + total, SEEK_SET);
        ret = read(fd, verbuf, MEGABYTES);
        if (ret < 0)
        {
            printf("read from current version failed\n");
            break;
        }
        lseek(fd, backoff + total, SEEK_SET);
        ret = write(fd, verbuf, ret);
        if(ret < 0)
        {
            printf("write to backup version failed\n");
            break;
        }
        total += ret;
    }
    printf("write %u/0x%x bytes from offset 0x%x to offset 0x%x\n", total, total, curoff, backoff);
    if (total != VERSION_PARTITION_SIZE)
    {
        inform_to_armd(UPG_WRITE_FAILED);
    }
    else
    {
        inform_to_armd(UPG_SUCCESS);
    }

    free(verbuf);
    close(fd);
    return 0;
}
