#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/errno.h>

#define DMA_EDU2RAM 0
#define DMA_RAM2EDU 1
#define EDU_IOC_MAGIC 'e'
#define EDU_IOC_VER _IO(EDU_IOC_MAGIC, 1)
#define EDU_IOC_FACT _IOR(EDU_IOC_MAGIC, 2, unsigned int)
#define EDU_IOC_DMA _IOWR(EDU_IOC_MAGIC, 3, struct edu_dma_req)

struct edu_dma_req {
    unsigned char dir;
    unsigned int len;
    void *buf;
};

int main(int argc, const char *argv[])
{
    int ret = 0;
    int fd = open("/dev/qemu_edu", O_RDWR);
    if(fd < 0)
    {
        perror("open /dev/qemu_edu");
        return -EACCES;
    }

    if((2 == argc) && !strcmp("ver", argv[1]))
    {
        ret = ioctl(fd, EDU_IOC_VER, NULL);
        if(ret < 0)
        {
            perror("get edu version failed\n");
        }
        goto out;
    }
    else if((3 == argc) && !strcmp("fact", argv[1]))
    {
        unsigned int num = atoi(argv[2]);
        num = num > 12 ? 12 : num;
        ret = ioctl(fd, EDU_IOC_FACT, &num);
        if(ret < 0)
        {
            perror("calculate factorial failed\n");
        }
        goto out;
    }
    else if((3 == argc) && !strcmp("dma", argv[1]) && !strcmp("read", argv[2]))
    {
        char rbuf[128];
        struct edu_dma_req req = { DMA_EDU2RAM, sizeof(rbuf), rbuf };
        ret = ioctl(fd, EDU_IOC_DMA, &req);
        if(ret < 0)
        {
            perror("dma read from device failed\n");
        }
        else
        {
            for(int i = 0; i < 128; i++)
            {
                if(0 == rbuf[i])
                {
                    break;
                }
                printf("%c", rbuf[i]);
            }
        }
        goto out;
    }
    else if((4 == argc) && !strcmp("dma", argv[1]) && !strcmp("write", argv[2]))
    {
        struct edu_dma_req req = { DMA_RAM2EDU, strlen(argv[3]), argv[3] };
        ret = ioctl(fd, EDU_IOC_DMA, &req);
        if(ret < 0)
        {
            perror("dma read from device failed\n");
        }
        goto out;
    }
    else
    {
        printf("invalid command\n");
        ret = -EINVAL;
    }

out:
    close(fd);
    return ret;
}