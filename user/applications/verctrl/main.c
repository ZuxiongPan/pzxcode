#include <stdio.h>
#include <string.h>
#include <linux/errno.h>

static void print_usage(void);
extern int version_sync(void);

int main(int argc, char *argv[])
{
    int ret = 0;
    if(argc < 2)
    {
        print_usage();
        return -EINVAL;
    }

    if(!strncmp(argv[1], "-sync", sizeof("-sync")))
    {
        ret = version_sync();
        printf("synchonize version return %d\n", ret);
    }

    return ret;
}

static void print_usage(void)
{
    printf("verctrl usage\n");
    printf("  -sync : start synchonize version\n");

    return ;
}
