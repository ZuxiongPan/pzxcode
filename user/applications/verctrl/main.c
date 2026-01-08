#include <stdio.h>
#include <string.h>
#include <linux/errno.h>

static void print_usage(void);
extern int version_sync(void);
extern int upgrade(char *upgfile_name);

int main(int argc, char *argv[])
{
    int ret = 0;
    if(argc < 2)
    {
        print_usage();
        return -EINVAL;
    }

    if(!strncmp(argv[1], "--sync", sizeof("--sync")))
    {
        ret = version_sync();
        printf("synchonize version return %d\n", ret);
    }
    else if(!strncmp(argv[1], "--upgrade", sizeof("--upgrade")) &&
        NULL != argv[2])
    {
        ret = upgrade(argv[2]);
        printf("upgrade %s ret %d\n", argv[2], ret);
    }
    else
    {
        print_usage();
    }

    return ret;
}

static void print_usage(void)
{
    printf("verctrl usage\n");
    printf("  --sync : start synchonize version\n");
    printf("  --upgrade [file] : upgrade [file] to back partition\n");

    return ;
}
