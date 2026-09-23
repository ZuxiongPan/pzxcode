#include <stdio.h>
#include <string.h>
#include <linux/errno.h>
#include "verctrl.h"

static void print_usage(void);

int main(int argc, char *argv[])
{
    int ret = 0;
    if(argc < 2)
    {
        print_usage();
        return -EINVAL;
    }

    ret = init_uds_socket();
    if(ret < 0)
    {
        printf("init uds socket failed, cannot inform armd\n");
        return ret;
    }
    
    if(!strncmp(argv[1], "--sync", sizeof("--sync")))
    {
        ret = version_sync();
        printf("synchonize version return %d\n", ret);
        inform_to_armd(UPG_END);
    }
    else if(!strncmp(argv[1], "--upgrade", sizeof("--upgrade")))
    {
        ret = download_upgrade_file();
        if (ret < 0)
        {
            printf("download upgrade file failed\n");
        }
        else
        {
            ret = write_upgrade_file(DOWNLOAD_FILE_PATH);
        }
        inform_to_armd(UPG_END);
    }
    else
    {
        print_usage();
    }

    cleanup_uds_socket();
    return ret;
}

static void print_usage(void)
{
    printf("verctrl usage\n");
    printf("  --sync : start synchonize version\n");
    printf("  --upgrade : upgrade from server(fetch + write)\n");

    return ;
}
