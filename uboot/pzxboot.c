#include <stdio.h>
#include <cli.h>
#include <linux/delay.h>
#include "pzxboot.h"

static const char pzxerrorstr[ERROR_END][128] = 
{
    [NO_ERRORS] = "no errors",
    [ERROR_NODEVICE] = "no device",
    [ERROR_HEADER] = "header invalid",
    [ERROR_KERNEL] = "kernel invalid",
    [ERROR_ROOTFS] = "rootfs invalid",
    [ERROR_OPSTORDEVICE] = "read/write error",
};

static int check_keypress(void)
{
    int ret = 0;
    int timeout = CONFIG_BOOTDELAY;

    printf("Press key 1 to stop pzxboot:\n");
    while(timeout)
    {
        if(tstc())
        {
            ret = getchar();
            if(ret == '1')
            {
                printf("\renter cli mode ...\n");
                return ret;
            }
        }
        printf("\r%d..", timeout);
        timeout--;
        mdelay(1000);
    }
    printf("\r%d..\n", timeout);

    return ret;
}

void pzxboot(void)
{
    enum boot_errors ret = NO_ERRORS;
    int select = -1;

    if(check_keypress() == '1')
    {
        cli_loop();
    }

    ret = boot_parameter_init();
    if(ret != NO_ERRORS)
    {
        printf("init boot parameter failed, error %u: %s\n", ret, pzxerrorstr[ret]);
        return ;
    }

    ret = find_valid_version(KERNEL1_PARTITION_OFFSET);
    if(ret != NO_ERRORS)
    {
        printf("version 1 is not valid, error %u: %s\n", ret, pzxerrorstr[ret]);
    }

    ret = find_valid_version(KERNEL2_PARTITION_OFFSET);
    if(ret != NO_ERRORS)
    {
        printf("version 2 is not valid, error %u: %s\n", ret, pzxerrorstr[ret]);
    }

    select = select_boot_version();
    if(select < 0)
    {
        printf("no valid version to boot\n");
        return ;
    }

    boot_kernel(select);

    // never come here
    printf("boot will never come here\n");

    return ;
}
