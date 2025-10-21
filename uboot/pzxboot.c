#include <stdio.h>
#include <cli.h>
#include <errno.h>
#include <linux/delay.h>
#include "pzxboot.h"

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
    int ret = 0;
    int select = -1;

    if(check_keypress() == '1')
    {
        cli_loop();
    }

    ret = boot_parameter_init();
    if(ret != 0)
    {
        pzxboot_emergency("init boot parameter failed, error %d\n", ret);
        return ;
    }

    ret = find_valid_version(KERNEL1_PARTITION_OFFSET);
    if(ret != 0)
    {
        pzxboot_error("version 1 is not valid, error %d\n", ret);
    }

    ret = find_valid_version(KERNEL2_PARTITION_OFFSET);
    if(ret != 0)
    {
        pzxboot_error("version 2 is not valid, error %d\n", ret);
    }

    select = select_boot_version();
    if(select < 0)
    {
        pzxboot_emergency("no valid version to boot\n");
        return ;
    }

    boot_kernel(select);

    // never come here
    pzxboot_debug("boot will never come here\n");

    return ;
}
