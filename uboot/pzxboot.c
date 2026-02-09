#include <stdio.h>
#include <cli.h>
#include <errno.h>
#include <command.h>
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

    for(int i = 0; i < VERSION_COUNTS; i++)
    {
        ret = version_check(i);
        pzxboot_info("check version %d ret %d\n", i, ret);
    }

    set_partition_table();

    select = select_boot_version();
    if(select < 0)
    {
        pzxboot_emergency("no valid version to boot\n");
        return ;
    }

    boot_kernel();

    // never come here
    pzxboot_debug("boot will never come here\n");

    return ;
}

static int do_pzxboot(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
    pzxboot();
    return 0;
}

U_BOOT_CMD(pzxboot, 1, 0, do_pzxboot,
    "pzxboot command, try to boot kernel",
    "custom boot");