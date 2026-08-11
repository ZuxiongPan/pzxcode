#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "channel/chnl_api.h"

extern int ch_timer_init(void);
extern void ch_timer_exit(void);
extern int ch_uevent_init(void);
extern void ch_uevent_exit(void);
extern int ch_uds_init(void);
extern void ch_uds_exit(void);

static const dcomp_init_f dchannel_initcalls[] = {
    ch_timer_init,
    ch_uevent_init,
    ch_uds_init,
    NULL,
};

static const dcomp_exit_f dchannel_exitcalls[] = {
    ch_uds_exit,
    ch_uevent_exit,
    ch_timer_exit,
    NULL,
};

void dchannel_init(void)
{
    int ret = Success;
    for (int i = 0; dchannel_initcalls[i] != NULL; i++)
    {
        ret = dchannel_initcalls[i]();
        if (ret != Success)
        {
            derror("failed to init channel[%d]\n", i);
        }
    }
    
    return ;
}

void dchannel_exit(void)
{
    for (int i = 0; dchannel_exitcalls[i] != NULL; i++)
    {
        dchannel_exitcalls[i]();
    }

    return ;
}
