#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "proto/proto_api.h"

extern int proto_uevent_init(void);
extern void proto_uevent_exit(void);

static const dcomp_init_f dproto_initcalls[] = {
    proto_uevent_init,
    NULL,
};

static const dcomp_exit_f dproto_exitcalls[] = {
    proto_uevent_exit,
    NULL,
};

void dproto_init(void)
{
    int ret = Success;
    for (int i = 0; dproto_initcalls[i] != NULL; i++)
    {
        ret = dproto_initcalls[i]();
        if (ret != Success)
        {
            derror("dproto_init: failed to init proto[%d]\n", i);
        }
    }
    
    return ;
}

void dproto_exit(void)
{
    for (int i = 0; dproto_exitcalls[i] != NULL; i++)
    {
        dproto_exitcalls[i]();
    }

    return ;
}
