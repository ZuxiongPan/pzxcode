#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "module/mod_api.h"

extern int blkmod_init(void);
extern void blkmod_exit(void);

static const dcomp_init_f dmodule_initcalls[] = {
    blkmod_init,
    NULL,
};

static const dcomp_exit_f dmodule_exitcalls[] = {
    blkmod_exit,
    NULL,
};

void dmodule_init(void)
{
    int ret = Success;
    for (int i = 0; dmodule_initcalls[i] != NULL; i++)
    {
        ret = dmodule_initcalls[i]();
        if (ret != Success)
        {
            derror("dmodule_init: failed to init module[%d]\n", i);
        }
    }
    
    return ;
}

void dmodule_exit(void)
{
    for (int i = 0; dmodule_exitcalls[i] != NULL; i++)
    {
        dmodule_exitcalls[i]();
    }

    return ;
}
