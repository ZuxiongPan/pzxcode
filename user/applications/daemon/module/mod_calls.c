#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "module/mod_api.h"

extern int ueventmod_init(void);
extern void ueventmod_exit(void);
extern int statmod_init(void);
extern void statmod_exit(void);
extern int upgrademod_init(void);
extern void upgrademod_exit(void);

static const dcomp_init_f dmodule_initcalls[] = {
    statmod_init,
    ueventmod_init,
    upgrademod_init,
    NULL,
};

static const dcomp_exit_f dmodule_exitcalls[] = {
    upgrademod_exit,
    ueventmod_exit,
    statmod_exit,
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
            derror("failed to init module[%d]\n", i);
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
