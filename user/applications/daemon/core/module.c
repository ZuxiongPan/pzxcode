#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dcommon.h"
#include "core/context.h"
#include "core/module.h"

int module_register(module_t *mod)
{
    if (mod == NULL || mod->id >= MOD_MAX)
    {
        derror("module_register fail, mod is invalid\n");
        return Fail;
    }

    dctx_t *ctx = dctx_instance();
    module_mgr_t *mgr = ctx->mod_mgr;

    pthread_rwlock_wrlock(&mgr->rwlock);
    mgr->modules[mod->id] = mod;
    mgr->mod_cnt++;
    pthread_rwlock_unlock(&mgr->rwlock);

    return Success;
}

module_t* module_find(const char *name)
{
    module_t *mod = NULL;

    if (name == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < g_mod_cnt; i++)
    {
        if (strncmp(g_modules[i]->name, name, sizeof(g_modules[i]->name)) == 0)
        {
            mod = g_modules[i];
            break;
        }
    }

    return mod;
}

int module_start_all(void)
{
    for (int i = 0; i < g_mod_cnt; i++)
    {
        if (g_modules[i]->ops != NULL && g_modules[i]->ops->start != NULL)
        {
            g_modules[i]->ops->start(g_modules[i]);
        }
    }

    return 0;
}

int module_stop_all(void)
{
    for (int i = 0; i < g_mod_cnt; i++)
    {
        if (g_modules[i]->ops != NULL && g_modules[i]->ops->stop != NULL)
        {
            g_modules[i]->ops->stop(g_modules[i]);
        }
    }

    return 0;
}

int module_manager_init(struct daemon_context *ctx)
{
    // here we shoule check ctx is valid, but this is a key init, ctx must be valid

    module_mgr_t *mgr = &ctx->mod_mgr;
    mgr->head = NULL;
    pthread_rwlock_init(&mgr->rwlock, NULL);

    return Success;
}

void module_manager_destroy(struct daemon_context *ctx)
{
    module_mgr_t *mgr = &ctx->mod_mgr;
    
    pthread_wrlock_wrlock(&mgr->rwlock);
    for (int i = 0; i < mgr->mod_cnt; i++)
    {
        if (mgr->modules[i] != NULL && mgr->modules[i]->ops != NULL
            && mgr->modules[i]->ops->stop != NULL)
        {
            mgr->modules[i]->ops->stop(mgr->modules[i]);
            mgr->modules[i] = NULL;
        }
    }
    free(mgr->modules);
    mgr->mod_cnt = 0;
    pthread_rwlock_unlock(&mgr->rwlock);

    return ;
}
