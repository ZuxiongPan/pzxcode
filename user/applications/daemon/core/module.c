#include <string.h>
#include <stdlib.h>

#include "core/module.h"

static module_t* g_modules[MAX_MODULE_COUNT];
static int g_mod_cnt = 0;

int module_register(module_t *mod)
{
    if (g_mod_cnt >= MAX_MODULE_COUNT || mod == NULL)
    {
        return -1;
    }

    g_modules[g_mod_cnt] = mod;
    g_mod_cnt++;

    if (mod->ops != NULL && mod->ops->init != NULL)
    {
        return mod->ops->init(mod);
    }

    return 0;
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
