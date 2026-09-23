#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "module/dmsgid.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"
#include "lib/util.h"

static dmod_t upgrademod;

static void upgrade_handle_simple_str(dtask_t *task)
{
    const char *str = task->data;

    if (strstr(str, "update"))
    {
        char *downargs[] = {
            "verctrl", "--upgrade", NULL
        };
        pid_t upgrade = run_new_program("verctrl", downargs);
        if (upgrade < 0)
        {
            derror("download upgrade file failed\n");
            return ;
        }
        else
        {
            dprint("start upgrading, pid %d\n", upgrade);
        }
    }
    else if (strstr(str, "result"))
    {
        dprint("receive upgrade info [%s]\n", str);
    }

    return ;
}

static int upgrademod_ontask(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Success;
    dtask_t *task = (dtask_t *)arg;

    switch (task->msgid)
    {
        case MSGID_SIMPLE_STR:
            upgrade_handle_simple_str(task);
            break;
        case MSGID_TEST_TIMER:
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t upgrademod_ops = {
    .ontask = upgrademod_ontask,
};

int upgrademod_init(void)
{
    int ret = Success;
    memset(&upgrademod, 0, sizeof(dmod_t));
    dcomponent_init(&upgrademod.dcomp, ModuleIDUpgrade, "upgrade");
    upgrademod.ops = &upgrademod_ops;

    ret = dmodule_register(&upgrademod);
    if (ret != Success)
    {
        derror("upgrade module register failed\n");
        return Fail;
    }

    dprint("upgrade_module register ret = %d\n", ret);
    return ret;
}

void upgrademod_exit(void)
{
    dmodule_unregister(&upgrademod);
    dprint("upgrade module unregister done\n");
}

DCOMP_INIT_LOWPRIO(upgrademod_init);
DCOMP_EXIT_LOWPRIO(upgrademod_exit);
