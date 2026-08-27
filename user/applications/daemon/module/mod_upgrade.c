#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "module/dmsgid.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"

static dmod_t upgrademod;
static int timerid = -1;

static int upgrade_handle_json_rawstr(dtask_t *task)
{
    (void)task;
    dprint("upgrade_handle_json_rawstr\n");
    if (timerid > 0)
    {
        timer_del(timerid);
    }

    return Success;
}

static int upgrademod_onmsg(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Fail;
    dtask_t *task = (dtask_t *)arg;

    switch (task->msgid)
    {
        case MSGID_JSON_RAWSTR:
            ret = upgrade_handle_json_rawstr(task);
            break;
        case MSGID_TEST_TIMER:
            dprint("receive a timer tick\n");
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t upgrademod_ops = {
    .onmsg = upgrademod_onmsg,
};

int upgrademod_init(void)
{
    int ret = Success;
    memset(&upgrademod, 0, sizeof(dmod_t));
    dcomponent_init(&upgrademod.dcomp, ModuleIDUpgrade, "mod_upgrade");
    upgrademod.ops = &upgrademod_ops;

    ret = dmodule_register(&upgrademod);
    if (ret != Success)
    {
        derror("upgrade module register failed\n");
        return Fail;
    }

    timerid = timer_add(3000, 5000, true, ModuleIDUpgrade, MSGID_TEST_TIMER);
    dprint("upgrade_module register ret = %d, timerid %d\n", ret, timerid);
    return ret;
}

void upgrademod_exit(void)
{
    dmodule_unregister(&upgrademod);
    dprint("upgrade module unregister done\n");
}