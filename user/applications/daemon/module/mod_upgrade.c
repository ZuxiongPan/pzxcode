#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "module/dmsgid.h"
#include "proto/proto_api.h"
#include "lib/cJSON.h"

static dmod_t upgrademod;

static int upgrade_handle_json_rawstr(dtask_t *task)
{
    dproto_data_t *req = (dproto_data_t *)task->data;
    dprint("upgrade_handle_json_rawstr req = %s\n", req->json_data);

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

    dprint("upgrade_module register ret = %d\n", ret);
    return ret;
}

void upgrademod_exit(void)
{
    dmodule_unregister(&upgrademod);
    dprint("upgrade module unregister done\n");
}