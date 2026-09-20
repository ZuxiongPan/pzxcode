#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "channel/chnl_api.h"
#include "module/dmsgid.h"
#include "lib/cJSON.h"

static dmod_t statmod;

static void stat_handle_simple_str(dtask_t *task)
{
    const char *str = task->data;
    int bytes = 0;
    char buf[TASK_DATA_MAXSIZE] = { 0 };

    if (strstr(str, "context"))
    {
        bytes = dctx_info(buf, sizeof(buf));
    }
    else if (strstr(str, "timer"))
    {
        bytes = dtimer_info(buf, sizeof(buf));
    }
    else
    {
        bytes = snprintf(buf, sizeof(buf), "invalid request [%s] for status module\n", str);
    }

    task_enqueue(DataToOuter, statmod.dcomp.dcompid, task->src_compid, 0, bytes, buf);

    return ;
}

static int statmod_ontask(dmod_t *m, void *arg)
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
            stat_handle_simple_str(task);
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t statmod_ops = {
    .ontask = statmod_ontask,
};

int statmod_init(void)
{
    int ret = Success;
    memset(&statmod, 0, sizeof(dmod_t));
    dcomponent_init(&statmod.dcomp, ModuleIDStatus, "status");
    statmod.ops = &statmod_ops;

    ret = dmodule_register(&statmod);
    if (ret != Success)
    {
        derror("status module register failed\n");
        return Fail;
    }

    dprint("status module register ret = %d\n", ret);
    return ret;
}

void statmod_exit(void)
{
    dmodule_unregister(&statmod);
    dprint("status module unregister done\n");
}

DCOMP_INIT_NORMPRIO(statmod_init);
DCOMP_EXIT_NORMPRIO(statmod_exit);
