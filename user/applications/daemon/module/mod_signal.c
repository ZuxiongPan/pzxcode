#include <string.h>
#include <signal.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "channel/chnl_api.h"
#include "module/dmsgid.h"

static dmod_t signalmod;

static int handle_signal(uint32_t signo)
{
    switch (signo)
    {
        case SIGINT:
        case SIGTERM:
            dprint("receive signal %d, the event loop ended\n", signo);
            stop_daemon_evloop();
            // this timer is used for stop the pending of daemon_context_run
            timer_add(100, 0, false, DCOMPID_NONE, MSGID_SYS_TIMER);
            break;
        case SIGCHLD:
            dprint("receive signal %d, child process exited\n", signo);
            break;
        default:
            dprint("unknown signal %d\n", signo);
            break;
    }

    return Success;
}

static int signalmod_ontask(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Success;
    dtask_t *task = (dtask_t *)arg;
    uint32_t signo = *((uint32_t *)task->data);

    switch (task->msgid)
    {
        case MSGID_SYS_SIGNAL:
            handle_signal(signo);
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t signalmod_ops = {
    .ontask = signalmod_ontask,
};

int signalmod_init(void)
{
    int ret = Success;
    memset(&signalmod, 0, sizeof(dmod_t));
    dcomponent_init(&signalmod.dcomp, ModuleIDSignal, "signal");
    signalmod.ops = &signalmod_ops;

    ret = dmodule_register(&signalmod);
    if (ret != Success)
    {
        derror("signal module register failed\n");
        return Fail;
    }

    dprint("signal module register ret = %d\n", ret);
    return ret;
}

void signalmod_exit(void)
{
    dmodule_unregister(&signalmod);
    dprint("signal module unregister done\n");
}

DCOMP_INIT_HIGHPRIO(signalmod_init);
DCOMP_EXIT_HIGHPRIO(signalmod_exit);
