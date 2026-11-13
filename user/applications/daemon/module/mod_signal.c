#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "dlog.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_name.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"

static struct dcomp signalmod;

static int msg_signal_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(comp);
    UNUSED(srcid);
    
    if (unlikely(data_size != sizeof(struct signalfd_siginfo) || data == NULL))
    {
        derror("invalid data size: %u, data: %p\n", data_size, data);
        return Fail;
    }

    struct signalfd_siginfo *info = (struct signalfd_siginfo *)data;

    switch (info->ssi_signo)
    {
        case SIGINT:
        case SIGTERM:
        {
            demerg("receive INT/TERM signal, the event loop ended\n");
            // stop_daemon_evloop() also kicks the blocked epoll_wait through
            // the wakeup eventfd, no timer hack is needed anymore
            stop_daemon_evloop();
            break;
        }
        case SIGCHLD:
            dprint("receive child signal\n");
            break;
        default:
            derror("unknown signal %d\n", info->ssi_signo);
            break;
    }

    return Success;
}

static const struct msg_handler handlers[] = {
    { .name = "signal", .msgid = MSGID_SYS_SIGNAL, .func = msg_signal_handler},
};

static int signalmod_init(void)
{
    int ret = Success;
    memset(&signalmod, 0, sizeof(signalmod));
    dcomp_init(&signalmod, ModuleSignal);
    dcomp_set_handlers(&signalmod, ARRAY_SIZE(handlers), handlers);

    ret = dcomp_record_add(&signalmod);
    if (unlikely(ret != Success))
    {
        derror("failed to add module[%s] to record\n",
            signalmod.name == NULL ? "no name" : signalmod.name);
        return ret;
    }

    dprint("[%s] init success\n", signalmod.name);
    return ret;
}

static void signalmod_exit(void)
{
    dcomp_record_del(&signalmod);
    dprint("[%s] exit\n", signalmod.name);

    return ;
}

// high priority: the module must be registered in the record table *before*
// the signal channel starts reading signalfd, otherwise a signal arriving in
// between would be consumed and then dropped (nobody to deliver it to)
DCOMP_INIT_HIGHPRIO(signalmod_init);
DCOMP_EXIT_HIGHPRIO(signalmod_exit);
