#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include "dlog.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "core/dsync.h"
#include "lib/util.h"

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
            // stop_dctx_evloop() also kicks the blocked epoll_wait through
            // the wakeup eventfd, no timer hack is needed anymore
            stop_dctx_evloop();
            break;
        }
        case SIGCHLD:
        {
            int wstatus = 0;
            int code = 0;
            pid_t pid = 0;

            // reap everything, not just the pid this signal reports: one SIGCHLD
            // can stand for several exits, and a child nobody waits for still
            // has to be collected or it stays a zombie until the daemon exits
            while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0)
            {
                code = child_exit_code(wstatus);
                if (dsync_complete(SyncChild, (unsigned int)pid, code) != 0)
                {
                    dprint("child[%d] reaped, code[%d], no waiter\n", pid, code);
                }
            }
            break;
        }
        default:
            derror("unknown signal %d\n", info->ssi_signo);
            break;
    }

    return Success;
}

static const struct msg_handler handlers[] = {
    { .name = "signal", .msgid = MSGID_SYS_SIGNAL, .func = msg_signal_handler },
};

static int signalmod_init(void)
{
    int ret = Success;
    memset(&signalmod, 0, sizeof(signalmod));
    dcomp_init(&signalmod, ModSignalName, ModSignalId);
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

DCOMP_INIT_HIGHPRIO(signalmod_init);
DCOMP_EXIT_HIGHPRIO(signalmod_exit);
