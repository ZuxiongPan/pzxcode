#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dmodule.h"
#include "core/dfuncalls.h"
#include "module/dmsgid.h"

static dchannel_t signal_chnl;

static int signal_read_from_outer(dchannel_t *chnl)
{
    ssize_t ret = Success;
    uint32_t signo = 0;
    struct signalfd_siginfo info;
    memset(&info, 0, sizeof(info));

    ret = read(chnl->fd, &info, sizeof(info));
    if (ret != sizeof(info))
    {
        derror("read failed");
        return Fail;
    }
    signo = info.ssi_signo;

    dprint("receive signal %d\n", signo);
    return task_enqueue(DataModuleMsg, chnl->dcomp.dcompid, ModuleIDSignal,
        MSGID_SYS_SIGNAL, sizeof(signo), (const char *)&signo);
}

static const channel_ops_t signal_ops = {
    .read_from_outer = signal_read_from_outer,
    .write_to_outer = NULL,
};

int ch_signal_init(void)
{
    int ret = Success;
    sigset_t mask;
    memset(&signal_chnl, 0, sizeof(dchannel_t));

    dcomponent_init(&signal_chnl.dcomp, ChannelIDSignal, "ch_signal");
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);

    ret = sigprocmask(SIG_BLOCK, &mask, NULL);
    if (ret < 0)
    {
        derror("sigprocmask failed");
        return Fail;
    }

    signal_chnl.ops = &signal_ops;
    signal_chnl.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_chnl.fd < 0)
    {
        derror("signalfd failed");
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &signal_chnl);

    dprint("signal channel fd = %d, register ret %d\n", signal_chnl.fd, ret);
    return ret;
}

void ch_signal_exit(void)
{
    dchannel_unregister(&signal_chnl);
    if (signal_chnl.fd >= 0)
    {
        close(signal_chnl.fd);
    }
    signal_chnl.fd = -1;

    return ;
}

DCOMP_INIT_NORMPRIO(ch_signal_init);
DCOMP_EXIT_NORMPRIO(ch_signal_exit);
