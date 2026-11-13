#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dcomp_name.h"
#include "core/dchannel.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"

static struct dchannel ch_signal;

static int ch_signal_read_from_out(struct dchannel *ch)
{
    ssize_t ret = 0;
    struct signalfd_siginfo info = { 0 };

    ret = read(ch->fd, &info, sizeof(info));
    if (ret < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        {
            // spurious wakeup, nothing to do
            return Success;
        }
        derror("read signalfd failed, errno: %d\n", errno);
        return Fail;
    }
    if (ret != (ssize_t)sizeof(info))
    {
        derror("short read on signalfd, got %zd of %zu\n", ret, sizeof(info));
        return Fail;
    }

    return task_enqueue_by_name(ch->comp.dcompid, ModuleSignal,
        MSGID_SYS_SIGNAL, sizeof(info), (const char *)&info);
}

static int ch_signal_init(void)
{
    int ret = Success;
    memset(&ch_signal, 0, sizeof(ch_signal));
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);

    dcomp_init(&ch_signal.comp, ChannelSignal);
    dcomp_set_handlers(&ch_signal.comp, 0, NULL);
    ch_signal.read_from_out = ch_signal_read_from_out;
    ch_signal.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (ch_signal.fd < 0)
    {
        derror("signalfd failed, errno: %d\n", errno);
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &ch_signal);
    if (ret != Success)
    {
        derror("dchannel_register [%s] failed\n", ch_signal.comp.name);
        close(ch_signal.fd);
        ch_signal.fd = -1;
        return Fail;
    }

    dprint("[%s] info: fd[%d], id[%u]\n", ch_signal.comp.name,
        ch_signal.fd, ch_signal.comp.dcompid);
    return Success;
}

static void ch_signal_exit(void)
{
    dchannel_unregister(&ch_signal);
    if (ch_signal.fd >= 0)
    {
        close(ch_signal.fd);
    }
    ch_signal.fd = -1;

    dprint("[%s] exit\n", ch_signal.comp.name);
    return ;
}

DCOMP_INIT_NORMPRIO(ch_signal_init);
DCOMP_EXIT_NORMPRIO(ch_signal_exit);
