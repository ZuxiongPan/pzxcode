#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dchannel.h"
#include "core/dfuncalls.h"

dchannel_t ch_input;

static int input_read_from_outer(dchannel_t *ch)
{
    struct input_event ev;
    ssize_t n = read(ch->fd, &ev, sizeof(ev));
    if (n < 0 || n != sizeof(ev))
    {
        derror("read input event failed");
        return Fail;
    }

    return task_enqueue(DataKeyEvent, ch->dcomp.dcompid, DCOMPID_NONE,
            0, sizeof(ev), (const char *)(&ev));
}

static const channel_ops_t ch_key_ops = {
    .read_from_outer = input_read_from_outer,
};

static int ch_input_init(void)
{
    int ret = Success;
    memset(&ch_input, 0, sizeof(ch_input));
    ch_input.ops = &ch_key_ops;
    dcomponent_init(&ch_input.dcomp, ChannelIDInput, "ch_input");
    ch_input.fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (ch_input.fd < 0)
    {
        derror("open /dev/input/event0 failed");
        return Fail;
    }

    ret = dchannel_register(EPOLLIN, &ch_input);
    dprint("input channel register ret = %d\n", ret);
    return ret;
}

static void ch_input_exit(void)
{
    dchannel_unregister(&ch_input);
    if (ch_input.fd >= 0)
    {
        close(ch_input.fd);
    }
    ch_input.fd = -1;

    dprint("ch_input exit\n");
    return ;
}

DCOMP_INIT_LOWPRIO(ch_input_init);
DCOMP_EXIT_LOWPRIO(ch_input_exit);
