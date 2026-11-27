#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "proto.h"
#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dcomp_info.h"
#include "dextension.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "dispatcher/ddispatcher.h"

static struct dcomp dispatcher = { 0 };

static const struct msg_handler dispatcher_handlers[] = {
    { .name = "socket", .msgid = MSGID_INPUT_SOCKET, .func = msg_socket_input_handler },
    { .name = "uevent", .msgid = MSGID_INPUT_UEVENT, .func = msg_uevent_input_handler },
    { .name = "generic-netlink", .msgid = MSGID_INPUT_GENERIC_NETLINK, .func = msg_genl_input_handler },
};

static int dispatcher_init(void)
{
    int ret = Success;

    memset(&dispatcher, 0, sizeof(dispatcher));
    dcomp_init(&dispatcher, ModDispatcherName, ModDispatcherId);
    dcomp_set_handlers(&dispatcher, ARRAY_SIZE(dispatcher_handlers), dispatcher_handlers);

    ret = dcomp_record_add(&dispatcher);
    if (unlikely(ret != Success))
    {
        derror("failed to add module[%s] to record\n", ModDispatcherName);
        return ret;
    }

    dprint("[%s] init success, id[%u]\n", dispatcher.name, dispatcher.dcompid);

    return Success;
}

static void dispatcher_exit(void)
{
    dcomp_record_del(&dispatcher);
    dprint("[%s] exit\n", ModDispatcherName);

    return ;
}

DCOMP_INIT_HIGHPRIO(dispatcher_init);
DCOMP_EXIT_HIGHPRIO(dispatcher_exit);
