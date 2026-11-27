#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "core/dworker.h"
#include "dispatcher/ddispatcher.h"

#define PROTO_DUMP_MAX 1024U

int msg_uevent_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    char buf[PROTO_DUMP_MAX];
    unsigned int keep = data_size < sizeof(buf) - 1 ? data_size : sizeof(buf) - 1;

    UNUSED(srcid);

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("[%s] empty uevent message\n", comp->name);
        return Fail;
    }

    // uevent delivers NUL separated key=value pairs
    for (unsigned int i = 0; i < keep; i++)
    {
        buf[i] = (data[i] == '\0') ? ' ' : data[i];
    }
    buf[keep] = '\0';

    dprint("[%s] uevent{%s\b}%s\n", comp->name, buf, keep < data_size ? " ..." : "");

    return Success;
}

int msg_genl_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    const struct genl_upmsg *msg = NULL;

    msg = genl_upmsg_check(data_size, data);
    if (unlikely(msg == NULL))
    {
        derror("[%s] malformed generic netlink message, %u bytes\n",
            comp->name, data_size);
        return Fail;
    }

    if (unlikely(msg->target_len == 0))
    {
        derror("[%s] generic netlink message without a target\n", comp->name);
        return Fail;
    }

    dprint("[%s] genl target[%s], act[%u], data[%u]\n", comp->name,
        genl_upmsg_target(msg), genl_upmsg_act(msg), msg->data_len);

    return task_enqueue_by_name(srcid, genl_upmsg_target(msg), MSGID_GENL_ACTION_START + genl_upmsg_act(msg),
                msg->data_len, genl_upmsg_data(msg));
}