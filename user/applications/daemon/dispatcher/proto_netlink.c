#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dconf.h"
#include "dextension.h"
#include "dispatcher/ddispatcher.h"

/* how much of a payload is traced, the rest is only counted */
#define PROTO_DUMP_MAX 1024U

/* the payload of both netlink channels may be binary, keep the trace readable */
static void proto_dump(const char *tag, const char *data, unsigned int len)
{
    char buf[PROTO_DUMP_MAX];
    unsigned int keep = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;

    for (unsigned int i = 0; i < keep; i++)
    {
        buf[i] = (data[i] >= 0x20 && data[i] < 0x7f) ? data[i] : '.';
    }
    buf[keep] = '\0';

    dprint("%s{%s}%s\n", tag, buf, keep < len ? " ..." : "");
}

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

    UNUSED(srcid);

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

    /*
     * the target is the routing key: once the modules behind it exist this is
     * where the payload is handed over, for example
     *   task_enqueue_by_name(comp->dcompid, msg->target, <msgid>,
     *       msg->data_len, genl_upmsg_data(msg));
     * until then the message is only traced.
     */
    dprint("[%s] genl target[%s], data[%u]\n", comp->name,
        genl_upmsg_target(msg), msg->data_len);

    if (msg->data_len > 0)
    {
        proto_dump("  data", genl_upmsg_data(msg), msg->data_len);
    }

    return Success;
}
