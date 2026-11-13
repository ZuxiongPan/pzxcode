/*
 * input dispatcher
 *
 * separates the three jobs that used to be mixed inside a channel:
 *
 *     channel    reads and writes bytes, nothing else
 *     dispatcher decodes the wire format and routes
 *     component  implements the actual logic
 *
 * flow of one request:
 *
 *     channel --task(msgid = MSGID_INPUT_*, src = connection)--> dispatcher
 *     dispatcher --task(msgid = request, src unchanged)--> component
 *     component --task(msgid = MSGID_UDS_RESPONSE, dst = src)--> connection
 *
 * srcid is forwarded untouched. that is what makes the answer find its way back
 * to the connection the request came from without the dispatcher knowing
 * anything about connections, sockets or clients.
 *
 * the same path carries the one way kernel events (generic netlink, uevent): the
 * channel sends them in with its own id as srcid, the parser routes them to the
 * component that wants them, and since that source has no MSGID_UDS_RESPONSE
 * handler, the dispatcher logs its own errors instead of trying to answer.
 *
 * the wire formats live in proto_*.c and are selected by the input msgid, so a
 * new protocol never touches a channel and never touches the routing code:
 * add a MSGID_INPUT_*, a parser, and one line in DIN_PROTO_LIST.
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dcomp_name.h"
#include "dextension.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"
#include "dispatcher/dinput.h"

// one wire format: the input msgid a channel tags the task with, and the parser
// that turns those bytes into a routable message
struct din_proto {
    unsigned int msgid;
    const char *name;
    int (*parse)(const char *data, unsigned int size, struct dinput *in);
};

// X(lower case name used for the symbols, input msgid)
#define DIN_PROTO_LIST(X) \
    X(json, MSGID_INPUT_JSON) \
    X(genl, MSGID_INPUT_GENL) \
    X(uevent, MSGID_INPUT_UEVENT)

// the parsers are internal to the dispatcher, proto_*.c only exports din_parse_*
#define DIN_PROTO_DECL(lname, id) \
    int din_parse_##lname(const char *data, unsigned int size, struct dinput *in);
DIN_PROTO_LIST(DIN_PROTO_DECL)
#undef DIN_PROTO_DECL

#define DIN_PROTO_ENTRY(lname, id) \
    { .msgid = (id), .name = #lname, .parse = din_parse_##lname },
static const struct din_proto din_protos[] = {
    DIN_PROTO_LIST(DIN_PROTO_ENTRY)
};

static struct dcomp dispatcher;

static int din_handle(unsigned int srcid, unsigned int data_size,
    const char *data, unsigned int msgid);
static int din_route(unsigned int srcid, const struct dinput *in);
static bool dcomp_has_handler(const struct dcomp *comp, unsigned int msgid);
static const struct din_proto *din_proto_find(unsigned int msgid);

/*
 * answer the sender directly. errors raised by the dispatcher (bad target,
 * unknown component) are protocol level, the channel that carried the request
 * knows nothing about them, so the dispatcher is the one that has to speak.
 *
 * a one way source (kernel events: generic netlink, uevent) has no answer path
 * at all, and neither has a message that arrived before its sender registered a
 * MSGID_UDS_RESPONSE handler. those are logged instead of enqueued, otherwise
 * every dropped kernel event would leave a task nobody can handle.
 */
static void din_reply(unsigned int srcid, const char *text)
{
    char buf[DIN_TARGET_MAXLEN + 96U];
    const struct dcomp *src = NULL;
    int len = 0;

    if (unlikely(srcid == DCOMPID_RESERVED))
    {
        // nobody to answer, the request did not come from a connection
        derror("dispatcher: %s\n", text);
        return ;
    }

    src = find_dcomp_by_id(srcid);
    if (unlikely(src == NULL || !dcomp_has_handler(src, MSGID_UDS_RESPONSE)))
    {
        // a kernel event source cannot be answered, this is a log line only
        derror("dispatcher: %s%s\n", text,
            src == NULL ? "" : " (source is one way)");
        return ;
    }

    len = snprintf(buf, sizeof(buf), "armd: %s\n", text);
    if (unlikely(len < 0))
    {
        return ;
    }
    if (unlikely((size_t)len >= sizeof(buf)))
    {
        len = (int)sizeof(buf) - 1;
    }

    if (unlikely(task_enqueue_by_id(dispatcher.dcompid, srcid,
        MSGID_UDS_RESPONSE, (unsigned int)len, buf) != Success))
    {
        derror("dispatcher: failed to answer [%s]\n", text);
    }

    return ;
}

static bool dcomp_has_handler(const struct dcomp *comp, unsigned int msgid)
{
    // pre-check only, the worker still does the authoritative dispatch. it just
    // turns "request silently timed out" into an immediate error reply
    for (unsigned int i = 0; i < comp->handle_num; i++)
    {
        if (comp->handlers[i].msgid == msgid)
        {
            return true;
        }
    }

    return false;
}

static bool din_target_valid(const char *target)
{
    if (target == NULL || target[0] == '\0')
    {
        return false;
    }

    // a target is a component name, it must not carry path or wildcard syntax
    if (strlen(target) >= DIN_TARGET_MAXLEN)
    {
        return false;
    }
    if (strchr(target, '/') != NULL)
    {
        return false;
    }

    return true;
}

static int din_route(unsigned int srcid, const struct dinput *in)
{
    char text[DIN_TARGET_MAXLEN + 64U];
    const struct dcomp *dst = NULL;

    if (unlikely(!din_target_valid(in->target)))
    {
        din_reply(srcid, "invalid target in request");
        return Fail;
    }

    if (unlikely(in->payload_len > 0 && in->payload == NULL))
    {
        derror("dispatcher: payload of %u bytes is NULL\n", in->payload_len);
        din_reply(srcid, "invalid payload in request");
        return Fail;
    }

    dst = find_dcomp_by_name(in->target);
    if (dst == NULL)
    {
        snprintf(text, sizeof(text), "component [%s] not found", in->target);
        din_reply(srcid, text);
        return Fail;
    }

    if (unlikely(!dcomp_has_handler(dst, in->msgid)))
    {
        snprintf(text, sizeof(text), "component [%s] has no handler for 0x%x",
            in->target, in->msgid);
        din_reply(srcid, text);
        return Fail;
    }

    // srcid is passed through on purpose: the component answers its srcid with
    // MSGID_UDS_RESPONSE and the transport that owns that id delivers the bytes
    return task_enqueue_by_id(srcid, dst->dcompid, in->msgid,
        in->payload_len, in->payload);
}

static int din_handle(unsigned int srcid, unsigned int data_size,
    const char *data, unsigned int msgid)
{
    const struct din_proto *proto = NULL;
    struct dinput in;
    int ret = Fail;

    proto = din_proto_find(msgid);
    if (unlikely(proto == NULL))
    {
        derror("dispatcher: no parser for msgid 0x%x\n", msgid);
        return Fail;
    }

    if (unlikely(data == NULL || data_size == 0))
    {
        derror("dispatcher: empty %s input\n", proto->name);
        din_reply(srcid, "empty request");
        return Fail;
    }

    memset(&in, 0, sizeof(in));

    if (unlikely(proto->parse(data, data_size, &in) != Success))
    {
        ddebug("dispatcher: %s request rejected: %s\n", proto->name, in.reason);
        din_reply(srcid, in.reason[0] == '\0' ? "malformed request" : in.reason);
        goto out;
    }

    ret = din_route(srcid, &in);

out:
    if (in.release != NULL)
    {
        in.release(&in);
    }

    return ret;
}

/*
 * the worker selects a handler by comparing the task msgid, so the protocol
 * table cannot be matched directly: each entry gets a trampoline that only says
 * which msgid it handles. all the real work is in din_handle().
 */
#define DIN_PROTO_HANDLER(lname, id) \
    static int dispatcher_on_##lname(const struct dcomp *self, unsigned int srcid, \
        unsigned int data_size, const char *data) \
    { \
        UNUSED(self); \
        return din_handle(srcid, data_size, data, (id)); \
    }
DIN_PROTO_LIST(DIN_PROTO_HANDLER)

#define DIN_PROTO_MSGH(lname, id) \
    { .name = "input." #lname, .msgid = (id), .func = dispatcher_on_##lname },
static const struct msg_handler dispatcher_handlers[] = {
    DIN_PROTO_LIST(DIN_PROTO_MSGH)
};

static const struct din_proto *din_proto_find(unsigned int msgid)
{
    for (unsigned int i = 0; i < ARRAY_SIZE(din_protos); i++)
    {
        if (din_protos[i].msgid == msgid)
        {
            return &din_protos[i];
        }
    }

    return NULL;
}

static int dispatcher_init(void)
{
    int ret = Success;

    memset(&dispatcher, 0, sizeof(dispatcher));
    dcomp_init(&dispatcher, ModuleDispatcher);
    dcomp_set_handlers(&dispatcher, ARRAY_SIZE(dispatcher_handlers), dispatcher_handlers);

    ret = dcomp_record_add(&dispatcher);
    if (unlikely(ret != Success))
    {
        derror("failed to add module[%s] to record\n", ModuleDispatcher);
        return ret;
    }

    dprint("[%s] init success, id[%u], protocols[%u]\n", ModuleDispatcher,
        dispatcher.dcompid, (unsigned int)ARRAY_SIZE(din_protos));

    return Success;
}

static void dispatcher_exit(void)
{
    dcomp_record_del(&dispatcher);
    dprint("[%s] exit\n", ModuleDispatcher);

    return ;
}

/*
 * the dispatcher has to exist before any channel routes to it, and it has to
 * outlive every component that answers a request, so it is initialised in the
 * highest priority group and torn down in the last one.
 */
DCOMP_INIT_HIGHPRIO(dispatcher_init);
DCOMP_EXIT_HIGHPRIO(dispatcher_exit);
