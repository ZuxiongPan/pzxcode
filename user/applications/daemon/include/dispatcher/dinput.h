#ifndef _DINPUT_H_
#define _DINPUT_H_

#include <stdint.h>

/*
 * one decoded input message
 *
 * a channel is transport only: it reads bytes and has no idea what they mean.
 * it tags the task with the input msgid matching the wire format of its own
 * transport (MSGID_INPUT_JSON for the unix socket control channel,
 * MSGID_INPUT_GENL for generic netlink, MSGID_INPUT_UEVENT for kobject uevents)
 * and sends it to ModuleDispatcher.
 * the dispatcher owns one parser per input msgid, so a new protocol is a new
 * proto_*.c file plus one entry in the dispatcher table, nothing else moves.
 *
 * a parser fills this structure and keeps ownership of anything it allocated
 * through priv/release. the dispatcher calls release() once the message has
 * been forwarded, so payload/target only have to stay valid that long.
 *
 * payload contract
 *   text formats (json): payload is NUL terminated and payload_len counts that
 *   NUL, so a handler may use strlen()/printf() without looking at data_size.
 *   binary formats (generic netlink): payload is not terminated, payload_len is
 *   the exact byte count and the bytes may contain NUL.
 *   normalised formats (uevent): the parser rewrites the kernel's NUL separated
 *   packet into one field per line, NUL terminated, so it prints as is.
 */
struct dinput {
    const char *target;         // destination component name, NUL terminated
    unsigned int msgid;         // msgid the destination receives
    const char *payload;        // bytes forwarded to the destination
    unsigned int payload_len;
    void *priv;                 // parser owned state, opaque to the dispatcher
    void (*release)(struct dinput *in);
    char reason[96];            // filled by the parser when it returns Fail
};

// longest component name accepted from an input message
#define DIN_TARGET_MAXLEN 64U

/*
 * generic netlink attributes understood by the MSGID_INPUT_GENL parser
 *
 *   struct nlmsghdr
 *   struct genlmsghdr
 *   nlattr DIN_GENL_ATTR_TARGET   string, destination component
 *   nlattr DIN_GENL_ATTR_DATA     binary payload, optional
 *   nlattr DIN_GENL_ATTR_MSGID    u32, msgid for the destination, optional
 *
 * the destination msgid defaults to MSGID_EVENT_GENL(genlmsghdr.cmd): the
 * daemon never sends to the kernel, so every generic netlink message it sees is
 * an event whose kind the kernel encodes in cmd. an explicit
 * DIN_GENL_ATTR_MSGID overrides that, which is what a test or a future sender
 * that wants to address an ordinary request msgid uses.
 */
enum din_genl_attr {
    DIN_GENL_ATTR_UNSPEC = 0,
    DIN_GENL_ATTR_TARGET,
    DIN_GENL_ATTR_DATA,
    DIN_GENL_ATTR_MSGID,
    DIN_GENL_ATTR_MAX,
};

/*
 * kobject uevent wire format, MSGID_INPUT_UEVENT
 *
 * the kernel hands over one datagram of NUL separated fields, the first one
 * being "ACTION@DEVPATH":
 *
 *   add@/devices/virtual/net/dummy0\0ACTION=add\0DEVPATH=/devices/...\0...
 *
 * there is no destination field, so the parser routes the message to
 * ModuleUevent and rewrites it into one field per line (see the payload
 * contract above). nothing is dropped or reinterpreted: the fields keep the
 * order and the text the kernel used, which is what makes the dump useful.
 */

#endif
