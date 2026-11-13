#ifndef _DMSGID_H_
#define _DMSGID_H_

#define MSGID_INTERNAL 0x00000000U
#define MSGID_EXTERNAL 0x10000000U

#define MSGID_SYS_START MSGID_INTERNAL
#define MSGID_SYS_SIGNAL (MSGID_SYS_START + 1)
#define MSGID_SYS_TIMER (MSGID_SYS_START + 2)

// input msgids: a channel tags every message it received with the wire format
// of its own transport and sends it to ModuleDispatcher, which owns the parser
// for that msgid. a new protocol is a new MSGID_INPUT_* plus one parser, the
// channels and the routing code stay untouched.
#define MSGID_INPUT_START (MSGID_INTERNAL | 0x00010000)
#define MSGID_INPUT_JSON (MSGID_INPUT_START + 1)
#define MSGID_INPUT_GENL (MSGID_INPUT_START + 2)
#define MSGID_INPUT_UEVENT (MSGID_INPUT_START + 3)

// control request/reply pair, transport independent: after decoding, the
// dispatcher delivers the request to the addressed component with
// MSGID_UDS_REQUEST and the component answers srcid with MSGID_UDS_RESPONSE.
// the names predate the dispatcher, both are kept so every transport shares the
// same pair and a component never has to know where a request came from.
#define MSGID_UDS_START (MSGID_INTERNAL | 0x00020000)
#define MSGID_UDS_REQUEST (MSGID_UDS_START + 1)
#define MSGID_UDS_RESPONSE (MSGID_UDS_START + 2)

/*
 * kernel originated events: they flow one way only (kernel -> daemon), so a
 * component handles them with an event msgid and has nobody to answer to.
 *
 * generic netlink carries the event kind in genlmsghdr.cmd, so the parser maps
 * that byte onto MSGID_EVENT_GENL(cmd): a new command on the kernel side needs
 * no change in the daemon, the receiving component only has to register the
 * msgid it expects. cmd is u8, which is why the genl range is 256 wide.
 *
 * uevent carries no selector at all, it always arrives as MSGID_EVENT_UEVENT.
 */
#define MSGID_EVENT_START (MSGID_INTERNAL | 0x00030000)
#define MSGID_EVENT_GENL(cmd) (MSGID_EVENT_START + ((unsigned int)(cmd) & 0xffU))
#define MSGID_EVENT_UEVENT (MSGID_EVENT_START + 0x100U)

#define MSGID_TEST_START (MSGID_INTERNAL | 0x000f0000)
#define MSGID_TEST_TIMER (MSGID_TEST_START + 1)

#endif
