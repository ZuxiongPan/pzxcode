#ifndef _MSGID_H_
#define _MSGID_H_

#define msg_type(msg_id) (((msg_id) & 0xFFFF0000) >> 16)
#define msg_event(msg_id) ((msg_id) & 0xFFFF)

#define MSG_TYPE_SYSTEM_START 0x00000000

#define MSG_UDS (MSG_TYPE_SYSTEM_START + 0x00000001)
#define MSG_UEVENT (MSG_TYPE_SYSTEM_START + 0x00000003)

#define MSG_TYPE_TCP_START 0x00010000

#endif
