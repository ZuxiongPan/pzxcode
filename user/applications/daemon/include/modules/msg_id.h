#ifndef _MSG_ID_H_
#define _MSG_ID_H_

#define msg_type(msg_id) (((msg_id) & 0xFFFF0000) >> 16)
#define msg_event(msg_id) ((msg_id) & 0xFFFF)

#define MSG_TYPE_SYSTEM_START 0x00000000
#define MSG_TYPE_TIMER_START 0x00010000

#define MSG_SYSTEM_EXIT (MSG_TYPE_SYSTEM_START + 0x00000001)

#endif
