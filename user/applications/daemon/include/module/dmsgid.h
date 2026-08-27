#ifndef _DMSGID_H_
#define _DMSGID_H_

#define msgid_type(msg_id) (((msg_id) & 0xFFFF0000) >> 16)
#define msgid_event(msg_id) ((msg_id) & 0xFFFF)

#define MSGID_SYS_START 0x00000000

#define MSGID_TEST_RELATED (MSGID_SYS_START | 0x00010000)
#define MSGID_TEST_TIMER (MSGID_TEST_RELATED + 1)

#define MSGID_SELFDEF_START 0x10000000

#define MSGID_STRING_RELATED (MSGID_SELFDEF_START | 0x00010000)
#define MSGID_JSON_RAWSTR (MSGID_STRING_RELATED + 1)

#endif
