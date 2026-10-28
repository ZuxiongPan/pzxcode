#ifndef _DMSGID_H_
#define _DMSGID_H_

#define msgid_type(msg_id) (((msg_id) & 0xFFFF0000) >> 16)
#define msgid_event(msg_id) ((msg_id) & 0xFFFF)

#define MSGID_SYS_START 0x00000000

#define MSGID_SYS_SIGNAL (MSGID_SYS_START + 1)
// this timer id only for sys infomation, if the module need timer
// use the self-defined msgid
#define MSGID_SYS_TIMER (MSGID_SYS_START + 2)

#define MSGID_TEST_RELATED (MSGID_SYS_START | 0x00010000)
#define MSGID_TEST_TIMER (MSGID_TEST_RELATED + 1)

#define MSGID_SELFDEF_START 0x10000000

#define MSGID_BINARY_RELATED (MSGID_SELFDEF_START | 0x00010000)
#define MSGID_SIMPLE_STR (MSGID_BINARY_RELATED + 1)
#define MSGID_JSON_STR (MSGID_BINARY_RELATED + 2)
#define MSGID_GENL_BIN (MSGID_BINARY_RELATED + 3)
#define MSGID_UEVENT_BIN (MSGID_BINARY_RELATED + 4)
#define MSGID_STATVFS_TIMER (MSGID_BINARY_RELATED + 5)

#endif
