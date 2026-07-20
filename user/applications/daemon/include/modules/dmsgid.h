#ifndef _DMSGID_H_
#define _DMSGID_H_

#define msgid_type(msg_id) (((msg_id) & 0xFFFF0000) >> 16)
#define msgid_event(msg_id) ((msg_id) & 0xFFFF)

#define MSGID_SYS_START 0x00000000
#define MSGID_TIMER (MSGID_SYS_START | 0x0001)

#define MSGID_BLKDEV_START 0x00010000
#define MSGID_BLKDEV_ADD (MSGID_BLKDEV_START | 0x0001)
#define MSGID_BLKDEV_REMOVE (MSGID_BLKDEV_START | 0x0002)

#endif
