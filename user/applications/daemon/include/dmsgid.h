#ifndef _DMSGID_H_
#define _DMSGID_H_

#define MSGID_INTERNAL 0x00000000U
#define MSGID_EXTERNAL 0x10000000U

#define MSGID_SYS_START MSGID_INTERNAL
#define MSGID_SYS_SIGNAL (MSGID_SYS_START + 1)
#define MSGID_SYS_TIMER (MSGID_SYS_START + 2)

#define MSGID_INPUT_START (MSGID_INTERNAL | 0x00010000)
#define MSGID_INPUT_SOCKET (MSGID_INPUT_START + 1)
#define MSGID_INPUT_GENERIC_NETLINK (MSGID_INPUT_START + 2)
#define MSGID_INPUT_UEVENT (MSGID_INPUT_START + 3)

#define MSGID_RESPONSE_START (MSGID_INTERNAL | 0x00020000)
#define MSGID_UDS_RESPONSE (MSGID_RESPONSE_START + 1)

// channel private messages: produced and consumed by the channel itself, they
// are never forwarded to the dispatcher
#define MSGID_CHANNEL_START (MSGID_INTERNAL | 0x00030000)
#define MSGID_CHANNEL_GENL_RETRY (MSGID_CHANNEL_START + 1)

// module messages: 内核事件由 dispatcher 按 target 路由到模块时使用，每个模块
// 占一段。同一个 msgid 同时用于内核事件和 sock 请求，因为两者的 payload 都是
// 裸字符串，模块不需要区分来源。
#define MSGID_MODULE_START (MSGID_INTERNAL | 0x00040000)

#define MSGID_MEMBLK_START (MSGID_MODULE_START + 0x0100U)
#define MSGID_MEMBLK_DEV_ADD (MSGID_MEMBLK_START + 1)      // data: 设备名
#define MSGID_MEMBLK_DEV_DEL (MSGID_MEMBLK_START + 2)      // data: 设备名
#define MSGID_MEMBLK_CMD (MSGID_MEMBLK_START + 3)          // data: 命令字符串
#define MSGID_MEMBLK_STATVFS_TIMER (MSGID_MEMBLK_START + 4) // 无 payload

#define MSGID_TEST_START (MSGID_INTERNAL | 0x000f0000)
#define MSGID_TEST_TIMER (MSGID_TEST_START + 1)

#endif
