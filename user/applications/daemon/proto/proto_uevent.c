#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dworker.h"
#include "core/dmodule.h"
#include "module/mod_api.h"
#include "module/dmsgid.h"
#include "module/mod_data.h"

enum uevent_keys_id {
    KeyAction = 0,
    KeyDevpath,
    KeySubsystem,
    KeyDevname,
    KeyDevtype,
    KeySeqNum,
};

typedef struct uevent_keyinfo {
    const char *key;
    int len;
} keyinfo_t;

static const keyinfo_t uevent_keys[] = {
    [KeyAction] = { .key = "ACTION=", .len = 7 },
    [KeyDevpath] = { .key = "DEVPATH=", .len = 8 },
    [KeySubsystem] = { .key = "SUBSYSTEM=", .len = 10 },
    [KeyDevname] = { .key = "DEVNAME=", .len = 8 },
    [KeyDevtype] = { .key = "DEVTYPE=", .len = 8 },
    [KeySeqNum] = { .key = "SEQNUM=", .len = 7 },
};

typedef struct uevent_msg {
    const char *action;
    const char *devpath;
    const char *subsystem;
    const char *devname;
    const char *devtype;
    const char *seqnum;
} uevent_msg_t;

static dproto_t uevent_proto;

static void translate_block_kernel_msg(const uevent_msg_t *msg);

static int uevent_proto_decode(const struct daemon_proto *proto, void *arg)
{
    (void)proto;
    if (NULL == arg)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    const dtask_t *task = (dtask_t *)arg;
    const char *ptr = task->data;
    uevent_msg_t msg;
    memset(&msg, 0, sizeof(uevent_msg_t));

    while(ptr < task->data + task->data_size)
    {
        if (strncmp(ptr, uevent_keys[KeyAction].key, uevent_keys[KeyAction].len) == 0)
        {
            msg.action = ptr + uevent_keys[KeyAction].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevpath].key, uevent_keys[KeyDevpath].len) == 0)
        {
            msg.devpath = ptr + uevent_keys[KeyDevpath].len;
        }
        else if (strncmp(ptr, uevent_keys[KeySubsystem].key, uevent_keys[KeySubsystem].len) == 0)
        {
            msg.subsystem = ptr + uevent_keys[KeySubsystem].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevname].key, uevent_keys[KeyDevname].len) == 0)
        {
            msg.devname = ptr + uevent_keys[KeyDevname].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevtype].key, uevent_keys[KeyDevtype].len) == 0)
        {
            msg.devtype = ptr + uevent_keys[KeyDevtype].len;
        }
        else if ((strncmp(ptr, uevent_keys[KeySeqNum].key, uevent_keys[KeySeqNum].len) == 0))
        {
            msg.seqnum = ptr + uevent_keys[KeySeqNum].len;
        }

        ptr += strlen(ptr) + 1;
    }

    if (msg.subsystem != NULL && strcmp(msg.subsystem, "block") == 0)
    {
        translate_block_kernel_msg(&msg);
        if (NULL == msg.seqnum)
        {
            msg.seqnum = "seqnum invalid";
        }
        dprint("------ uevent message ------\n");
        dprint("\t[%s]action = %s\n", msg.seqnum, msg.action ? msg.action : "null");
        dprint("\t[%s]devpath = %s\n", msg.seqnum, msg.devpath ? msg.devpath : "null");
        dprint("\t[%s]subsystem = %s\n", msg.seqnum, msg.subsystem ? msg.subsystem : "null");
        dprint("\t[%s]devname = %s\n", msg.seqnum, msg.devname ? msg.devname : "null");
        dprint("\t[%s]devtype = %s\n", msg.seqnum, msg.devtype ? msg.devtype : "null");
        dprint("---- uevent message end ----\n");
    }

    return 0;
}

static const proto_ops_t uevent_proto_ops = {
    .encode = NULL,
    .decode = uevent_proto_decode,
};

int proto_uevent_init(void)
{
    int ret = Success;
    memset(&uevent_proto, 0, sizeof(dproto_t));
    dcomponent_init(&uevent_proto.dcomp, ProtoIDUevent, "proto_uevent");
    uevent_proto.ops = &uevent_proto_ops;

    ret = dproto_register(&uevent_proto);
    if (ret != Success)
    {
        derror("proto_uevent_init: uevent proto register failed\n");
        return Fail;
    }

    dprint("proto_uevent_init: ret = %d\n", ret);
    return Success;
}

void proto_uevent_exit(void)
{
    dproto_unregister(&uevent_proto);
    dprint("proto_uevent_exit: uevent proto unregister done\n");
}

static void translate_block_kernel_msg(const uevent_msg_t *msg)
{
    blk_info_t data = { 0 };
    unsigned int msgid = 0;
    if (NULL != msg->action && !strcmp(msg->action, "add"))
    {
        msgid = MSGID_BLKDEV_ADD;
    }
    else if (NULL != msg->action && !strcmp(msg->action, "remove"))
    {
        msgid = MSGID_BLKDEV_REMOVE;
    }

    if (NULL != msg->devtype && !strcmp(msg->devtype, "disk"))
    {
        snprintf(data.blkdev_name, BLKDEV_NAME_MAXLEN, "%s", msg->devname);
        int ret = task_enqueue(TaskInform, uevent_proto.dcomp.dcomp_id, ModuleIDBlock,
            msgid, sizeof(data), (const char *)&data);
        dprint("send message to mod block ret %d\n", ret);
    }

    return ;
}
