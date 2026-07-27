#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dworker.h"
#include "core/dmodule.h"
#include "core/dcontext.h"
#include "module/mod_api.h"
#include "module/dmsgid.h"
#include "module/mod_data.h"

enum uevent_keys_id {
    KeyAction = 0,
    KeyDevpath,
    KeySubsystem,
    KeyDevname,
    KeyDevtype,
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
};

typedef struct uevent_msg {
    const char *action;
    const char *devpath;
    const char *subsystem;
    const char *devname;
    const char *devtype;
} uevent_msg_t;

static dproto_t uevent_proto;

static void translate_block_kernel_msg(const uevent_msg_t *msg);

static int uevent_proto_decode(const struct daemon_proto *proto, void *inbuf,
    unsigned int inbuf_size, void *data)
{
    (void)inbuf;
    (void)inbuf_size;
    dpdata_t *pdata = (dpdata_t *)data;
    dtask_t *task = proto->task_tmp;
    unsigned int data_size = task ? task->data_size : 0;
    const char *ptr = pdata->data;
    uevent_msg_t msg;
    memset(&msg, 0, sizeof(uevent_msg_t));

    while(ptr < pdata->data + pdata->data_size)
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

        ptr += strlen(ptr) + 1;
    }

    if (msg.subsystem != NULL && strcmp(msg.subsystem, "block") == 0)
    {
        translate_block_kernel_msg(&msg);
        dprint("------ uevent message ------\n");
        dprint("\t[%u]action = %s\n", data_size, msg.action ? msg.action : "null");
        dprint("\t[%u]devpath = %s\n", data_size, msg.devpath ? msg.devpath : "null");
        dprint("\t[%u]subsystem = %s\n", data_size, msg.subsystem ? msg.subsystem : "null");
        dprint("\t[%u]devname = %s\n", data_size, msg.devname ? msg.devname : "null");
        dprint("\t[%u]devtype = %s\n", data_size, msg.devtype ? msg.devtype : "null");
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
    dcomponent_init(&uevent_proto.dcomp, dproto_get_name(ProtoUevent));
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
        snprintf(data.blkdev_name, BLKDEV_NAME_MAXLEN, "%s", msg->devpath);
        const dcomp_t *blk = find_dcomponent_by_name("dblock", Layer_Module);
        if (NULL != blk)
        {
            dmodule_create_task(uevent_proto.dcomp.dcomp_id, blk->dcomp_id,
                msgid, sizeof(data), &data);
        }
        else
        {
            derror("translate_block_kernel_msg: no target\n");
        }
    }

    return ;
}
