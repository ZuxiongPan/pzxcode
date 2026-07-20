#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dworker.h"

static dproto_t uevent_proto;

static int uevent_proto_decode(const struct daemon_proto *proto, void *inbuf,
    unsigned int inbuf_size, void *data)
{
    (void)proto;
    (void)inbuf;
    (void)inbuf_size;
    dpdata_t *pdata = (dpdata_t *)data;
    char *raw_data = pdata->data;
    ssize_t len = 0;

    dprint("------ uevent message ------\n");
    while(len < pdata->data_size)
    {
        dprint("\t%s\n", raw_data + len);
        len += strlen(raw_data + len) + 1;
    }
    dprint("---- uevent message end ----\n");

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
