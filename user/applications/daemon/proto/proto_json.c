#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "dlog.h"
#include "dconf.h"
#include "core/dproto.h"
#include "core/dworker.h"
#include "core/dmodule.h"
#include "module/dmsgid.h"
#include "proto/proto_api.h"
#include "lib/cJSON.h"

static dproto_t json_proto;
/**
 * json proto data format
 * {
 *     "target": "target_module",
 *     "request": "a json string data"
 * }
 */
static int json_proto_decode(const struct daemon_proto *proto, void *arg)
{
    if (NULL == arg)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    int ret = Success;
    const dtask_t *task = (dtask_t *)arg;
    const char *ptr = task->data;
    int buf_size = task->data_size;
    char buffer[buf_size];
    dproto_data_t *data = (dproto_data_t *)buffer;

    data->src_compid = task->src_compid;
    cJSON *json = cJSON_Parse(ptr);
    if (json == NULL)
    {
        derror("json parse failed\n");
        return Fail;
    }

    cJSON *item = cJSON_GetObjectItem(json, "target");
    if (item == NULL)
    {
        derror("target not found\n");
        cJSON_Delete(json);
        return Fail;
    }
    const dcomp_t *comp = find_dcomponent_by_name(item->valuestring, Layer_Module);
    if (comp == NULL)
    {
        derror("target not found\n");
        cJSON_Delete(json);
        return Fail;
    }
    data->dst_compid = comp->dcomp_id;
    item = cJSON_GetObjectItem(json, "request");
    if (item == NULL)
    {
        derror("request not found\n");
        cJSON_Delete(json);
        return Fail;
    }
    strcpy(data->json_data, item->valuestring);
    cJSON_Delete(json);
    
    ret = task_enqueue(TaskInform, proto->dcomp.dcomp_id, data->dst_compid,
        MSGID_JSON_RAWSTR, buf_size, buffer);

    return ret;
}

static int json_proto_encode(const struct daemon_proto *proto, void *arg)
{
    (void)proto;
    if (NULL == arg)
    {
        derror("the task info is invalid\n");
        return Fail;
    }
    // const dtask_t *task = (dtask_t *)arg;
    // const char *ptr = task->data;


    return 0;
}

static const proto_ops_t json_proto_ops = {
    .encode = json_proto_encode,
    .decode = json_proto_decode,
};

int proto_json_init(void)
{
    int ret = Success;
    memset(&json_proto, 0, sizeof(dproto_t));
    dcomponent_init(&json_proto.dcomp, ProtoIDJSON, "proto_json");
    json_proto.ops = &json_proto_ops;

    ret = dproto_register(&json_proto);
    if (ret != Success)
    {
        derror("json proto register failed\n");
        return Fail;
    }

    dprint("proto_json_init ret = %d\n", ret);
    return Success;
}

void proto_json_exit(void)
{
    dproto_unregister(&json_proto);
    dprint("json proto unregister done\n");
}
