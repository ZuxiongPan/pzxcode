#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dcomp_info.h"
#include "dmsgid.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dsync.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"

struct str_action {
    const char *name;
    void (*func)(const char *str);
};

/*
 * 模块入口表：sock 请求的 target 命中这里的名字，就把 command 字符串原样投给
 * 该模块，模块自己解释命令。内核事件的入口在 dispatcher，那边按普通 netlink
 * 的 target 路由，两边用同一套 msgid。
 */
struct module_route {
    const char *name;
    unsigned int msgid;
};

static const struct module_route module_routes[] = {
    { ModMemblkName, MSGID_MEMBLK_CMD },
};

static void handle_command(const char *cmd)
{
    if (strcmp(cmd, "info") == 0)
    {
        dctx_info();
        dworker_info();
        dtimer_info();
        dsync_info();
    }
    else
    {
        derror("invalid command, cmd[%s]\n", cmd);
    }

    return ;
}

static void handle_result(const char *res)
{
    dprint("result: %s\n", res);

    return ;
}

static const struct str_action str_actions[] = {
    { "command", handle_command },
    { "result", handle_result },
    { NULL, NULL }
};

/* 把请求转给模块，srcid 保持不变，模块的应答才能回到这个客户端 */
static int socket_route_to_module(unsigned int srcid, const char *target,
    const char *command)
{
    for (unsigned int i = 0; i < sizeof(module_routes) / sizeof(module_routes[0]); i++)
    {
        const struct dcomp *dst = NULL;

        if (strcmp(module_routes[i].name, target) != 0)
        {
            continue;
        }

        dst = find_dcomp_by_name(target);
        if (dst == NULL)
        {
            derror("target[%s] is not registered\n", target);
            return Fail;
        }

        // 带上结尾 NUL，模块可以当 C 字符串用
        return task_enqueue_by_id(srcid, dst->dcompid, module_routes[i].msgid,
            (unsigned int)strlen(command) + 1, command);
    }

    derror("no route for target[%s]\n", target);
    return Fail;
}

int msg_socket_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    cJSON *obj = NULL;

    if (unlikely(data_size == 0 || data == NULL))
    {
        derror("invalid input data, size[%u], data[%p]\n", data_size, data);
        return -EINVAL;
    }

    cJSON *root = cJSON_Parse(data);
    if (root == NULL)
    {
        derror("invalid input data, size[%u], data[%p]\n", data_size, data);
        return -EINVAL;
    }

    obj = cJSON_GetObjectItem(root, "target");

    if (obj != NULL && obj->valuestring != NULL &&
        !strcmp(obj->valuestring, ModDispatcherName))
    {
        for (int i = 0; str_actions[i].name != NULL; i++)
        {
            obj = cJSON_GetObjectItem(root, str_actions[i].name);
            if (obj != NULL && obj->valuestring != NULL)
            {
                str_actions[i].func(obj->valuestring);
                break;
            }
        }
    }
    else if (obj != NULL && obj->valuestring != NULL)
    {
        cJSON *cmd = cJSON_GetObjectItem(root, "command");

        if (cmd == NULL || cmd->valuestring == NULL)
        {
            derror("request for target[%s] without command\n", obj->valuestring);
        }
        else if (socket_route_to_module(srcid, obj->valuestring, cmd->valuestring) != Success)
        {
            derror("request for target[%s] dropped\n", obj->valuestring);
        }
    }
    else
    {
        derror("request without target from comp[%u]\n", srcid);
    }

    UNUSED(comp);

    cJSON_Delete(root);
    return Success;
}
