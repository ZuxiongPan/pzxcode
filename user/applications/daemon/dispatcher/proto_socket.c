#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dcomp_info.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"

struct str_action {
    const char *name;
    void (*func)(const char *str);
};

static void handle_command(const char *cmd)
{
    if (strcmp(cmd, "info") == 0)
    {
        dctx_info();
        dworker_info();
        dtimer_info();
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

int msg_socket_input_handler(const struct dcomp *comp, uint32_t srcid,
    unsigned int data_size, const char *data)
{
    UNUSED(comp);
    UNUSED(srcid);

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

    cJSON_Delete(root);
    return Success;
}