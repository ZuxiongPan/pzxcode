#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dcomp_name.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"

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

    if (obj != NULL && !strcmp(obj->valuestring, ModuleDispatcher))
    {
        obj = cJSON_GetObjectItem(root, "command");
        if (obj != NULL)
        {
            handle_command(obj->valuestring);
        }
    }

    cJSON_Delete(root);
    return Success;
}