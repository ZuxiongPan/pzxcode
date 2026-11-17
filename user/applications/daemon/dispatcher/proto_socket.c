#include <errno.h>
#include <string.h>

#include "proto.h"
#include "dlog.h"
#include "dcomp_name.h"
#include "lib/cJSON.h"

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
    const char *target = obj->valuestring;

    if (target != NULL && !strcmp(target, ModuleDispatcher))
    {
        dprint("dispatcher socket input\n");
    }

    return Success;
}