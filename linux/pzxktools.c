#include <linux/string.h>
#include "kernel/pzxktools.h"

#define EXPANDED_STR_LEN 256

int uevent_expanded_info(struct kobject *kobj, const char *expanded)
{
    char tmp[EXPANDED_STR_LEN];
    char *envp[] = {
        tmp,
        NULL,
    };

    snprintf(tmp, sizeof(tmp), "EXPANDED=%s", expanded);
    return kobject_uevent_env(kobj, KOBJ_CHANGE, envp);
}
EXPORT_SYMBOL(uevent_expanded_info);
