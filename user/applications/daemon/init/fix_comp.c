#include <string.h>

#include "dcomp_info.h"
#include "common/uk_netlink.h"

struct fix_dcomp_info {
    unsigned int id;
    const char *name;
};

static const struct fix_dcomp_info infos[] = {
    {ChSignalId, ChSignalName},
    {ChTimerRepeatId, ChTimerRepeatName},
    {ChTimerOnceId, ChTimerOnceName},
    {ChUnixDomainSocketId, ChUnixDomainSocketName},
    {ChGenericNetlinkId, ChGenericNetlinkName},
    {ChUeventId, ChUeventName},
    {ModDispatcherId, ModDispatcherName},
    {ModSignalId, ModSignalName},
    {ModMemblkId, ModMemblkName},
    // 内核通用 netlink 用裸设备名做 target（见 include/common/uk_netlink.h），
    // 这里给它挂一个别名，dispatcher 的按名路由才找得到 memblk 模块
    {ModMemblkId, USER_MEMBLK_MODNAME},
};

unsigned int find_fix_dcompid(const char *name)
{
    unsigned int ret = DCOMPID_RESERVED;

    if (name == NULL)
    {
        return ret;
    }

    for (unsigned int i = 0; i < sizeof(infos) / sizeof(infos[0]); i++)
    {
        if (strcmp(infos[i].name, name) == 0)
        {
            ret = infos[i].id;
            break;
        }
    }

    return ret;
}
