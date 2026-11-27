#include <string.h>

#include "dcomp_info.h"

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
