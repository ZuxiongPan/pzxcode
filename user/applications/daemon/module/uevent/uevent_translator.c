#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "uevent_translator.h"

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
    [KeySeqNum] = { .key = "SEQNUM=", .len = 7 },
};

void uevent_translate(const char *data, unsigned int size, uevent_strs_t *info)
{
    const char *ptr = data;

    while(ptr < data + size)
    {
        if (strncmp(ptr, uevent_keys[KeyAction].key, uevent_keys[KeyAction].len) == 0)
        {
            info->action = ptr + uevent_keys[KeyAction].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevpath].key, uevent_keys[KeyDevpath].len) == 0)
        {
            info->devpath = ptr + uevent_keys[KeyDevpath].len;
        }
        else if (strncmp(ptr, uevent_keys[KeySubsystem].key, uevent_keys[KeySubsystem].len) == 0)
        {
            info->subsystem = ptr + uevent_keys[KeySubsystem].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevname].key, uevent_keys[KeyDevname].len) == 0)
        {
            info->devname = ptr + uevent_keys[KeyDevname].len;
        }
        else if (strncmp(ptr, uevent_keys[KeyDevtype].key, uevent_keys[KeyDevtype].len) == 0)
        {
            info->devtype = ptr + uevent_keys[KeyDevtype].len;
        }
        else if ((strncmp(ptr, uevent_keys[KeySeqNum].key, uevent_keys[KeySeqNum].len) == 0))
        {
            info->seqnum = ptr + uevent_keys[KeySeqNum].len;
        }

        ptr += strlen(ptr) + 1;
    }

    dprint("------ uevent message ------\n");
    rawlog("\tseqnum = %s\n", info->seqnum ? info->seqnum : "null");
    //rawlog("\taction = %s\n", info->action ? info->action : "null");
    //rawlog("\tdevpath = %s\n", info->devpath ? info->devpath : "null");
    //rawlog("\tsubsystem = %s\n", info->subsystem ? info->subsystem : "null");
    //rawlog("\tdevname = %s\n", info->devname : "null");
    //rawlog("\tdevtype = %s\n", info->devtype : "null");
    dprint("---- uevent message end ----\n");

    return ;
}