#ifndef _UEVENT_TRANSLATOR_H_
#define _UEVENT_TRANSLATOR_H_

enum uevent_keys_id {
    KeyAction = 0,
    KeyDevpath,
    KeySubsystem,
    KeyDevname,
    KeyDevtype,
    KeySeqNum,
};

typedef struct uevent_strs {
    const char *action;
    const char *devpath;
    const char *subsystem;
    const char *devname;
    const char *devtype;
    const char *seqnum;
} uevent_strs_t;

void uevent_translate(const char *data, unsigned int size, uevent_strs_t *info);

#endif