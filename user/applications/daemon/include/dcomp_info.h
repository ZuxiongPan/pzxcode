#ifndef _DCOMP_INFO_H_
#define _DCOMP_INFO_H_

#define DCOMPID_STATIC_START 0U
#define DCOMPID_RESERVED DCOMPID_STATIC_START
#define DCOMPID_CHANNEL_START (DCOMPID_STATIC_START + 1U)
#define DCOMPID_MODULE_START (DCOMPID_STATIC_START + 0x4000U)
#define DCOMPID_DYNAMIC_START 0x10000U

#define ChSignalId (DCOMPID_CHANNEL_START + 0U)
#define ChSignalName "channel.signal"

#define ChTimerRepeatId (DCOMPID_CHANNEL_START + 1U)
#define ChTimerRepeatName "channel.timer.repeat"

#define ChTimerOnceId (DCOMPID_CHANNEL_START + 2U)
#define ChTimerOnceName "channel.timer.once"

#define ChUnixDomainSocketId (DCOMPID_CHANNEL_START + 3U)
#define ChUnixDomainSocketName "channel.uds"

#define ChGenericNetlinkId (DCOMPID_CHANNEL_START + 4U)
#define ChGenericNetlinkName "channel.generic-netlink"

#define ChUeventId (DCOMPID_CHANNEL_START + 5U)
#define ChUeventName "channel.uevent"


#define ModDispatcherId (DCOMPID_MODULE_START + 0U)
#define ModDispatcherName "module.dispatcher"

#define ModSignalId (DCOMPID_MODULE_START + 1U)
#define ModSignalName "module.signal"

#define ModMemblkId (DCOMPID_MODULE_START + 2U)
#define ModMemblkName "module.memblk"


// this is dynamic component, id is not fixed
#define ChUnixDomainSocketClientName "channel.uds.client"

unsigned int find_fix_dcompid(const char *name);

#endif
