#ifndef _DCOMP_NAME_H_
#define _DCOMP_NAME_H_

#define ChannelSignal "channel.signal"
#define ChannelTimerRepeat "channel.timer.repeat"
#define ChannelTimerOnce "channel.timer.once"
#define ChannelUnixDomainSocket "channel.uds"
#define ChannelGenericNetlink "channel.generic-netlink"
#define ChannelUevent "channel.uevent"

// all connected clients under same channel use the same name
// task_enqueue will check dest name and refuse enqueue "client" included task
#define ChannelUnixDomainSocketClient "channel.uds.client"

#define ModuleSignal "module.signal"
#define ModuleDispatcher "module.dispatcher"
#define ModuleUevent "module.uevent"

#endif
