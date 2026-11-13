#ifndef _DCOMP_NAME_H_
#define _DCOMP_NAME_H_

#define ChannelSignal "channel.signal"
#define ChannelTimerRepeat "channel.timer.repeat"
#define ChannelTimerOnce "channel.timer.once"
#define ChannelUnixDomainSocket "channel.uds"
// one component per connected client, the index is appended: channel.uds.client0
#define ChannelUnixDomainSocketClient "channel.uds.client"
// kernel event sources, the daemon never sends data back to the kernel
#define ChannelGenericNetlink "channel.generic-netlink"
// retry/revalidate timer that drives the generic netlink attach state machine
#define ChannelGenericNetlinkTick "channel.generic-netlink.tick"
#define ChannelUevent "channel.uevent"

#define ModuleSignal "module.signal"
#define ModuleDispatcher "module.dispatcher"
#define ModuleUevent "module.uevent"

#endif
