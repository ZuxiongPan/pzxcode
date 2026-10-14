#ifndef _PZXKTOOLS_H_
#define _PZXKTOOLS_H_

int pzx_netlink_async_send(u32 cmd, const char *target, const void *data, size_t data_len);

#endif
