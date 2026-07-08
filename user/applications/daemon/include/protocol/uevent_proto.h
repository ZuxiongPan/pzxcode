#ifndef _UEVENT_PROTO_H_
#define _UEVENT_PROTO_H_

#include <sys/types.h>

// protocol parser function must be reentrant function
int uevent_parser(const char *buf, ssize_t size);

#endif
