#ifndef _PARSER_H_
#define _PARSER_H_

#include <sys/types.h>
#include "core/message.h"

// protocol parser function must be reentrant function
int uevent_parser(const char *buf, ssize_t size);
int uds_parser(const char *buf, ssize_t size);
int tcp_parser(const message_t *msg);
int tcp_send(const message_t *msg);

#endif
