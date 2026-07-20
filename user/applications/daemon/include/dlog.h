#ifndef _DLOG_H_
#define _DLOG_H_

#include <stdio.h>

#define ddebug(fmt, ...) printf("[debug] " fmt, ##__VA_ARGS__)
#define dprint(fmt, ...) printf("[log] " fmt, ##__VA_ARGS__)
#define derror(fmt, ...) printf("[error] "fmt, ##__VA_ARGS__)
#define demerg(fmt, ...) printf("[emerg] "fmt, ##__VA_ARGS__)

#endif