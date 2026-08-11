#ifndef _DLOG_H_
#define _DLOG_H_

#include <stdio.h>

#define ddebug(fmt, ...) printf("[%s@%d]-debug# " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define dprint(fmt, ...) printf("[%s@%d]-log# " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define derror(fmt, ...) printf("[%s@%d]-error# " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define demerg(fmt, ...) printf("[%s@%d]-emerg# " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define rawlog(fmt, ...) printf(fmt, ##__VA_ARGS__)

#endif