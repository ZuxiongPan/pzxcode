#ifndef _RUN_H_
#define _RUN_H_

#include <sys/types.h>

pid_t run_new_program(const char *program, char *args[]);

#endif