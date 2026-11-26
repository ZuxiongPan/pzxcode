#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <sys/types.h>

int run_new_program(const char *program, char *const args[], pid_t *pid_ptr);
int run_new_program_sync(const char *program, char *const args[], uint64_t timeout_ms, pid_t *pid_ptr);

// decode a wait status into the same convention run_new_program_sync returns
int child_exit_code(int wstatus);

#endif
