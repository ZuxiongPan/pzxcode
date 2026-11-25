#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <sys/types.h>

pid_t run_new_program(const char *program, char *const args[]);

// spawn a program and block the caller until it exits. timeout_ms == 0 waits
// without a deadline, otherwise the wait gives up after timeout_ms.
// returns the child's exit code (0..255), or -WTERMSIG when it was killed by a
// signal, or a negative error: -ETIMEDOUT / -EBUSY / -EINVAL / -errno from spawn
int run_new_program_sync(const char *program, char *const args[], uint64_t timeout_ms);

// decode a wait status into the same convention run_new_program_sync returns
int child_exit_code(int wstatus);

#endif
