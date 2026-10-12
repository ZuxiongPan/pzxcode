#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>

struct sync_child {
    pid_t pid;
    bool finished;
    int exit_code;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct sync_child *next;
};
typedef struct sync_child sync_child_t;

pid_t run_new_program(const char *program, char *const args[]);
int run_new_program_sync(const char *program, char *const args[]);
void set_child_finished(pid_t pid, int exit_code);

#endif