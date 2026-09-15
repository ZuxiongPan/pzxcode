#include <spawn.h>

#include "lib/run.h"

extern char *environ[];

pid_t run_new_program(const char *program, char *args[])
{
    pid_t pid = 0;
    int ret = posix_spawnp(&pid, program, NULL, NULL, args, environ);
    if(ret != 0)
    {
        return -1;
    }

    return pid;
}
