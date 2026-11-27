#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "dlog.h"
#include "lib/util.h"
#include "core/dsync.h"

extern char *environ[];

int run_new_program(const char *program, char *const args[], pid_t *pid_ptr)
{
    if (program == NULL || args == NULL)
    {
        return -EINVAL;
    }

    pid_t pid = 0;
    int ret = posix_spawnp(&pid, program, NULL, NULL, args, environ);
    if (ret == 0 && pid_ptr != NULL)
    {
        *pid_ptr = pid;
    }

    return ret;
}

int child_exit_code(int wstatus)
{
    if (WIFEXITED(wstatus))
    {
        return WEXITSTATUS(wstatus);
    }

    if (WIFSIGNALED(wstatus))
    {
        return -WTERMSIG(wstatus);
    }

    return -1;
}

int run_new_program_sync(const char *program, char *const args[], uint64_t timeout_ms, pid_t *pid_ptr)
{
    struct dsync unit;
    pid_t pid = 0;
    pid_t reaped = 0;
    int wstatus = 0;
    int status = 0;
    int ret = 0;

    if (program == NULL || args == NULL)
    {
        return -EINVAL;
    }

    if (!dsync_can_block())
    {
        derror("no worker can be spared for %s, refused\n", program);
        return -EBUSY;
    }

    ret = run_new_program(program, args, &pid);
    if (ret < 0)
    {
        derror("failed to spawn %s, ret[%d]\n", program, ret);
        return ret;
    }

    if (pid <= 0)
    {
        derror("spawned %s but got no valid pid[%d]\n", program, (int)pid);
        return -EINVAL;
    }

    if (pid_ptr != NULL)
    {
        *pid_ptr = pid;
    }

    dsync_init(&unit, SyncChild, (unsigned int)pid);
    dsync_arm(&unit);

    reaped = waitpid(pid, &wstatus, WNOHANG);
    if (reaped == pid)
    {
        dsync_complete(SyncChild, (unsigned int)pid, child_exit_code(wstatus));
    }
    else if (reaped < 0)
    {
        dsync_complete(SyncChild, (unsigned int)pid, -1);
    }

    ret = dsync_wait(&unit, timeout_ms, &status);
    if (ret != 0)
    {
        dsync_cancel(&unit);
        if (ret == -EBUSY)
        {
            kill(pid, SIGKILL);
        }

        derror("wait for %s[%d] failed, ret[%d]\n", program, (int)pid, ret);
        return ret;
    }

    return status;
}
