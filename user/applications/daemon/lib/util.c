#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "dlog.h"
#include "lib/util.h"
#include "core/dsync.h"

extern char *environ[];

pid_t run_new_program(const char *program, char *const args[])
{
    pid_t pid = 0;
    int ret = posix_spawnp(&pid, program, NULL, NULL, args, environ);

    if (ret != 0)
    {
        return (pid_t)-ret;
    }

    return pid;
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

int run_new_program_sync(const char *program, char *const args[], uint64_t timeout_ms)
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

    // refuse before spawning anything: a child created for a wait that is going
    // to be turned down would keep running with nobody waiting for it
    if (!dsync_can_block())
    {
        derror("no worker can be spared for %s, refused\n", program);
        return -EBUSY;
    }

    pid = run_new_program(program, args);
    if (pid < 0)
    {
        derror("failed to spawn %s, ret[%d]\n", program, (int)pid);
        return (int)pid;
    }

    // the pid only exists once spawn returned, so the unit is registered and
    // armed first: a child that exits immediately would otherwise be reaped by
    // the SIGCHLD path while nobody is waiting for it, and its code is lost
    dsync_init(&unit, SyncChild, (unsigned int)pid);
    dsync_arm(&unit);

    // close the window left between spawn and arm, ask the kernel directly in
    // case the signal path already ran. 0 means the child is still running and
    // the SIGCHLD message will complete the unit later
    reaped = waitpid(pid, &wstatus, WNOHANG);
    if (reaped == pid)
    {
        dsync_complete(SyncChild, (unsigned int)pid, child_exit_code(wstatus));
    }
    else if (reaped < 0)
    {
        // ECHILD: it was collected somewhere else and will never report again,
        // completing here keeps the wait from burning the whole timeout
        dsync_complete(SyncChild, (unsigned int)pid, -1);
    }

    ret = dsync_wait(&unit, timeout_ms, &status);
    if (ret != 0)
    {
        // -EBUSY is decided before dsync_wait links the unit and a timeout
        // unlinks it, cancel is idempotent and covers both
        dsync_cancel(&unit);

        // the hint above can lose a race for the last slot: the child exists but
        // nobody will ever consume its code, so it must not be left running.
        // a timeout is different, the child may be halfway through its work and
        // is left alone, its exit is still reaped and logged later
        if (ret == -EBUSY)
        {
            kill(pid, SIGKILL);
        }

        derror("wait for %s[%d] failed, ret[%d]\n", program, (int)pid, ret);
        return ret;
    }

    return status;
}
