#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "lib/util.h"

extern char *environ[];

static sync_child_t *sync_child_list = NULL;
static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;

pid_t run_new_program(const char *program, char *const args[])
{
    pid_t pid = 0;
    int ret = posix_spawnp(&pid, program, NULL, NULL, args, environ);
    if(ret != 0)
    {
        return -1;
    }

    return pid;
}

int run_new_program_sync(const char *program, char *const args[])
{
    pid_t pid = 0;
    int ret = posix_spawnp(&pid, program, NULL, NULL, args, environ);
    if (ret != 0)
    {
        return -1;
    }

    sync_child_t child;
    child.pid = pid;
    child.finished = false;
    child.exit_code = -1;
    pthread_mutex_init(&child.mutex, NULL);
    pthread_cond_init(&child.cond, NULL);
    child.next = NULL;

    pthread_mutex_lock(&list_lock);
    child.next = sync_child_list;
    sync_child_list = &child;
    pthread_mutex_unlock(&list_lock);

    pthread_mutex_lock(&child.mutex);
    while (!child.finished)
    {
        pthread_cond_wait(&child.cond, &child.mutex);
    }
    ret = child.exit_code;
    pthread_mutex_unlock(&child.mutex);

    pthread_mutex_destroy(&child.mutex);
    pthread_cond_destroy(&child.cond);

    return ret;
}

void set_child_finished(pid_t pid, int exit_code)
{
    pthread_mutex_lock(&list_lock);
    sync_child_t **child = &sync_child_list;
    while (*child != NULL)
    {
        if ((*child)->pid == pid)
        {
            pthread_mutex_lock(&((*child)->mutex));
            (*child)->finished = true;
            (*child)->exit_code = exit_code;
            pthread_cond_signal(&((*child)->cond));
            pthread_mutex_unlock(&((*child)->mutex));
            break;
        }
        child = &((*child)->next);
    }
    pthread_mutex_unlock(&list_lock);

    return ;
}
