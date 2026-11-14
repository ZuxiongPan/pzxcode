#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "core/dworker.h"
#include "core/dfuncalls.h"

static void dcomp_highprio_init(void);
static void dcomp_normprio_init(void);
static void dcomp_lowprio_init(void);
static void dcomp_highprio_exit(void);
static void dcomp_normprio_exit(void);
static void dcomp_lowprio_exit(void);

int main(/*int argc, const char *argv[]*/)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    dctx_init();

    dcomp_highprio_init();
    dcomp_normprio_init();
    dcomp_lowprio_init();

    start_dctx_evloop();

    // stop the workers before running the exit handlers, otherwise they may
    // still dispatch a queued task to a component that is being unregistered
    worker_mgr_stop();

    dcomp_lowprio_exit();
    dcomp_normprio_exit();
    dcomp_highprio_exit();

    dctx_destroy();

    return Success;
}

static void dcomp_highprio_init(void)
{
    extern dcomp_init_f __attribute__((weak)) __start_highprio_initfuncs[];
    extern dcomp_init_f __attribute__((weak)) __stop_highprio_initfuncs[];

    int inner_ret = Success;
    dcomp_init_f *func = __start_highprio_initfuncs;
    while (func < __stop_highprio_initfuncs)
    {
        inner_ret = (*func)();
        if (unlikely(inner_ret != Success))
        {
            derror("highprio init %p ret %d\n", func, inner_ret);
        }
        func++;
    }

    return ;
}

static void dcomp_normprio_init(void)
{
    extern dcomp_init_f __attribute__((weak)) __start_normprio_initfuncs[];
    extern dcomp_init_f __attribute__((weak)) __stop_normprio_initfuncs[];

    int inner_ret = Success;
    dcomp_init_f *func = __start_normprio_initfuncs;
    while (func < __stop_normprio_initfuncs)
    {
        inner_ret = (*func)();
        if (unlikely(inner_ret != Success))
        {
            derror("normprio init %p ret %d\n", func, inner_ret);
        }
        func++;
    }

    return ;
}

static void dcomp_lowprio_init(void)
{
    extern dcomp_init_f __attribute__((weak)) __start_lowprio_initfuncs[];
    extern dcomp_init_f __attribute__((weak)) __stop_lowprio_initfuncs[];

    int inner_ret = Success;
    dcomp_init_f *func = __start_lowprio_initfuncs;
    while (func < __stop_lowprio_initfuncs)
    {
        inner_ret = (*func)();
        if (unlikely(inner_ret != Success))
        {
            derror("lowprio init %p ret %d\n", func, inner_ret);
        }
        func++;
    }

    return ;
}

static void dcomp_highprio_exit(void)
{
    extern dcomp_exit_f __attribute__((weak)) __start_highprio_exitfuncs[];
    extern dcomp_exit_f __attribute__((weak)) __stop_highprio_exitfuncs[];

    dcomp_exit_f *func = __start_highprio_exitfuncs;
    while (func < __stop_highprio_exitfuncs)
    {
        (*func)();
        func++;
    }

    return ;
}

static void dcomp_normprio_exit(void)
{
    extern dcomp_exit_f __attribute__((weak)) __start_normprio_exitfuncs[];
    extern dcomp_exit_f __attribute__((weak)) __stop_normprio_exitfuncs[];

    dcomp_exit_f *func = __start_normprio_exitfuncs;
    while (func < __stop_normprio_exitfuncs)
    {
        (*func)();
        func++;
    }

    return ;
}

static void dcomp_lowprio_exit(void)
{
    extern dcomp_exit_f __attribute__((weak)) __start_lowprio_exitfuncs[];
    extern dcomp_exit_f __attribute__((weak)) __stop_lowprio_exitfuncs[];

    dcomp_exit_f *func = __start_lowprio_exitfuncs;
    while (func < __stop_lowprio_exitfuncs)
    {
        (*func)();
        func++;
    }

    return ;
}
