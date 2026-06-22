#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/sysinfo.h>

#include "core/timer.h"
#include "core/module.h"

static void cpumem_info_cb(void *arg)
{
    (void)arg;
    struct sysinfo info = { 0 };
    if(sysinfo(&info) != 0)
    {
        perror("sysinfo");
        return;
    }

    printf("uptime: %ld min %ld seconds\n", info.uptime / 60, info.uptime % 60);
    printf("load average: 1min[%ld], 5min[%ld], 15min[%ld]\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("memory: free[%ldK]/total[%ldK]\n", info.freeram / 1024, info.totalram / 1024);

    return ;
}

static void test_tick_cb(void *arg)
{
    (void)arg;
    printf("test tick\n");

    return ;
}

static int cpumem_init(struct module *m)
{
    (void)m;
    timer_add(0, 5000, true, cpumem_info_cb, NULL);
    timer_add(0, 10000, true, test_tick_cb, NULL);

    return 0;
}

static const mod_ops_t cpumem_ops = {
    .init = cpumem_init,
    .start = NULL,
    .stop = NULL,
    .on_msg = NULL,
};

module_t cpumem_mod = {
    .name = "cpumem",
    .ops = &cpumem_ops,
    .priv = NULL,
};

int module_register_cpumem(void)
{
    return module_register(&cpumem_mod);
}