#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/sysinfo.h>

#include "core/module.h"
#include "evsrc/timer.h"
#include "modules/msg_id.h"

#define MSG_ID_CPUMEM_INFO (MSG_TYPE_TIMER_START + 0x0001)
#define MSG_ID_TEST_TICK (MSG_TYPE_TIMER_START + 0x0002)

static void cpumem_info()
{
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

static void test_tick()
{
    printf("test tick\n");

    return ;
}

static int cpumem_init(struct module *m)
{
    (void)m;
    timer_add(5000, 5000, true, MSG_ID_CPUMEM_INFO, "cpumem");
    timer_add(10000, 10000, true, MSG_ID_TEST_TICK, "cpumem");

    return 0;
}

static int cpumem_on_msg(struct module *m, const message_t *msg)
{
    (void)m;

    if (msg->msg_id == MSG_ID_CPUMEM_INFO)
    {
        cpumem_info();
    }
    else if (msg->msg_id == MSG_ID_TEST_TICK)
    {
        test_tick();
    }

    return 0;
}

static const mod_ops_t cpumem_ops = {
    .init = cpumem_init,
    .start = NULL,
    .stop = NULL,
    .on_msg = cpumem_on_msg,
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
