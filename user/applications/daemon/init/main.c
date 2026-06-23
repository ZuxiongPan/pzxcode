#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "core/bus.h"
#include "core/evloop.h"
#include "core/worker.h"
#include "core/timer.h"
#include "core/module.h"

extern int module_register_cpumem(void);

int main(/*int argc, const char *argv[]*/)
{
    int ret = 0;

    ret = evloop_init();
    if(ret != 0)
    {
        perror("evloop_init");
        return -1;
    }

    ret = timer_init();
    if(ret != 0)
    {
        perror("timer_init");
        return -1;
    }

    ret = worker_init(WORKER_MAX_CNT);
    if(ret != 0)
    {
        perror("worker_init");
        return -1;
    }

    ret = module_register_cpumem();

    module_start_all();

    evloop_run();

    return 0;
}
