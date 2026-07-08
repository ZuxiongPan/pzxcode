#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "core/bus.h"
#include "core/evloop.h"
#include "core/worker.h"
#include "core/module.h"
#include "channel/uds.h"
#include "channel/tcp.h"
#include "channel/timer.h"
#include "channel/uevent.h"
#include "modules/mod_init.h"

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

    ret = uevent_init();
    if(ret != 0)
    {
        perror("uevent_init");
        return -1;
    }

    ret = uds_init();
    if(ret != 0)
    {
        perror("uds_init");
        return -1;
    }
    
    ret = tcp_init();
    if(ret != 0)
    {
        perror("tcp_init");
        return -1;
    }

    ret = worker_init(WORKER_MAX_CNT);
    if(ret != 0)
    {
        perror("worker_init");
        return -1;
    }

    ret = module_register_parser();

    module_start_all();

    evloop_run();

    return 0;
}
