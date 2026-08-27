#include <signal.h>
#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "channel/chnl_api.h"
#include "module/mod_api.h"

static void signal_handler(int signum)
{  
    dmodule_exit();
    dchannel_exit();
    daemon_context_destroy();
    ddebug("receive signal %d, the event loop ended\n", signum);

    return ;
}

int main(/*int argc, const char *argv[]*/)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    daemon_context_init();
    dchannel_init();
    dmodule_init();

    daemon_context_run();

    return Success;
}
