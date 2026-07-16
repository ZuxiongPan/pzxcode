#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "channel/chnl_api.h"

int main(/*int argc, const char *argv[]*/)
{
    int ret = Success;

    daemon_context_init();
    dchannel_init();

    ret = timer_add(5000, 5000, true);
    dprint("timer_add: %d\n", ret);

    ret = timer_add(3000, 3000, true);
    dprint("timer_add: %d\n", ret);

    daemon_context_run();

    ddebug("the event loop ended\n");

    return Success;
}
