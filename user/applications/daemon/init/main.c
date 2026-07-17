#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "channel/chnl_api.h"

int main(/*int argc, const char *argv[]*/)
{
    daemon_context_init();
    dchannel_init();

    daemon_context_run();

    dchannel_exit();
    daemon_context_destroy();
    ddebug("the event loop ended\n");

    return Success;
}
