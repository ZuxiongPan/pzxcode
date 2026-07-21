#include "dlog.h"
#include "dconf.h"
#include "core/dcontext.h"
#include "channel/chnl_api.h"
#include "proto/proto_api.h"
#include "module/mod_api.h"

int main(/*int argc, const char *argv[]*/)
{
    daemon_context_init();
    dchannel_init();
    dproto_init();
    dmodule_init();

    daemon_context_run();

    dmodule_exit();
    dproto_exit();
    dchannel_exit();
    daemon_context_destroy();
    ddebug("the event loop ended\n");

    return Success;
}
