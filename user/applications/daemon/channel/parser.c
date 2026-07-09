/**
 * this is a parser, the parser should run in different channel code,
 * such as uevent/uds/client, which will make channel become slow,
 * for efficiency, the parser designed as a module, it will not block the channel message receive.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/sysinfo.h>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          

#include "core/module.h"
#include "modules/msgid.h"
#include "protocol/parser.h"

static int parser_on_msg(struct module *m, const message_t *msg)
{
    (void)m;
    int ret = 0;

    // msg here is a heap memory, it is only used by parser, this function is reentrant
    switch (msg->msg_id)
    {
        case MSG_UDS:
            ret = uds_parser(msg->payload, msg->payload_len);
            break;
        case MSG_UEVENT:
            ret = uevent_parser(msg->payload, msg->payload_len);
            break;
        default:
            printf("parser: unknown msg_id 0x%x\n", msg->msg_id);
            break;
    }

    return ret;
}

static const mod_ops_t parser_ops = {
    .init = NULL,
    .start = NULL,
    .stop = NULL,
    .on_msg = parser_on_msg,
};

module_t parser_mod = {
    .name = "parser",
    .ops = &parser_ops,
    .priv = NULL,
};

int module_register_parser(void)
{
    return module_register(&parser_mod);
}
