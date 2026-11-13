#ifndef _CHNL_API_H_
#define _CHNL_API_H_

#include <stdbool.h>
#include <stdint.h>
#include <linux/netlink.h>

// generic netlink attribute decoding used to live here (genl_parse_attrs_armd,
// implemented inside the channel). the channel is transport only now, the parser
// belongs to the dispatcher: see dispatcher/proto_genl.c and
// include/dispatcher/dinput.h.

int timer_add(uint64_t timeout_ms, uint64_t interval_ms, bool repeat,
            unsigned int modid, unsigned int msgid);
void timer_del(int timer_id);
int dtimer_info(char *inbuf, int bufsize);

#endif
