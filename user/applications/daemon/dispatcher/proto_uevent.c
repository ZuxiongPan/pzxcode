/*
 * kobject uevent wire format, MSGID_INPUT_UEVENT
 *
 * the kernel sends one datagram of NUL separated fields, the first one being
 * "ACTION@DEVPATH" (the exact layout is documented in
 * include/dispatcher/dinput.h). the parser only normalises: a terminal cannot
 * print a NUL separated packet, so every field gets its own line. order and
 * text stay exactly as the kernel wrote them - nothing is split into key/value
 * pairs, because the whole point of this channel is to show what really
 * arrived, byte for byte.
 *
 * the packet carries no destination, so it always goes to ModuleUevent with
 * MSGID_EVENT_UEVENT.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dcomp_name.h"
#include "dextension.h"
#include "dispatcher/dinput.h"

static void din_uevent_release(struct dinput *in)
{
    // the normalised text is the only thing this parser allocates
    free((void *)in->payload);
    in->payload = NULL;
    in->payload_len = 0;
    in->priv = NULL;
    in->release = NULL;

    return ;
}

int din_parse_uevent(const char *data, unsigned int size, struct dinput *in)
{
    char *text = NULL;
    unsigned int fields = 0;
    unsigned int start = 0;
    unsigned int out = 0;
    unsigned int i = 0;

    // first pass counts the non empty fields, so an empty packet is rejected
    // before anything is allocated
    for (i = 0; i <= size; i++)
    {
        if (i < size && data[i] != '\0')
        {
            continue;
        }
        if (i > start)
        {
            fields++;
        }
        start = i + 1U;
    }

    if (fields == 0)
    {
        snprintf(in->reason, sizeof(in->reason), "uevent packet has no fields");
        return Fail;
    }

    // the fields together never exceed the packet, plus one newline each and the
    // terminator, so size + 2 is always enough
    text = calloc(1, (size_t)size + 2U);
    if (unlikely(text == NULL))
    {
        snprintf(in->reason, sizeof(in->reason),
            "no memory for a %u byte uevent", size);
        return Fail;
    }

    // second pass writes one field per line, keeping the kernel's order
    start = 0;
    for (i = 0; i <= size; i++)
    {
        if (i < size && data[i] != '\0')
        {
            continue;
        }
        if (i > start)
        {
            memcpy(text + out, data + start, i - start);
            out += i - start;
            text[out] = '\n';
            out++;
        }
        start = i + 1U;
    }

    in->target = ModuleUevent;
    in->msgid = MSGID_EVENT_UEVENT;
    in->payload = text;
    // normalised text payload: payload_len counts the terminating NUL, so the
    // module can print it as a C string and still know the real size
    in->payload_len = out + 1U;
    in->priv = text;
    in->release = din_uevent_release;

    return Success;
}
