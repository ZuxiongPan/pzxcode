/*
 * json wire format, MSGID_INPUT_JSON
 *
 *     {"target":"status","data":"context"}
 *
 *   target  component name, required, must be a string
 *   data    payload for the component, optional, must be a string when present
 *
 * both fields are plain strings, so the payload reaches the component byte for
 * byte after the escapes have been decoded. the request is length delimited: a
 * task slot is not NUL terminated, so cJSON is handed the size and the bytes
 * after the value are checked for garbage instead of trusting a terminator.
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "dlog.h"
#include "dconf.h"
#include "dmsgid.h"
#include "dextension.h"
#include "dispatcher/dinput.h"
#include "lib/cJSON.h"

static void din_json_release(struct dinput *in)
{
    // the target and payload strings live inside the parsed tree
    cJSON_Delete((cJSON *)in->priv);
    in->priv = NULL;
    in->release = NULL;

    return ;
}

// the daemon must not accept "{"a":1}garbage", cJSON happily stops at the value
static bool din_json_tail_is_blank(const char *tail, const char *end)
{
    for (const char *p = tail; p < end; p++)
    {
        if (*p != '\0' && !isspace((unsigned char)*p))
        {
            return false;
        }
    }

    return true;
}

int din_parse_json(const char *data, unsigned int size, struct dinput *in)
{
    const char *end = NULL;
    cJSON *root = NULL;
    cJSON *target = NULL;
    cJSON *payload = NULL;
    const char *text = NULL;

    root = cJSON_ParseWithLengthOpts(data, (size_t)size, &end, 0);
    if (root == NULL)
    {
        snprintf(in->reason, sizeof(in->reason), "invalid json");
        return Fail;
    }

    if (unlikely(end != NULL && !din_json_tail_is_blank(end, data + size)))
    {
        snprintf(in->reason, sizeof(in->reason), "trailing bytes after json");
        goto fail;
    }

    if (unlikely(!cJSON_IsObject(root)))
    {
        snprintf(in->reason, sizeof(in->reason), "json root is not an object");
        goto fail;
    }

    target = cJSON_GetObjectItemCaseSensitive(root, "target");
    if (unlikely(!cJSON_IsString(target) || target->valuestring == NULL ||
        target->valuestring[0] == '\0'))
    {
        snprintf(in->reason, sizeof(in->reason), "missing string field [target]");
        goto fail;
    }

    payload = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (payload == NULL || cJSON_IsNull(payload))
    {
        // a request without data is legal, the component gets an empty payload
        text = "";
    }
    else if (cJSON_IsString(payload) && payload->valuestring != NULL)
    {
        text = payload->valuestring;
    }
    else
    {
        snprintf(in->reason, sizeof(in->reason), "field [data] is not a string");
        goto fail;
    }

    in->target = target->valuestring;
    in->msgid = MSGID_UDS_REQUEST;
    in->payload = text;
    // text payload: keep the NUL inside the size so handlers can use it as a
    // C string without caring about data_size
    in->payload_len = (unsigned int)strlen(text) + 1U;
    in->priv = root;
    in->release = din_json_release;

    return Success;

fail:
    cJSON_Delete(root);
    in->priv = NULL;
    in->release = NULL;

    return Fail;
}
