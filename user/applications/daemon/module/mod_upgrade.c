#include <string.h>

#include "dlog.h"
#include "dconf.h"
#include "core/dmodule.h"
#include "core/dworker.h"
#include "core/dcontext.h"
#include "core/dfuncalls.h"
#include "module/dmsgid.h"
#include "channel/chnl_api.h"
#include "lib/cJSON.h"
#include "lib/run.h"

static dmod_t upgrademod;

static void upgrade_handle_json_cmd(dtask_t *task)
{
    const char *json_str = task->data;

    cJSON *json = cJSON_Parse(json_str);
    if (NULL == json)
    {
        dprint("invalid json string\n");
        return ;
    }

    cJSON *arg1 = cJSON_GetObjectItem(json, "arg1");
    if (NULL == arg1)
    {
        dprint("no request in cmd\n");
        cJSON_Delete(json);
        return ;
    }

    if (strcmp(arg1->valuestring, "update") == 0)
    {
        // 1. use ftp download firmware
        char *downargs[] = {
            "tftp", "-g", "-l", "/var/fw.bin", "-r", "upgrade.bin", "10.0.2.2", NULL
        };
        pid_t ftp = run_new_program("tftp", downargs);
        if (ftp < 0)
        {
            derror("download upgrade file failed\n");
            return ;
        }
        else
        {
            // wait for 100s downloading
            timer_add(100*1000, 0, false, upgrademod.dcomp.dcompid, MSGID_TEST_TIMER);
        }
    }

    return ;
}

static int upgrademod_ontask(dmod_t *m, void *arg)
{
    (void)m;
    if (NULL == arg)
    {
        dprint("invalid task\n");
        return Fail;
    }

    int ret = Success;
    dtask_t *task = (dtask_t *)arg;

    switch (task->msgid)
    {
        case MSGID_JSON_CMD:
            upgrade_handle_json_cmd(task);
            break;
        case MSGID_TEST_TIMER:
            dprint("downloading finished\n");
            break;
        default:
            dprint("invalid msgid 0x%x\n", task->msgid);
            break;
    }

    return ret;
}

static const mod_ops_t upgrademod_ops = {
    .ontask = upgrademod_ontask,
};

int upgrademod_init(void)
{
    int ret = Success;
    memset(&upgrademod, 0, sizeof(dmod_t));
    dcomponent_init(&upgrademod.dcomp, ModuleIDUpgrade, "upgrade");
    upgrademod.ops = &upgrademod_ops;

    ret = dmodule_register(&upgrademod);
    if (ret != Success)
    {
        derror("upgrade module register failed\n");
        return Fail;
    }

    dprint("upgrade_module register ret = %d\n", ret);
    return ret;
}

void upgrademod_exit(void)
{
    dmodule_unregister(&upgrademod);
    dprint("upgrade module unregister done\n");
}

DCOMP_INIT_LOWPRIO(upgrademod_init);
DCOMP_EXIT_LOWPRIO(upgrademod_exit);
