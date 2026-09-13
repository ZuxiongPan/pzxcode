#ifndef _DMODULE_H_
#define _DMODULE_H_

#include "core/dcontext.h"

#define ModuleIDUevent (MODULEID_START + 1)
#define ModuleIDStatus (MODULEID_START + 2)
#define ModuleIDUpgrade (MODULEID_START + 3)
#define ModuleIDSignal (MODULEID_START + 4)

struct daemon_module;

struct mod_ops {
    // arg here is the task pointer
    int (*ontask)(struct daemon_module *m, void *arg);
};
typedef struct mod_ops mod_ops_t;

struct daemon_module {
    dcomp_t dcomp;
    const mod_ops_t *ops;
    void *priv;
};
typedef struct daemon_module dmod_t;

int dmodule_register(dmod_t *mod);
void dmodule_unregister(dmod_t *mod);
int dmodule_handle(void *arg);

#endif
