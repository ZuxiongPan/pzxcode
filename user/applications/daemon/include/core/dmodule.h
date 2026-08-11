#ifndef _DMODULE_H_
#define _DMODULE_H_

#include "core/dcontext.h"

#define ModuleIDBlock (MODULEID_START + 1)
#define ModuleIDStatus (MODULEID_START + 2)
#define ModuleIDUpgrade (MODULEID_START + 3)

struct daemon_module;

struct daemon_message {
    int src_compid;
    int dst_compid;
    unsigned int msgid;
    unsigned int content_size;
    char content[0];
};
typedef struct daemon_message dmsg_t;

struct mod_ops {
    // arg here is the task pointer
    int (*onmsg)(struct daemon_module *m, void *arg);
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
