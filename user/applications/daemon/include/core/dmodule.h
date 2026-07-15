#ifndef _DMODULE_H_
#define _DMODULE_H_

#include "core/dcontext.h"

struct daemon_module;

struct mod_ops {
    int (*start)(struct daemon_module *m);
    int (*stop)(struct daemon_module *m);
    int (*on_msg)(struct daemon_module *m, const message_t *msg);
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

#endif
