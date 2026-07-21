#ifndef _DMODULE_H_
#define _DMODULE_H_

#include "core/dcontext.h"

struct daemon_module;

enum dmodule_id {
    ModUnused = 0,
    ModBlock,
    ModInvalid,
};
typedef enum dmodule_id dmod_id_e;

struct daemon_message {
    int src_compid;
    int dst_compid;
    unsigned int msgid;
    unsigned int content_size;
    char content[0];
};
typedef struct daemon_message dmsg_t;

struct mod_ops {
    int (*start)(struct daemon_module *m);
    void (*stop)(struct daemon_module *m);
    int (*onmsg)(struct daemon_module *m, const dmsg_t *msg);
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
const char *dmodule_get_name(dmod_id_e modid);
int dmodule_handle(void *arg);

#endif
