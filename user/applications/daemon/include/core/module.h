#ifndef _MODULE_H_
#define _MODULE_H_

#include "message.h"

#define MAX_MODULE_COUNT 32

struct module;

typedef struct mod_ops {
    int (*init)(struct module *m);
    int (*start)(struct module *m);
    int (*stop)(struct module *m);
    int (*on_msg)(struct module *m, const message_t *msg);
} mod_ops_t;

typedef struct module {
    char name[STRUCT_INNER_NAME_LEN];
    const mod_ops_t *ops;
    void *priv;
} module_t;

int module_register(module_t *mod);
module_t* module_find(const char *name);
int module_start_all(void);
int module_stop_all(void);

#endif
