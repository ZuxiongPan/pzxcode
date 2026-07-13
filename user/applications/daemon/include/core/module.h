#ifndef _MODULE_H_
#define _MODULE_H_

#include "message.h"

enum daemon_module_id {
    MOD_PARSER = 0,
    MOD_MAX,    // this id if appear in message means outer process
};
typedef enum daemon_module_id dmod_id_e;

struct daemon_module;
struct daemon_context;

struct mod_ops {
    int (*init)(struct daemon_module *m);
    int (*start)(struct daemon_module *m);
    int (*stop)(struct daemon_module *m);
    int (*on_msg)(struct daemon_module *m, const message_t *msg);
};
typedef struct mod_ops mod_ops_t;

struct daemon_module {
    dmod_id_e mid;
    const char *name;
    const mod_ops_t *ops;
    void *priv;
};
typedef struct daemon_module dmod_t;

int module_manager_init(struct daemon_context *ctx);
void module_manager_destroy(struct daemon_context *ctx);
int module_register(dmod_t *mod);
dmod_t* module_find(const char *name);
int module_start_all(void);
int module_stop_all(void);

#endif
