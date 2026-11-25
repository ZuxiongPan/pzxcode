#ifndef _DSYNC_H_
#define _DSYNC_H_

#include <stdbool.h>
#include <stdint.h>

#include "dextension.h"

enum dsync_kind {
    SyncChild = 1,
    SyncMsg = 2,
    SyncKindMax = 3,
};

struct dsync {
    struct lnode node;
    unsigned int kind;
    unsigned int key;
    bool armed;
    bool done;
    int status;
};

void dsync_init(struct dsync *unit, unsigned int kind, unsigned int key);
void dsync_arm(struct dsync *unit);
void dsync_cancel(struct dsync *unit);

// timeout_ms == 0 means no deadline: wait until the unit is completed.
// the blocking budget is the worker count minus one worker kept for message
// handling, it is shared by every kind because the workers are, and it is
// checked on entry: -EBUSY when it is already exhausted, -ETIMEDOUT on deadline,
// -ECANCELED after dsync_abort_all(), 0 with *status filled otherwise
int dsync_wait(struct dsync *unit, uint64_t timeout_ms, int *status);
int dsync_complete(unsigned int kind, unsigned int key, int status);

// true when dsync_wait() would still be admitted right now. it is a hint for
// callers that pay a price before waiting (spawning a child, for instance), the
// real decision stays inside dsync_wait() where it is atomic
bool dsync_can_block(void);

// wake every waiter with -ECANCELED: it is the shutdown path's only way out of
// a wait without deadline, worker_mgr_stop() would hang on join otherwise
void dsync_abort_all(void);

void dsync_info(void);

#endif
