#ifndef _PZXKTOOLS_H_
#define _PZXKTOOLS_H_

#include <linux/kobject.h>

int uevent_expanded_info(struct kobject *kobj, const char *expanded);

#endif