#ifndef _UK_NETLINK_H_
#define _UK_NETLINK_H_

#define PZX_KEVENT_GENL_VERSION 1
#define PZX_KEVENT_GENL_GROUP "pzx_kevent"
#define PZX_KEVENT_GENL_FAMILY "pzx_kfamily"

#define NLCMD_INFORM 0x55

enum uk_nlattr {
    NLATTR_UNSPEC,
    NLATTR_TARGET,  // this is a string
    NLATTR_DATA,
    __NLATTR_MAX,
};
#define NLATTR_MAX (__NLATTR_MAX - 1)

#define USER_MEMBLK_MODNAME "memblk"

#endif
