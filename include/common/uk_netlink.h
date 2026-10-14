#ifndef _UK_NETLINK_H_
#define _UK_NETLINK_H_

enum uk_nlcmd {
    NLCMD_UNSPEC,
    NLCMD_DEVADD,
    NLCMD_DEVDEL,
    __NLCMD_MAX,
};
#define NLCMD_MAX (__NLCMD_MAX - 1)

enum uk_nlattr {
    NLATTR_UNSPEC,
    NLATTR_TARGET,  // this is a string
    NLATTR_DATA,
    __NLATTR_MAX,
};
#define NLATTR_MAX (__NLATTR_MAX - 1)

#endif
