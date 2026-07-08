#include <stdio.h>
#include <string.h>

#include "protocol/uevent_proto.h"

int uevent_parser(const char *buf, ssize_t size)
{
    ssize_t len = 0;

    printf("------ uevent message ------\n");
    while(len < size)
    {
        printf("\t%s\n", buf + len);
        len += strlen(buf + len) + 1;
    }

    printf("----------------------\n");

    return 0;
}