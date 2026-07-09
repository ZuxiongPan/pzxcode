#include <stdio.h>
#include <string.h>

#include "protocol/parser.h"

int uds_parser(const char *buf, ssize_t size)
{
    (void)size;

    printf("------ uds message ------\n");
    printf("%s\n", buf);
    printf("----------------------\n");

    return 0;
}