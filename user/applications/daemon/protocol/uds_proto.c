#include <stdio.h>
#include <string.h>

#include "protocol/parser.h"

int uds_parser(const char *buf, ssize_t size)
{
    ssize_t len = 0;

    printf("------ uds message ------\n");
    printf("%s\n", buf);
    printf("----------------------\n");

    return 0;
}