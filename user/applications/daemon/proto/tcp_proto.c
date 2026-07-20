#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "common.h"
#include "core/bus.h"
#include "protocol/parser.h"

static void bus_route_http_resp(const char *body, uint32_t msg_id)
{
    char resp[2048];

    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(body),
        body);

    bus_post_msg("armd", "parser", msg_id, len, resp);
}

static void http_handle_request(const message_t *msg)
{
    char resp[1024] = { 0 };

    if (strncmp(msg->payload, "GET /sysinfo", 12) == 0)
    {
        struct sysinfo info = { 0 };
        if(sysinfo(&info) == 0)
        {
            snprintf(resp, sizeof(resp), "uptime: %ldmin %lds\nload average: 1min[%ld], 5min[%ld], 15min[%ld]\n"
                "memory: free[%ldK]/total[%ldK]\n", info.uptime / 60, info.uptime % 60, info.loads[0], info.loads[1],
                info.loads[2], info.freeram / 1024, info.totalram / 1024);
        }
        else
        {
            snprintf(resp, sizeof(resp), "sysinfo failed\n");
        }
    }
    else
    {
        time_t now;
        struct tm tinfo;
        time(&now);
        localtime_r(&now, &tinfo);
        
        snprintf(resp, sizeof(resp), "software name: armd\nsoftware version: %s\n"
            "software author: pzx\ncurrent time: %04d-%02d-%02d\n", 
            ARMD_VERSION, tinfo.tm_year + 1900, tinfo.tm_mon + 1, tinfo.tm_mday);
    }

    bus_route_http_resp(resp, msg->msg_id);
}

int tcp_parser(const message_t *msg)
{
    if (strstr(msg->payload, "\r\n\r\n"))
    {
        printf("HTTP REQ:\n%s\n", msg->payload);
        http_handle_request(msg);
    }

    return 0;
}