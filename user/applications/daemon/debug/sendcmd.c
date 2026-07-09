#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "channel/dnet.h"

int main(int argc, const char *argv[])
{
    if(argc < 2)
    {
        printf("Usage: %s <message>\n", argv[0]);
        return -1;
    }

    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket create uds");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", UDS_PATH);

    ssize_t len = sendto(sockfd, argv[1], strlen(argv[1]), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (len < 0)
    {
        perror("send uds message");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}