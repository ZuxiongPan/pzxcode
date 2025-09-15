#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define UEVENT_MSG_BUFSIZE 4096

int main(void)
{
    int sock = 0, len = 0;
    struct sockaddr_nl addr;
    char buf[UEVENT_MSG_BUFSIZE];
    memset(buf, 0, sizeof(buf));

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if(sock < 0)
    {
        perror("socket create");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = -1;
    printf("uevent netlink info: socket[%d] family[%d] pid[%d] groups[%d]\n", 
        sock, addr.nl_family, addr.nl_pid, addr.nl_groups);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind socket");
        close(sock);
        return -1;
    }

    printf("Now listening from kernel uevent\n");

    while(1)
    {
        len = recv(sock, buf, sizeof(buf), 0);
        if(len < 0)
        {
            perror("receive uevent message");
            continue;
        }

        printf("Received uevent message:\n");
        for(int i = 0; i< len; )
        {
            printf("\t%s\n", buf + i);
            i += strlen(buf + i) + 1;
        }
    }

    close(sock);

    return 0;
}