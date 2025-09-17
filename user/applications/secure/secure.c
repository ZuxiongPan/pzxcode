#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#define LINE_BUFSIZE 256
#define KEY_BUFSIZE 128
#define VALUE_BUFSIZE 128

static int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize)
{
    FILE *fp = fopen("/proc/verinfo", "r");
    if(NULL == fp)
    {
        printf("open /proc/verinfo failed\n");
        return -1;
    }

    int found = 0;
    char line[LINE_BUFSIZE];
    char key[KEY_BUFSIZE];
    char value[VALUE_BUFSIZE];

    while(NULL != fgets(line, sizeof(line), fp))
    {
        char *colon = strchr(line, ':');
        if(NULL == colon)
            continue;

        unsigned int keylen = colon - line;
        keylen = (keylen >= KEY_BUFSIZE) ? (KEY_BUFSIZE - 1) : keylen;
        strncpy(key, line, keylen);
        key[keylen] = '\0';

        // Key: Value, after colon is a SPACE
        char *valbeg = colon + 2;
        strncpy(value, valbeg, VALUE_BUFSIZE - 1);
        value[VALUE_BUFSIZE - 1] = '\0';
        value[strcspn(value, "\r\n")] = '\0';

        if(0 == strcmp(key, name))
        {
            strncpy(valbuf, value, bufsize -1);
            valbuf[bufsize - 1] = '\0';
            found = 1;
            break;
        }
    }

    fclose(fp);
    return found;
}

static inline void set_blkdev_rdonly(const char *path)
{
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        printf("cannot open %s\n", path);
        return ;
    }

    int readonly = 1;
    if(-1 == ioctl(fd, BLKROSET, &readonly))
        printf("set %s readonly failed\n", path);
    else
        printf("set %s readonly now\n", path);

    close(fd);
    return ;
}

int main()
{
    char buf[VALUE_BUFSIZE];

    // set current kernel part readonly
    if(get_value_from_verinfo("Current Kernel Part", buf, VALUE_BUFSIZE))
        set_blkdev_rdonly(buf);

    // set current rootfs part readonly
    if(get_value_from_verinfo("Current Rootfs Part", buf, VALUE_BUFSIZE))
        set_blkdev_rdonly(buf);

    return 0;
}