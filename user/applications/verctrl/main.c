#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "common/pzx_stat.h"

#define LINE_BUFSIZE 256
#define KEY_BUFSIZE 128
#define VALUE_BUFSIZE 128

// verinfo format: [Key: Value]
// name is Key, this function will skip COLON and SPACE in verinfo
// so name DO NOT include COLON character
static int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize)
{
    FILE *fp = fopen("/proc/verinfo", "r");
    if(NULL == fp)
    {
        printf("open /proc/verinfo failed\n");
        return ERR_OPEN_FAILED;
    }

    int found = BOOL_FALSE;
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
            found = BOOL_TRUE;
            break;
        }
    }

    fclose(fp);
    return found;
}

int main()
{
    char buf[VALUE_BUFSIZE] = {0};
    int rfd = -1, wfd = -1;
    int curidx = 0, backidx = 0;
    unsigned char needsync = BOOL_FALSE;

    if(!get_value_from_verinfo("Current Version Index", buf, VALUE_BUFSIZE))
    {
        printf("Cannot find \'Current Version Index\' in /proc/verinfo!\n");
        return ERR_READ_FAIED;
    }
    sscanf(buf, "%08x", &curidx);

    if(!get_value_from_verinfo("Backup Version Index", buf, VALUE_BUFSIZE))
    {
        printf("Cannot find \'Backup Version Index\' in /proc/verinfo!\n");
        return ERR_READ_FAIED;
    }
    sscanf(buf, "%08x", &backidx);

    if(!get_value_from_verinfo("Backup Version State", buf, VALUE_BUFSIZE))
    {
        printf("Cannot find \'Backup Version State\' in /proc/verinfo!\n");
        return ERR_READ_FAIED;
    }

    printf("versionstate: cur %d back %d stat %s\n", curidx, backidx, buf);

    if(!strcmp(buf, "Invalid") || (curidx != backidx))
    {
        needsync = BOOL_TRUE;
    }

    if(needsync)
    {
        printf("version need synchonized.\n");
        
    }

    return 0;
}
