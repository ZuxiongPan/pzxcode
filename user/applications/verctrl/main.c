#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/errno.h>
#include <unistd.h>

#define LINE_BUFSIZE 256
#define KEY_BUFSIZE 128
#define VALUE_BUFSIZE 128

extern int do_upgrade_version(const char *filepath);
static void print_usage(void);

int main(int argc, char *argv[])
{
    int ret = 0;
    if(argc < 2)
    {
        print_usage();
        return -EINVAL;
    }

    if(!strncmp(argv[1], "-sync", sizeof("-sync")))
    {
        ret = 0;
        printf("synchonize version return %d\n", ret);
    }

    if(!strncmp(argv[1], "-upgrade", sizeof("-upgrade")) && argc >= 3)
    {
        ret = do_upgrade_version(argv[2]);
        printf("upgrade version %s return %d\n", argv[2], ret);
        system("rm -f upgrade.bin");
    }

    return ret;
}

static void print_usage(void)
{
    printf("verctrl usage\n");
    printf("  -upgrade <filepath> : start upgrade <filepath>\n");
    printf("  -sync : start synchonize version\n");

    return ;
}

// verinfo format: [Key: Value]
// name is Key, this function will skip COLON and SPACE in verinfo
// so name DO NOT include COLON character
int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize)
{
    FILE *fp = fopen("/proc/verinfo", "r");
    if(NULL == fp)
    {
        printf("open /proc/verinfo failed\n");
        return -EIO;
    }

    int found = false;
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
            found = true;
            break;
        }
    }

    fclose(fp);
    return found;
}