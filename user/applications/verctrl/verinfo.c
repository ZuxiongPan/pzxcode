#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/errno.h>
#include "common/version_info.h"

#ifdef CONFIG_VERHEADER_ENCRYPT
#include "common/aes_key.h"
#include "mbedtls/aes.h"

int aes256_cbc_decrypt(uint8_t *data, unsigned int datalen, uint8_t *iv)
{
    mbedtls_aes_context aes_ctx;
    int ret = 0;

    mbedtls_aes_init(&aes_ctx);
    ret = mbedtls_aes_setkey_dec(&aes_ctx, aes_key, 256);
    if(ret)
    {
        printf("set aes key failed, ret %d\n", ret);
        mbedtls_aes_free(&aes_ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, datalen,
        iv, data, data);
    
    mbedtls_aes_free(&aes_ctx);
    printf("%s decrypt ret %d\n", __FUNCTION__, ret);

    return ret;
}
#endif


#define LINE_BUFSIZE 256
#define KEY_BUFSIZE 128
#define VALUE_BUFSIZE 128

// verinfo format: [Key: Value]
// name is Key, this function will skip COLON and SPACE in verinfo
// so name DO NOT include COLON character
int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize)
{
    FILE *fp = fopen(PROC_FILEPARH, "r");
    if(NULL == fp)
    {
        printf("open %s failed\n", PROC_FILEPARH);
        return -EACCES;
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