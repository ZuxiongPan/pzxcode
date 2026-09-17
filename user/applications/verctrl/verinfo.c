#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/errno.h>
#include "common/version_info.h"

#ifdef CONFIG_VERHEADER_ENCRYPT
#include "common/aes_key.h"
#include "openssl/evp.h"

int aes256_cbc_decrypt(uint8_t *data, unsigned int datalen, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *tmp = NULL;
    int outlen = 0, finallen = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printf("EVP_CIPHER_CTX_new failed\n");
        return -ENOMEM;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv))
    {
        printf("EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    tmp = malloc(datalen);
    if (!tmp)
    {
        printf("malloc temp buffer for decrypt failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -ENOMEM;
    }

    if (1 != EVP_DecryptUpdate(ctx, tmp, &outlen, data, datalen))
    {
        printf("EVP_DecryptUpdate failed\n");
        free(tmp);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, tmp + outlen, &finallen))
    {
        printf("EVP_DecryptFinal_ex failed\n");
        free(tmp);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(data, tmp, outlen + finallen);
    free(tmp);
    EVP_CIPHER_CTX_free(ctx);

    printf("%s decrypt success, outlen %d\n", __FUNCTION__, outlen + finallen);
    return 0;
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