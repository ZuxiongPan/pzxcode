#include <stdio.h>
#include <stdlib.h>    
#include <string.h>
#include <linux/errno.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "common/version_partition.h"
#include "common/version_header.h"

extern uint32_t pzx_crc32(const uint8_t *data, uint32_t length);

int rsa_sign(char *filepath, char *keypath)
{
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ckey = NULL;
    EVP_MD_CTX *context = NULL;
    uint32_t sign_size = 0;
    size_t sig_size = 0;
    uint8_t *buf = NULL;
    uint8_t *sig = NULL;
    uint8_t headbuf[STORDEV_PHYSICAL_BLKSIZE];
    struct signature_header *sighead = (struct signature_header *)headbuf;

    int ret = OPENSSL_init_ssl(0, NULL);
    if(!ret)
    {
        printf("init openssl failed, ret %d\n", ret);
        return ret;
    }

    // read private key to pkey
    fp = fopen(keypath, "r");
    if(NULL == fp)
    {
        printf("fopen key %s failed\n", keypath);
        return -ENOENT;
    }

    if(NULL == PEM_read_PrivateKey(fp, &pkey, NULL, keypath))
    {
        printf("read private key failed\n");
        fclose(fp);
        return -EPROTO;
    }
    fclose(fp);

    // read sign file to buffer
    fp = fopen(filepath, "r");
    if(NULL == fp)
    {
        printf("open sign file %s failed\n", filepath);
        EVP_PKEY_free(pkey);
        return -ENOENT;
    }
    fseek(fp, 0, SEEK_END);
    sign_size = ftell(fp) - VERSION_HEADER_OFFSET;

    buf = malloc(sign_size);
    if(NULL == buf)
    {
        printf("request buffer for file %s failed\n", filepath);
        fclose(fp);
        EVP_PKEY_free(pkey);
        return -ENOMEM;
    }

    fseek(fp, VERSION_HEADER_OFFSET, SEEK_SET);
    ret = fread(buf, 1, sign_size, fp);
    fclose(fp);
    printf("sign bytes is %u\n", sign_size);

    // do rsa sign
    context = EVP_MD_CTX_new();
    if(NULL == context)
    {
        printf("create a EVP context failed\n");
        free(buf);
        EVP_PKEY_free(pkey);
        return -ENOMEM;
    }

    ckey = EVP_PKEY_CTX_new(pkey, NULL);
    if(NULL == ckey)
    {
        printf("create a EVP key context failed\n");
        free(buf);
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(pkey);
        return -ENOMEM;
    }

    if(EVP_DigestSignInit(context, &ckey, EVP_sha256(), NULL, pkey) <= 0)
    {
        printf("init EVP signer failed\n");
        free(buf);
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(pkey);
        return -EPROTO;
    }

    if(!EVP_DigestSignUpdate(context, buf, sign_size))
    {
        printf("sign data failed\n");
        free(buf);
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(pkey);
        return -EPROTO;
    }
    free(buf);

    sig_size = EVP_PKEY_size(pkey);
    sig = malloc(sig_size);
    if(NULL == sig)
    {
        printf("request buffer for signature failed\n");
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(pkey);
        return -ENOMEM;
    }

    if(!EVP_DigestSignFinal(context, sig, &sig_size))
    {
        printf("get signature failed\n");
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(pkey);
        return -ENOMEM;
    }

    EVP_MD_CTX_free(context);
    EVP_PKEY_free(pkey);
    printf("sign success, signature size is %lu, signature:\n", sig_size);
    for(unsigned int i = 0; i < sig_size; i++)
    {
        printf("%02x", sig[i]);
    }
    printf("\n");

    // construct version header
    if(sig_size > 384)
    {
        printf("this rsa sign type is invalid, please change\n");
        free(sig);
    }
    sighead->magic[0] = SIGN_HEADER_MAGIC0;
    sighead->magic[1] = SIGN_HEADER_MAGIC1;
    sighead->header_version = SIGN_HEADER_VERNUM;
    sighead->signed_size = sign_size;
    sighead->sig_size = sig_size;
    memcpy(sighead->signature, sig, sig_size);
    free(sig);
    sighead->header_crc = pzx_crc32(headbuf, sizeof(struct signature_header) - sizeof(uint32_t));

    // write signature header to upgrade file
    fp = fopen(filepath, "r+");
    if(NULL == fp)
    {
        printf("open %s failed\n", filepath);
        return -ENOENT;
    }
    fseek(fp, SIGN_HEADER_OFFSET, SEEK_SET);
    sign_size = fwrite(headbuf, 1, STORDEV_PHYSICAL_BLKSIZE, fp);
    fclose(fp);
    
    return 0;
}