#ifndef __PZXAES_H__
#define __PZXAES_H__

// AES256, this code is modified from koke/tiny-AES-c
// if aes cbc, encry/decry buffer size must be multiple of AES_BLKLEN
#define AES_BLKLEN 16
#define AES_KEYLEN 32
#define AES_KEY_EXPSIZE 240

struct aes_ctx {
    unsigned char round_key[AES_KEY_EXPSIZE];
    unsigned char iv[AES_BLKLEN];
};

void aes_init_ctx_iv(struct aes_ctx *ctx, const unsigned char *key, const unsigned char *iv);
void aes_ctx_set_iv(struct aes_ctx *ctx, const unsigned char *iv);
void aes_cbc_encrypt_buffer(struct aes_ctx *ctx, unsigned char *buf, unsigned int len);
void aes_cbc_decrypt_buffer(struct aes_ctx *ctx, unsigned char *buf, unsigned int len);

#endif