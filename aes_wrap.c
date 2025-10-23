#include "aes_wrap.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

unsigned char* aes_decrypt(const unsigned char *ciphertext, size_t ct_len,
                           const unsigned char *key, const unsigned char *iv,
                           size_t *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Allocate output buffer (plaintext can be at most ct_len + block_size)
    unsigned char *plaintext = malloc(ct_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (out_len) *out_len = plaintext_len;
    return plaintext;
}

unsigned char* aes_encrypt(const unsigned char *plaintext, size_t pt_len,
                           const unsigned char *key, const unsigned char *iv,
                           size_t *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Allocate output buffer
    unsigned char *ciphertext = malloc(pt_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (out_len) *out_len = ciphertext_len;
    return ciphertext;
}
