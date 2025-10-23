#pragma once
#include <stddef.h>

// AES-256-CBC decrypt
// Returns allocated buffer (caller must free) or NULL on error
// Sets *out_len to decrypted length
unsigned char* aes_decrypt(const unsigned char *ciphertext, size_t ct_len,
                           const unsigned char *key, const unsigned char *iv,
                           size_t *out_len);

// AES-256-CBC encrypt
// Returns allocated buffer (caller must free) or NULL on error
// Sets *out_len to encrypted length
unsigned char* aes_encrypt(const unsigned char *plaintext, size_t pt_len,
                           const unsigned char *key, const unsigned char *iv,
                           size_t *out_len);
