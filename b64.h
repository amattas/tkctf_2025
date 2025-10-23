#pragma once
#include <stddef.h>

// Base64 decode: returns allocated buffer (caller must free) or NULL on error
// Sets *out_len to decoded length
unsigned char* b64_decode(const char *input, size_t input_len, size_t *out_len);

// Base64 encode: returns allocated string (caller must free) or NULL on error
char* b64_encode(const unsigned char *input, size_t input_len);
