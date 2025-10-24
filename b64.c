#include "b64.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;
    return -2;
}

unsigned char* b64_decode(const char *input, size_t input_len, size_t *out_len) {
    if (!input || input_len == 0) return NULL;

    // Remove whitespace and newlines
    size_t clean_len = 0;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] != ' ' && input[i] != '\t' && input[i] != '\r' && input[i] != '\n') {
            clean_len++;
        }
    }

    if (clean_len % 4 != 0) return NULL;

    size_t out_size = (clean_len / 4) * 3;
    // Check padding on the cleaned data by scanning backwards from input
    size_t padding = 0;
    for (size_t i = input_len; i > 0 && padding < 2; i--) {
        if (input[i-1] == '=') {
            padding++;
        } else if (input[i-1] != ' ' && input[i-1] != '\t' && input[i-1] != '\r' && input[i-1] != '\n') {
            break;
        }
    }
    out_size -= padding;

    unsigned char *output = malloc(out_size + 1);
    if (!output) return NULL;

    size_t out_idx = 0;
    int values[4];
    int val_idx = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;

        int val = b64_decode_value(c);
        if (val == -2) {
            free(output);
            return NULL;
        }

        values[val_idx++] = val;

        if (val_idx == 4) {
            if (values[0] >= 0 && values[1] >= 0) {
                output[out_idx++] = (values[0] << 2) | (values[1] >> 4);
            }
            if (values[1] >= 0 && values[2] >= 0) {
                output[out_idx++] = (values[1] << 4) | (values[2] >> 2);
            }
            if (values[2] >= 0 && values[3] >= 0) {
                output[out_idx++] = (values[2] << 6) | values[3];
            }
            val_idx = 0;
        }
    }

    output[out_idx] = '\0';
    if (out_len) *out_len = out_idx;
    return output;
}

char* b64_encode(const unsigned char *input, size_t input_len) {
    if (!input || input_len == 0) return NULL;

    size_t out_len = 4 * ((input_len + 2) / 3);
    char *output = malloc(out_len + 1);
    if (!output) return NULL;

    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = b64_table[(triple >> 18) & 0x3F];
        output[j++] = b64_table[(triple >> 12) & 0x3F];
        output[j++] = b64_table[(triple >> 6) & 0x3F];
        output[j++] = b64_table[triple & 0x3F];
    }

    // Add padding
    int pad = (3 - (input_len % 3)) % 3;
    for (int p = 0; p < pad; p++) {
        output[out_len - 1 - p] = '=';
    }

    output[out_len] = '\0';
    return output;
}
