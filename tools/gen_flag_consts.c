// Build-time generator for flag reveal constants
// Uses trapdoor VDF with RSA-2048 and BLAKE3/SHA256
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <endian.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Parameters
#define SEED_BYTES 64
#define PRIME_BITS 2048
#define VDF_T_DEFAULT (1ULL << 24)  // ~16M squarings, tune as needed
#define VDF_ROUNDS 7
#define FLAG_MAX 64

// Domain separators
static const char *DOM_SEED = "SEED";
static const char *DOM_STATE = "STATE";
static const char *DOM_XMAP = "XMAP";
static const char *DOM_KEY = "KEY";
static const char *DOM_STREAM = "STREAM";
static const char *DOM_CHK = "CHK";

// Simple hash wrapper (SHA256-based)
static void hash_multi(uint8_t *out, size_t out_len, int count, ...) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        const uint8_t *data = va_arg(args, const uint8_t*);
        size_t len = va_arg(args, size_t);
        EVP_DigestUpdate(ctx, data, len);
    }
    va_end(args);

    uint8_t digest[32];
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);

    // Expand if needed (simple repeat for now)
    for (size_t i = 0; i < out_len; i++) {
        out[i] = digest[i % 32];
    }
}

// Derive seed from S0
static void derive_seed(const uint8_t *s0, size_t s0_len, uint8_t seed[SEED_BYTES]) {
    hash_multi(seed, SEED_BYTES, 2,
               (const uint8_t*)DOM_SEED, strlen(DOM_SEED),
               s0, s0_len);
}

// Deterministic prime generation from seed
static BIGNUM* generate_prime_from_seed(const uint8_t *seed_in, size_t seed_len, int offset) {
    uint8_t expanded[512];

    // Mix seed with offset
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, seed_in, seed_len);
    EVP_DigestUpdate(ctx, &offset, sizeof(offset));
    uint8_t h[32];
    EVP_DigestFinal_ex(ctx, h, NULL);

    // Expand to fill prime bits
    for (int i = 0; i < 512; i++) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, h, 32);
        EVP_DigestUpdate(ctx, &i, sizeof(i));
        EVP_DigestFinal_ex(ctx, h, NULL);
        expanded[i] = h[0];
    }
    EVP_MD_CTX_free(ctx);

    // Create candidate
    BIGNUM *candidate = BN_new();
    BN_bin2bn(expanded, PRIME_BITS / 8, candidate);

    // Set MSB and make odd
    BN_set_bit(candidate, PRIME_BITS - 1);
    BN_set_bit(candidate, 0);

    // Find next prime
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *one = BN_new();
    BN_one(one);

    int attempts = 0;
    int is_prime = 0;
    while (!is_prime && attempts++ < 10000) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        is_prime = (BN_check_prime(candidate, bn_ctx, NULL) == 1);
#else
        is_prime = BN_is_prime_ex(candidate, 20, bn_ctx, NULL);
#endif
        if (!is_prime) {
            BN_add(candidate, candidate, one);
            BN_add(candidate, candidate, one);  // Keep odd
        }
    }

    BN_free(one);
    BN_CTX_free(bn_ctx);

    if (attempts >= 10000) {
        fprintf(stderr, "Failed to find prime\n");
        BN_free(candidate);
        return NULL;
    }

    return candidate;
}

// Map hash to Z*_N
static BIGNUM* map_to_zn_star(const uint8_t *hash, size_t hash_len, const BIGNUM *N, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BN_bin2bn(hash, hash_len, x);

    BIGNUM *two = BN_new();
    BN_set_word(two, 2);

    BN_mod(x, x, N, ctx);
    BN_add(x, x, two);

    // Ensure gcd(x, N) = 1 (simple: just use x as-is, very unlikely to hit factor)
    BN_free(two);
    return x;
}

// Fast VDF evaluation using CRT
static BIGNUM* vdf_fast(const BIGNUM *x, uint64_t T,
                        const BIGNUM *p, const BIGNUM *q,
                        const BIGNUM *dp, const BIGNUM *dq,
                        const BIGNUM *qInv, const BIGNUM *N,
                        BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *xp = BN_CTX_get(ctx);
    BIGNUM *xq = BN_CTX_get(ctx);
    BIGNUM *yp = BN_CTX_get(ctx);
    BIGNUM *yq = BN_CTX_get(ctx);
    BIGNUM *h = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);

    // xp = x mod p, xq = x mod q
    BN_mod(xp, x, p, ctx);
    BN_mod(xq, x, q, ctx);

    // yp = xp^dp mod p
    BN_mod_exp(yp, xp, dp, p, ctx);

    // yq = xq^dq mod q
    BN_mod_exp(yq, xq, dq, q, ctx);

    // CRT reconstruction: y = yq + q * (qInv * (yp - yq) mod p)
    BN_mod_sub(h, yp, yq, p, ctx);
    BN_mod_mul(h, qInv, h, p, ctx);
    BN_mul(y, q, h, ctx);
    BN_add(y, y, yq);
    BN_mod(y, y, N, ctx);

    BIGNUM *result = BN_dup(y);
    BN_CTX_end(ctx);
    return result;
}

// Main generator
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <flag> <output.h>\n", argv[0]);
        return 1;
    }

    const char *flag = argv[1];
    const char *output_path = argv[2];
    size_t flag_len = strlen(flag);

    if (flag_len > FLAG_MAX) {
        fprintf(stderr, "Flag too long (max %d)\n", FLAG_MAX);
        return 1;
    }

    // Generate random S0
    uint8_t s0[64];
    RAND_bytes(s0, sizeof(s0));

    // Derive seed
    uint8_t seed[SEED_BYTES];
    derive_seed(s0, sizeof(s0), seed);

    printf("[*] Generating primes (this may take a minute)...\n");

    // Generate primes
    BIGNUM *p = generate_prime_from_seed(seed, SEED_BYTES, 0);
    BIGNUM *q = generate_prime_from_seed(seed, SEED_BYTES, 1);

    if (!p || !q) {
        fprintf(stderr, "Prime generation failed\n");
        return 1;
    }

    printf("[*] Primes generated (%d bits each)\n", BN_num_bits(p));

    // Compute N, lambda(N)
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *lambda_n = BN_new();
    BIGNUM *gcd = BN_new();

    BN_mul(N, p, q, ctx);
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());

    // lambda(N) = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
    BN_gcd(gcd, p_minus_1, q_minus_1, ctx);
    BN_mul(lambda_n, p_minus_1, q_minus_1, ctx);
    BN_div(lambda_n, NULL, lambda_n, gcd, ctx);

    uint64_t T = VDF_T_DEFAULT;

    // Compute dp = 2^T mod (p-1)
    BIGNUM *two = BN_new();
    BIGNUM *dp = BN_new();
    BIGNUM *dq = BN_new();
    BN_set_word(two, 2);

    // Reduce T mod (p-1) and (q-1)
    BIGNUM *T_bn = BN_new();
    BN_set_word(T_bn, T >> 32);           // High 32 bits
    BN_lshift(T_bn, T_bn, 32);
    BIGNUM *T_low = BN_new();
    BN_set_word(T_low, T & 0xFFFFFFFFULL); // Low 32 bits
    BN_add(T_bn, T_bn, T_low);

    BN_mod(dp, T_bn, p_minus_1, ctx);
    BN_mod(dq, T_bn, q_minus_1, ctx);

    BN_mod_exp(dp, two, dp, p_minus_1, ctx);
    BN_mod_exp(dq, two, dq, q_minus_1, ctx);

    // Compute qInv = q^-1 mod p
    BIGNUM *qInv = BN_new();
    BN_mod_inverse(qInv, q, p, ctx);

    printf("[*] VDF parameters computed (T = 2^%d)\n", (int)__builtin_ctzll(T));

    // Initialize state
    uint8_t state[32];
    {
        uint8_t N_bytes[512];
        int N_len = BN_bn2bin(N, N_bytes);
        uint64_t T_be = htobe64(T);

        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_STATE, strlen(DOM_STATE));
        EVP_DigestUpdate(md, N_bytes, N_len);
        EVP_DigestUpdate(md, &T_be, sizeof(T_be));
        EVP_DigestFinal_ex(md, state, NULL);
        EVP_MD_CTX_free(md);
    }

    printf("[*] Running VDF chain (%d rounds)...\n", VDF_ROUNDS);

    // VDF chain
    for (int round = 0; round < VDF_ROUNDS; round++) {
        // xi = map_to_ZNstar(HASH("XMAP" || state || round), N)
        uint8_t xmap_input[64];
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_XMAP, strlen(DOM_XMAP));
        EVP_DigestUpdate(md, state, 32);
        EVP_DigestUpdate(md, &round, sizeof(round));
        EVP_DigestFinal_ex(md, xmap_input, NULL);
        EVP_MD_CTX_free(md);

        BIGNUM *xi = map_to_zn_star(xmap_input, 32, N, ctx);

        // y = xi^{2^T} mod N (fast path)
        BIGNUM *y = vdf_fast(xi, T, p, q, dp, dq, qInv, N, ctx);

        // state = HASH(state || y || round)
        uint8_t y_bytes[512];
        int y_len = BN_bn2bin(y, y_bytes);

        md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, state, 32);
        EVP_DigestUpdate(md, y_bytes, y_len);
        EVP_DigestUpdate(md, &round, sizeof(round));
        EVP_DigestFinal_ex(md, state, NULL);
        EVP_MD_CTX_free(md);

        BN_free(xi);
        BN_free(y);

        printf("  Round %d complete\n", round + 1);
    }

    printf("[*] VDF chain complete\n");

    // Derive key
    uint8_t key[32];
    {
        uint8_t N_bytes[512];
        int N_len = BN_bn2bin(N, N_bytes);
        uint64_t T_be = htobe64(T);

        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_KEY, strlen(DOM_KEY));
        EVP_DigestUpdate(md, state, 32);
        EVP_DigestUpdate(md, N_bytes, N_len);
        EVP_DigestUpdate(md, &T_be, sizeof(T_be));
        EVP_DigestFinal_ex(md, key, NULL);
        EVP_MD_CTX_free(md);
    }

    // Generate keystream
    uint8_t stream[FLAG_MAX];
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_STREAM, strlen(DOM_STREAM));
        EVP_DigestUpdate(md, key, 32);
        EVP_DigestFinal_ex(md, stream, NULL);
        EVP_MD_CTX_free(md);

        // Extend if needed
        for (size_t i = 32; i < flag_len; i++) {
            stream[i] = stream[i % 32] ^ (i * 0x9e);
        }
    }

    // Encrypt flag
    uint8_t ciphertext[FLAG_MAX];
    for (size_t i = 0; i < flag_len; i++) {
        ciphertext[i] = flag[i] ^ stream[i];
    }

    // Compute integrity check
    uint8_t check_digest[32];
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_CHK, strlen(DOM_CHK));
        EVP_DigestUpdate(md, (const uint8_t*)flag, flag_len);
        EVP_DigestFinal_ex(md, check_digest, NULL);
        EVP_MD_CTX_free(md);
    }

    printf("[*] Flag encrypted\n");

    // Write output header with obfuscation
    FILE *out = fopen(output_path, "w");
    if (!out) {
        perror("fopen");
        return 1;
    }

    fprintf(out, "// Auto-generated flag constants - DO NOT EDIT\n");
    fprintf(out, "#pragma once\n");
    fprintf(out, "#include <stdint.h>\n\n");

    // Obfuscated seed (split into 4 chunks with XOR masks)
    fprintf(out, "// Obfuscated seed fragments\n");
    uint32_t seed_xor_keys[4];
    for (int i = 0; i < 4; i++) {
        RAND_bytes((uint8_t*)&seed_xor_keys[i], sizeof(uint32_t));
        fprintf(out, "static const uint32_t SEED_XOR_%d = 0x%08xU;\n", i, seed_xor_keys[i]);
    }
    fprintf(out, "\n");

    for (int chunk = 0; chunk < 4; chunk++) {
        fprintf(out, "static const uint32_t SEED_FRAG_%d[] = {\n", chunk);
        for (int i = 0; i < 4; i++) {
            uint32_t val;
            memcpy(&val, &seed[chunk * 16 + i * 4], 4);
            val ^= seed_xor_keys[chunk];
            fprintf(out, "  0x%08xU,\n", val);
        }
        fprintf(out, "};\n\n");
    }

    // VDF parameters
    fprintf(out, "// VDF parameters\n");
    fprintf(out, "#define VDF_T_VAL %lluULL\n", T);
    fprintf(out, "#define VDF_R_VAL %d\n", VDF_ROUNDS);
    fprintf(out, "#define FLAG_LEN_VAL %zuU\n\n", flag_len);

    // Ciphertext (split into pieces)
    fprintf(out, "// Ciphertext fragments\n");
    size_t ct_split = (flag_len + 2) / 3;
    fprintf(out, "static const uint8_t CT_PART_A[] = {");
    for (size_t i = 0; i < ct_split && i < flag_len; i++) {
        if (i > 0) fprintf(out, ",");
        fprintf(out, "0x%02x", ciphertext[i]);
    }
    fprintf(out, "};\n");

    fprintf(out, "static const uint8_t CT_PART_B[] = {");
    for (size_t i = ct_split; i < ct_split * 2 && i < flag_len; i++) {
        if (i > ct_split) fprintf(out, ",");
        fprintf(out, "0x%02x", ciphertext[i]);
    }
    fprintf(out, "};\n");

    fprintf(out, "static const uint8_t CT_PART_C[] = {");
    for (size_t i = ct_split * 2; i < flag_len; i++) {
        if (i > ct_split * 2) fprintf(out, ",");
        fprintf(out, "0x%02x", ciphertext[i]);
    }
    fprintf(out, "};\n\n");

    // Integrity digest
    fprintf(out, "// Integrity check\n");
    fprintf(out, "static const uint8_t CHECK_DIGEST[32] = {");
    for (int i = 0; i < 32; i++) {
        if (i > 0) fprintf(out, ",");
        if (i % 8 == 0) fprintf(out, "\n  ");
        fprintf(out, "0x%02x", check_digest[i]);
    }
    fprintf(out, "\n};\n");

    fclose(out);

    printf("[*] Constants written to %s\n", output_path);
    printf("[*] Flag: %s\n", flag);

    // Cleanup
    BN_free(p);
    BN_free(q);
    BN_free(N);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(lambda_n);
    BN_free(gcd);
    BN_free(two);
    BN_free(dp);
    BN_free(dq);
    BN_free(T_bn);
    BN_free(T_low);
    BN_free(qInv);
    BN_CTX_free(ctx);

    return 0;
}
