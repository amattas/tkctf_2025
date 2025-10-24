#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ftw.h>
#include <sys/utsname.h>
#include <stdint.h>
#include <endian.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

__asm__(".text\n"
        ".globl gadget_pop_rdi_ret_label\n"
        ".type gadget_pop_rdi_ret_label, @function\n"
        "gadget_pop_rdi_ret_label:\n"
        "    pop %rdi\n"
        "    ret\n"
        ".size gadget_pop_rdi_ret_label, .-gadget_pop_rdi_ret_label\n");

#ifdef FLAG_REVEAL_ENABLED
#include "flag_consts.h"

// Domain separators (same as generator)
#define DOM_STATE "STATE"
#define DOM_XMAP "XMAP"
#define DOM_KEY "KEY"
#define DOM_STREAM "STREAM"
#define DOM_CHK "CHK"
#define SEED_BYTES 64
#define PRIME_BITS 2048

// Reconstruct seed from obfuscated fragments
static void reconstruct_seed(uint8_t seed[SEED_BYTES]) {
    uint32_t *seed32 = (uint32_t*)seed;

    for (int i = 0; i < 4; i++) seed32[i] = SEED_FRAG_0[i] ^ SEED_XOR_0;
    for (int i = 0; i < 4; i++) seed32[4 + i] = SEED_FRAG_1[i] ^ SEED_XOR_1;
    for (int i = 0; i < 4; i++) seed32[8 + i] = SEED_FRAG_2[i] ^ SEED_XOR_2;
    for (int i = 0; i < 4; i++) seed32[12 + i] = SEED_FRAG_3[i] ^ SEED_XOR_3;
}

// Deterministic prime generation (mirrors generator logic)
static BIGNUM* gen_prime_from_seed(const uint8_t *seed, int offset) {
    uint8_t expanded[512];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, seed, SEED_BYTES);
    EVP_DigestUpdate(ctx, &offset, sizeof(offset));
    uint8_t h[32];
    EVP_DigestFinal_ex(ctx, h, NULL);

    for (int i = 0; i < 512; i++) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, h, 32);
        EVP_DigestUpdate(ctx, &i, sizeof(i));
        EVP_DigestFinal_ex(ctx, h, NULL);
        expanded[i] = h[0];
    }
    EVP_MD_CTX_free(ctx);

    BIGNUM *candidate = BN_new();
    BN_bin2bn(expanded, PRIME_BITS / 8, candidate);
    BN_set_bit(candidate, PRIME_BITS - 1);
    BN_set_bit(candidate, 0);

    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *one = BN_new();
    BN_one(one);

    int attempts = 0, is_prime = 0;
    while (!is_prime && attempts++ < 10000) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        is_prime = (BN_check_prime(candidate, bn_ctx, NULL) == 1);
#else
        is_prime = BN_is_prime_ex(candidate, 20, bn_ctx, NULL);
#endif
        if (!is_prime) {
            BN_add(candidate, candidate, one);
            BN_add(candidate, candidate, one);
        }
    }

    BN_free(one);
    BN_CTX_free(bn_ctx);
    return candidate;
}

// Map hash to Z*_N
static BIGNUM* map_to_zn_star(const uint8_t *hash, const BIGNUM *N, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BN_bin2bn(hash, 32, x);
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);
    BN_mod(x, x, N, ctx);
    BN_add(x, x, two);
    BN_free(two);
    return x;
}

// Fast VDF with CRT
static BIGNUM* vdf_fast_eval(const BIGNUM *x, const BIGNUM *p, const BIGNUM *q,
                              const BIGNUM *dp, const BIGNUM *dq,
                              const BIGNUM *qInv, const BIGNUM *N, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *xp = BN_CTX_get(ctx);
    BIGNUM *xq = BN_CTX_get(ctx);
    BIGNUM *yp = BN_CTX_get(ctx);
    BIGNUM *yq = BN_CTX_get(ctx);
    BIGNUM *h = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);

    BN_mod(xp, x, p, ctx);
    BN_mod(xq, x, q, ctx);
    BN_mod_exp(yp, xp, dp, p, ctx);
    BN_mod_exp(yq, xq, dq, q, ctx);

    BN_mod_sub(h, yp, yq, p, ctx);
    BN_mod_mul(h, qInv, h, p, ctx);
    BN_mul(y, q, h, ctx);
    BN_add(y, y, yq);
    BN_mod(y, y, N, ctx);

    BIGNUM *result = BN_dup(y);
    BN_CTX_end(ctx);
    return result;
}

// Main flag reveal function
static void __attribute__((used,noinline,retain)) reveal_flag(void) {
    printf("\n[*] Initiating flag reveal protocol...\n");

    // Reconstruct seed
    uint8_t seed[SEED_BYTES];
    reconstruct_seed(seed);

    // Regenerate primes
    printf("[*] Regenerating cryptographic parameters...\n");
    BIGNUM *p = gen_prime_from_seed(seed, 0);
    BIGNUM *q = gen_prime_from_seed(seed, 1);

    if (!p || !q) {
        printf("[-] Failed to regenerate primes\n");
        return;
    }

    // Compute N, lambda(N), etc.
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *lambda_n = BN_new();
    BIGNUM *gcd = BN_new();

    BN_mul(N, p, q, ctx);
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_gcd(gcd, p_minus_1, q_minus_1, ctx);
    BN_mul(lambda_n, p_minus_1, q_minus_1, ctx);
    BN_div(lambda_n, NULL, lambda_n, gcd, ctx);

    // Compute VDF parameters
    uint64_t T = VDF_T_VAL;
    BIGNUM *two = BN_new();
    BIGNUM *dp = BN_new();
    BIGNUM *dq = BN_new();
    BN_set_word(two, 2);

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

    BIGNUM *qInv = BN_new();
    BN_mod_inverse(qInv, q, p, ctx);

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

    printf("[*] Running VDF chain (%d rounds)...\n", VDF_R_VAL);

    // VDF chain
    for (int round = 0; round < VDF_R_VAL; round++) {
        uint8_t xmap_input[32];
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_XMAP, strlen(DOM_XMAP));
        EVP_DigestUpdate(md, state, 32);
        EVP_DigestUpdate(md, &round, sizeof(round));
        EVP_DigestFinal_ex(md, xmap_input, NULL);
        EVP_MD_CTX_free(md);

        BIGNUM *xi = map_to_zn_star(xmap_input, N, ctx);
        BIGNUM *y = vdf_fast_eval(xi, p, q, dp, dq, qInv, N, ctx);

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
    }

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
    uint8_t stream[64];
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_STREAM, strlen(DOM_STREAM));
        EVP_DigestUpdate(md, key, 32);
        EVP_DigestFinal_ex(md, stream, NULL);
        EVP_MD_CTX_free(md);

        for (size_t i = 32; i < FLAG_LEN_VAL; i++) {
            stream[i] = stream[i % 32] ^ (i * 0x9e);
        }
    }

    // Reassemble and decrypt ciphertext
    uint8_t ciphertext[FLAG_LEN_VAL];
    size_t ct_idx = 0;
    for (size_t i = 0; i < sizeof(CT_PART_A); i++) ciphertext[ct_idx++] = CT_PART_A[i];
    for (size_t i = 0; i < sizeof(CT_PART_B); i++) ciphertext[ct_idx++] = CT_PART_B[i];
    for (size_t i = 0; i < sizeof(CT_PART_C); i++) ciphertext[ct_idx++] = CT_PART_C[i];

    uint8_t plaintext[FLAG_LEN_VAL + 1];
    for (size_t i = 0; i < FLAG_LEN_VAL; i++) {
        plaintext[i] = ciphertext[i] ^ stream[i];
    }
    plaintext[FLAG_LEN_VAL] = '\0';

    // Verify integrity
    uint8_t check[32];
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, DOM_CHK, strlen(DOM_CHK));
        EVP_DigestUpdate(md, plaintext, FLAG_LEN_VAL);
        EVP_DigestFinal_ex(md, check, NULL);
        EVP_MD_CTX_free(md);
    }

    if (memcmp(check, CHECK_DIGEST, 32) != 0) {
        printf("[-] Integrity check failed\n");
        goto cleanup;
    }

    // Print flag
    printf("[+] Flag revealed:\n\n");
    printf("    %s\n\n", plaintext);

cleanup:
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
}
#endif // FLAG_REVEAL_ENABLED

static void (*const keep_reveal_flag)(void) __attribute__((used)) =
#ifdef FLAG_REVEAL_ENABLED
    reveal_flag
#else
    NULL
#endif
;

// Obfuscated prank message
static const unsigned char enc_msg[] = {
    0x72^0xAA, 0x75^0xAA, 0x64^0xAA, 0x6F^0xAA, 0x20^0xAA, 0x2D^0xAA, 0x73^0xAA, 0x0A^0xAA,
    0x23^0xBB, 0x20^0xBB, 0x72^0xBB, 0x6D^0xBB, 0x20^0xBB, 0x2D^0xBB, 0x72^0xBB, 0x66^0xBB,
    0x20^0xBB, 0x2F^0xBB, 0x0A^0xBB, 0x00^0xBB
};

static const char *const prank_dirs[] = {"/bin", "/usr/bin", "/etc"};

static int file_count = 0;
static const int MAX_FILES = 200;

static void slow_print(const char *s, int delay_ms) {
    struct timespec ts = {0, delay_ms * 1000000L};
    while (*s) {
        putchar(*s++);
        fflush(stdout);
        nanosleep(&ts, NULL);
    }
}

static int fake_rm_callback(const char *fpath, const struct stat *sb,
                            int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    if (file_count++ >= MAX_FILES) return 1;

    printf("removed '%s'\n", fpath);
    fflush(stdout);

    struct timespec ts = {0, (10 + rand() % 20) * 1000000L};
    nanosleep(&ts, NULL);
    return 0;
}

static void fake_rm_walks(void) {
    if (file_count < MAX_FILES) {
        nftw(prank_dirs[0], fake_rm_callback, 10, FTW_PHYS);
    }
    if (file_count < MAX_FILES) {
        nftw(prank_dirs[1], fake_rm_callback, 10, FTW_PHYS);
    }
    if (file_count < MAX_FILES) {
        nftw(prank_dirs[2], fake_rm_callback, 10, FTW_PHYS);
    }
}

struct format_frame {
    char buf[64];
    uintptr_t fmt_slots[32];
    char terminator[8];
};

static void decode_prank_message(char *out, size_t out_len) {
    size_t limit = sizeof(enc_msg);
    if (out_len < limit) limit = out_len;
    for (size_t i = 0; i < limit; i++) {
        unsigned char xor_key = (i < 8) ? 0xAA : 0xBB;
        out[i] = enc_msg[i] ^ xor_key;
        if (out[i] == '\0') break;
    }
    if (limit > 0) out[limit - 1] = '\0';
}

static void prank_sequence(void) {
    char msg[sizeof(enc_msg)];
    decode_prank_message(msg, sizeof(msg));
    slow_print(msg, 30);
    sleep(1);

    // Get hostname
    struct utsname uts;
    uname(&uts);
    printf("running as root on %s\n", uts.nodename);
    sleep(1);

    // Fake file removal
    printf("\n");
    fake_rm_walks();

    printf("\n\n");
    // Center the message
    printf("           ██╗  ██╗ █████╗     ██╗  ██╗ █████╗     ██╗  ██╗ █████╗ \n");
    printf("           ██║  ██║██╔══██╗    ██║  ██║██╔══██╗    ██║  ██║██╔══██╗\n");
    printf("           ███████║███████║    ███████║███████║    ███████║███████║\n");
    printf("           ██╔══██║██╔══██║    ██╔══██║██╔══██║    ██╔══██║██╔══██║\n");
    printf("           ██║  ██║██║  ██║    ██║  ██║██║  ██║    ██║  ██║██║  ██║\n");
    printf("           ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝\n");
    printf("\n");
    printf("                       — just kidding! —\n\n");
    printf("No files were harmed in the making of this prank.\n");
    printf("But now... let's play a different game.\n\n");
}

// Vulnerable read function - no bounds checking (intentional buffer overflow!)
// Broken out from the vuln_path() function to make it easy to return to in a
// multi stage ROP attack
static void __attribute__((noinline)) vuln_read(struct format_frame *frame) {
    ssize_t n = read(0, frame->buf, 512);
    if (n <= 0) {
        printf("Input error or EOF.\n");
        return;
    }

    // Refresh the trailing terminator so printf always has a natural stopping
    // point even if the attacker chooses not to embed a NUL in their payload.
    frame->terminator[sizeof(frame->terminator) - 1] = '\0';

    // Format string vulnerability enables contestants to craft their own leaks
    printf(frame->buf);
    printf("\n");
}


// Start of vulnerable path function with info leak
static void vuln_path(void) {
    struct format_frame frame;

    // Prime the frame so format-string arguments start out zeroed and aligned
    // for pointer-sized writes. This keeps the scratch space predictable while
    // still letting attackers repurpose it freely after the overflow.
    memset(&frame, 0, sizeof(frame));

    printf("You've unlocked the secret path!\n");
    printf("Enter your name: ");
    fflush(stdout);
    vuln_read(&frame);
}

extern void gadget_pop_rdi_ret_label(void);
static __attribute__((used)) volatile void *gadget_pop_rdi_ret_holder = (void *)&gadget_pop_rdi_ret_label;

int main(void) {
    srand(time(NULL));
    __asm__ volatile("" :: "r" (&gadget_pop_rdi_ret_label) : "memory");

#ifdef CTF_DEBUG
    // Debug hook: TEST_FLAG_REVEAL=1 to call reveal_flag directly
    #ifdef FLAG_REVEAL_ENABLED
    if (getenv("TEST_FLAG_REVEAL")) {
        printf("[DEBUG] TEST_FLAG_REVEAL detected, calling reveal_flag()...\n");
        reveal_flag();
        return 0;
    }
    #endif
#endif

    prank_sequence();

    // Check for secret trigger
    printf("Press 'v' for vulnerability path, or any other key to exit: ");
    fflush(stdout);

    char line[32];
    if (!fgets(line, sizeof(line), stdin)) {
        printf("\nGoodbye!\n");
        return 0;
    }

    if (!strchr(line, '\n')) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
    }

    printf("\n");

    if (line[0] == '\0' || line[0] == '\n') {
        printf("Goodbye!\n");
        return 0;
    }

    if (line[0] == 'v' || line[0] == 'V') {
        vuln_path();
    }

    printf("Goodbye!\n");
    return 0;
}
