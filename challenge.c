#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <openssl/evp.h>
#include "b64.h"
#include "aes_wrap.h"
#include "obf_k2.h"

// External ciphertext (auto-generated)
extern const unsigned char ciphertext[];
extern const size_t ciphertext_len;

static uint8_t generated_k1[32];
static int k1_generated = 0;
static int k2_unlocked = 0;
static int decrypt_success = 0;

static volatile sig_atomic_t interrupted = 0;

// Zero IV
static const uint8_t IV[16] = {0};
static const char TARGET_PHRASE[] = "CASINO ROYALE!";
static const uint8_t TARGET_PHRASE_HASH[32] = {
    0x3c, 0xb0, 0x35, 0x5a, 0xc8, 0xaf, 0xc9, 0x63,
    0x87, 0xc9, 0x1b, 0x5f, 0xd2, 0x51, 0xd3, 0x06,
    0x5b, 0x29, 0xcc, 0x97, 0x33, 0x4c, 0xf1, 0x12,
    0x37, 0x52, 0x9f, 0x56, 0x5f, 0x93, 0x78, 0x7d
};

static void handle_sigint(int sig) {
    (void)sig;
    interrupted = 1;
}

static int read_line(char *buf, size_t size) {
    while (1) {
        if (interrupted) return 0;
        if (fgets(buf, size, stdin)) {
            size_t len = strcspn(buf, "\n");
            if (buf[len] == '\n') {
                buf[len] = '\0';
            } else {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF);
                buf[size - 1] = '\0';
            }
            return 1;
        }
        if (feof(stdin)) return 0;
        if (ferror(stdin)) {
            if (errno == EINTR) {
                clearerr(stdin);
                if (interrupted) return 0;
                continue;
            }
            return 0;
        }
        return 0;
    }
}

static uint8_t dice_transform_byte(uint8_t value, const uint8_t d[5]) {
    value = (uint8_t)((value + d[0]) & 0xFF);
    value = (uint8_t)(value ^ d[1]);
    value = (uint8_t)((value - d[2]) & 0xFF);
    value = (uint8_t)(value ^ d[3]);
    value = (uint8_t)((value + d[4]) & 0xFF);
    return value;
}

static void dice_transform_buffer(const uint8_t d[5], const uint8_t *src, size_t len, uint8_t *dst) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = dice_transform_byte(src[i], d);
    }
}

static void sha256_digest(const void *chunks[], const size_t lens[], size_t count, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "SHA256 context allocation failed\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "SHA256 init failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    for (size_t i = 0; i < count; i++) {
        if (EVP_DigestUpdate(ctx, chunks[i], lens[i]) != 1) {
            fprintf(stderr, "SHA256 update failed\n");
            EVP_MD_CTX_free(ctx);
            exit(1);
        }
    }
    if (EVP_DigestFinal_ex(ctx, out, NULL) != 1) {
        fprintf(stderr, "SHA256 final failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    EVP_MD_CTX_free(ctx);
}

// Parse hex string to bytes
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || strlen(hex) != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%02x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return 1;
}

// Print bytes as hex
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

// K2 verifier: first 8 hex chars of SHA256(K2 || "yahtzee-tag")
static void k2_verifier(const uint8_t k2[32], char out[9]) {
    uint8_t digest[32];
    const char *tag = "yahtzee-tag";

    const void *chunks[] = {k2, tag};
    const size_t lens[] = {32, 11};
    sha256_digest(chunks, lens, 2, digest);

    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[2*i] = hex[digest[i] >> 4];
        out[2*i+1] = hex[digest[i] & 0xF];
    }
    out[8] = '\0';
}

// De-obfuscate K2 from dice
static void unveil_k2_from_dice(const uint8_t d[5], uint8_t k2[32]) {
    dice_transform_buffer(d, OBF_K2, 32, k2);
}

// Hash phrase after dice manipulation for validation
static void dice_phrase_digest(const uint8_t d[5], uint8_t out[32]) {
    uint8_t transformed[sizeof(TARGET_PHRASE) - 1];
    dice_transform_buffer(d, (const uint8_t *)TARGET_PHRASE, sizeof(transformed), transformed);
    const void *chunks[] = {transformed};
    const size_t lens[] = {sizeof(transformed)};
    sha256_digest(chunks, lens, 1, out);
}

static void report_k2_result(const uint8_t dice[5], const uint8_t k2[32], const char *failure_msg) {
    char verif[9];
    k2_verifier(k2, verif);
    printf("K2 Verifier: %s\n", verif);

    uint8_t phrase_hash[32];
    dice_phrase_digest(dice, phrase_hash);
    const int match = (memcmp(phrase_hash, TARGET_PHRASE_HASH, 32) == 0);

#ifdef CTF_DEBUG
    printf("[DEBUG] Dice: %d %d %d %d %d\n", dice[0], dice[1], dice[2], dice[3], dice[4]);
    printf("[DEBUG] Phrase hash (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x", phrase_hash[i]);
    printf("\n[DEBUG] Target hash (first 8): ");
    for (int i = 0; i < 8; i++) printf("%02x", TARGET_PHRASE_HASH[i]);
    printf("\n[DEBUG] Match: %s\n", match ? "YES" : "NO");
#endif

    if (match) {
        printf("\nCongratulations your key is: ");
        print_hex(k2, 32);
        printf("\n");
        k2_unlocked = 1;
#ifdef CTF_DEBUG
        printf("[DEBUG] K2 unlocked!\n");
#endif
    } else {
        printf("\n");
        printf("\n%s\n", failure_msg);
    }
    printf("\n");
}

// Check anti-debug/anti-VM
static int check_security(void) {
    static int security_cleared = 0;
    static int ptrace_primed = 0;

    if (k2_unlocked || decrypt_success) {
#ifdef CTF_DEBUG
        printf("[DEBUG] Security bypassed (k2_unlocked=%d, decrypt_success=%d)\n",
               k2_unlocked, decrypt_success);
#endif
        return 1;
    }
    if (getenv("CTF_ALLOW_DEBUG")) {
#ifdef CTF_DEBUG
        printf("[DEBUG] CTF_ALLOW_DEBUG set, bypassing checks\n");
#endif
        return 1;
    }
    if (security_cleared) return 1;

    if (!ptrace_primed) {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int pid = 0;
                    if (sscanf(line + 10, "%d", &pid) == 1 && pid != 0) {
                        fclose(f);
                        fprintf(stderr, "!!! Debugger detected (TracerPid)\n");
                        return 0;
                    }
                    break;
                }
            }
            fclose(f);
        }

        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            if (errno == EPERM || errno == EBUSY || errno == EINVAL) {
                fprintf(stderr, "!!! Debugger detected (ptrace)\n");
                return 0;
            }
        } else {
            ptrace_primed = 1;
            ptrace(PTRACE_DETACH, 0, NULL, NULL);
        }
    }

    const char *ld_vars[] = {"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", NULL};
    for (int i = 0; ld_vars[i]; i++) {
        if (getenv(ld_vars[i])) {
            fprintf(stderr, "!!! LD variable detected: %s\n", ld_vars[i]);
            unsetenv(ld_vars[i]);
        }
    }

    security_cleared = 1;
    return 1;
}

// Yahtzee - roll and sort descending
static void play_yahtzee(void) {
    if (!check_security()) {
        printf("Security check failed.\n");
        return;
    }

    printf("\n=== Yahtzee Game ===\n");
    printf("Rolling 5 dice...\n");

    uint8_t dice[5];
    for (int i = 0; i < 5; i++) {
        dice[i] = (rand() % 6) + 1;
    }

    printf("Raw roll: ");
    for (int i = 0; i < 5; i++) printf("%d ", dice[i]);
    printf("\n");

    // Sort descending
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 5; j++) {
            if (dice[j] > dice[i]) {
                uint8_t tmp = dice[i];
                dice[i] = dice[j];
                dice[j] = tmp;
            }
        }
    }

    printf("Sorted (desc): ");
    for (int i = 0; i < 5; i++) printf("%d ", dice[i]);
    printf("\n");

    // Derive K2
    uint8_t k2[32];
    unveil_k2_from_dice(dice, k2);
    report_k2_result(dice, k2, "Sorry try again!");
}

// Cheat mode - manual dice entry (no sorting)
static void cheat_mode(void) {
    if (!check_security()) {
        printf("Security check failed.\n");
        return;
    }

    printf("\n=== Cheat Mode ===\n");
    printf("Enter 5 dice values (space separated, 1-6): ");

    char line[128];
    if (!read_line(line, sizeof(line))) {
        printf("\nInput aborted.\n");
        return;
    }

    uint8_t dice[5];
    int count = 0;
    char *saveptr = NULL;
    for (char *token = strtok_r(line, " \t", &saveptr);
         token;
         token = strtok_r(NULL, " \t", &saveptr)) {
        if (count >= 5) {
            printf("Need exactly 5 dice values.\n");
            return;
        }
        char *endptr = NULL;
        unsigned long val = strtoul(token, &endptr, 10);
        if (endptr == token || *endptr != '\0') {
            printf("Dice values must be integers.\n");
            return;
        }
        if (val < 1 || val > 6) {
            printf("Dice values must be 1-6.\n");
            return;
        }
        dice[count++] = (uint8_t)val;
    }

    if (count != 5) {
        printf("Need exactly 5 dice values.\n");
        return;
    }

    printf("Entered dice: ");
    for (int i = 0; i < 5; i++) printf("%d ", dice[i]);
    printf("\n");

    // Derive K2 (no sorting in cheat mode!)
    uint8_t k2[32];
    unveil_k2_from_dice(dice, k2);
    report_k2_result(dice, k2, "Cheaters never prosper!");
}

// Generate weak K1
static void generate_k1(void) {
    printf("\n=== Generate Key ===\n");

    // 5-byte pattern: [0xAB, 0xCB, 0xCD, 0xEF, DIGIT]
    // where DIGIT is random 1-6
    const uint8_t pattern[] = {0xAB, 0xCB, 0xCD, 0xEF};

    for (int i = 0; i < 32; i += 5) {
        for (int j = 0; j < 4 && (i+j) < 32; j++) {
            generated_k1[i+j] = pattern[j];
        }
        if (i+4 < 32) {
            generated_k1[i+4] = (rand() % 6) + 1;
        }
    }

    // Ensure exactly 32 bytes
    k1_generated = 1;

    printf("Generated Key: ");
    print_hex(generated_k1, 32);
    printf("\n");
}

// Decrypt and execute final binary
static void decrypt_and_exec(void) {
    printf("\n=== Decrypt Payload ===\n");

    printf("Enter Key 1");
    if (k1_generated) printf(", or press Enter to use generated");
    printf(": ");

    char k1_hex[128];
    if (!read_line(k1_hex, sizeof(k1_hex))) {
        printf("\nInput aborted.\n");
        return;
    }

    // If user pressed Enter and we have a generated key, use it
    if (k1_generated && k1_hex[0] == '\0') {
        // Use existing generated_k1, do nothing
    } else {
        // User provided input - validate and parse to temporary buffer
        uint8_t temp_k1[32];
        if (strlen(k1_hex) != 64 || !hex_to_bytes(k1_hex, temp_k1, 32)) {
            printf("Invalid Key 1 (must be 64 hex characters).\n");
            return;
        }
        // Valid input - copy to generated_k1
        memcpy(generated_k1, temp_k1, 32);
        k1_generated = 1;
    }

    printf("Enter Key 2: ");
    char k2_hex[128];
    if (!read_line(k2_hex, sizeof(k2_hex))) {
        printf("\nInput aborted.\n");
        return;
    }

    uint8_t k2[32];
    if (strlen(k2_hex) != 64 || !hex_to_bytes(k2_hex, k2, 32)) {
        printf("Invalid Key 2.\n");
        return;
    }

#ifdef CTF_DEBUG
    printf("[DEBUG] K1 (first 16 hex): ");
    for (int i = 0; i < 8; i++) printf("%02x", generated_k1[i]);
    printf("...\n");
    printf("[DEBUG] K2 (first 16 hex): ");
    for (int i = 0; i < 8; i++) printf("%02x", k2[i]);
    printf("...\n");
    printf("[DEBUG] Ciphertext size: %zu bytes\n", ciphertext_len);
#endif

    printf("\nDecrypting...\n");

    // Decrypt with K2
    size_t stage1_len;
    unsigned char *stage1 = aes_decrypt(ciphertext, ciphertext_len, k2, IV, &stage1_len);
    if (!stage1) {
        printf("Decryption failed (Key 2 stage).\n");
        return;
    }

    // Decrypt with K1
    size_t stage2_len;
    unsigned char *stage2 = aes_decrypt(stage1, stage1_len, generated_k1, IV, &stage2_len);
    free(stage1);
    if (!stage2) {
        printf("Decryption failed (Key 1 stage).\n");
        return;
    }

    // Base64 decode
    size_t final_len;
    unsigned char *vulnerable_blob = b64_decode((char*)stage2, stage2_len, &final_len);
    free(stage2);
    if (!vulnerable_blob) {
        printf("Decryption failed (Key 1 stage).\n");
        return;
    }

    printf("Decryption successful! Writing ./vulnerable...\n");

#ifdef CTF_DEBUG
    printf("[DEBUG] Stage1 (K2 decrypt) size: %zu bytes\n", stage1_len);
    printf("[DEBUG] Stage2 (K1 decrypt) size: %zu bytes\n", stage2_len);
    printf("[DEBUG] Final (base64 decoded) size: %zu bytes\n", final_len);
#endif

    // Write to file
    FILE *out = fopen("./vulnerable", "wb");
    if (!out) {
        perror("fopen");
        free(vulnerable_blob);
        return;
    }
    fwrite(vulnerable_blob, 1, final_len, out);
    fclose(out);
    free(vulnerable_blob);

    // Make executable
    chmod("./vulnerable", 0755);

    printf("Wrote ./vulnerable (%zu bytes)\n", final_len);
    printf("Launch ./vulnerable manually to continue the challenge.\n");
    decrypt_success = 1;
#ifdef CTF_DEBUG
    printf("[DEBUG] decrypt_success set to 1\n");
#endif
    printf("\nExiting so you can take it from here.\n");
    exit(0);
}

int main(void) {
    srand(time(NULL));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    printf("╔═══════════════════════════════════════╗\n");
    printf("║     Play to Earn - Yahtzee CTF        ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    int last_choice = -1;

    while (1) {
        if (interrupted) {
            printf("\nGoodbye!\n");
            return 0;
        }
        printf("1) Play a game\n");
        printf("2) Cheat\n");
        printf("3) Generate a Key\n");
        printf("4) Decrypt payload\n");
        printf("5) Exit\n");
        printf("\nChoice: ");
        fflush(stdout);

        char line[32];
        if (!read_line(line, sizeof(line))) {
            printf("\nGoodbye!\n");
            return 0;
        }

        int choice = -1;

        if (line[0] == '\0') {
            printf("\n");
            if (last_choice == -1) {
                printf("No previous selection to repeat.\n");
                continue;
            }
            printf("(Repeating choice %d)\n", last_choice);
            choice = last_choice;
        } else {
            char *endptr = NULL;
            long parsed = strtol(line, &endptr, 10);
            if (*endptr != '\0' || parsed < 1 || parsed > 5) {
                printf("Invalid input.\n");
                continue;
            }
            choice = (int)parsed;
        }

        switch (choice) {
            case 1:
                play_yahtzee();
                last_choice = 1;
                break;
            case 2:
                cheat_mode();
                last_choice = 2;
                break;
            case 3:
                generate_k1();
                last_choice = 3;
                break;
            case 4:
                decrypt_and_exec();
                last_choice = 4;
                break;
            case 5:
                last_choice = 5;
                printf("Goodbye!\n");
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }

    return 0;
}
