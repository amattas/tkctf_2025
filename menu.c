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
#include <openssl/sha.h>
#include "b64.h"
#include "aes_wrap.h"
#include "obf_k2.h"

// External ciphertext (auto-generated)
extern const unsigned char ciphertext[];
extern const size_t ciphertext_len;

// Static K2 for verification (injected at compile time)
#ifndef STATIC_K2_HEX
#define STATIC_K2_HEX "4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760"
#endif

static uint8_t STATIC_K2[32];
static uint8_t generated_k1[32];
static int k1_generated = 0;
static int k2_unlocked = 0;
static int decrypt_success = 0;

// Zero IV
static const uint8_t IV[16] = {0};

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

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k2, 32);
    SHA256_Update(&ctx, tag, 11);
    SHA256_Final(digest, &ctx);

    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[2*i] = hex[digest[i] >> 4];
        out[2*i+1] = hex[digest[i] & 0xF];
    }
    out[8] = '\0';
}

// De-obfuscate K2 from dice
static void unveil_k2_from_dice(const uint8_t d[5], uint8_t k2[32]) {
    for (int i = 0; i < 32; i++) {
        uint8_t k = OBF_K2[i];
        k = (uint8_t)((k + d[0]) & 0xFF);
        k = (uint8_t)(k ^ d[1]);
        k = (uint8_t)((k - d[2]) & 0xFF);
        k = (uint8_t)(k ^ d[3]);
        k = (uint8_t)((k + d[4]) & 0xFF);
        k2[i] = k;
    }
}

// Check anti-debug/anti-VM
static int check_security(void) {
    if (k2_unlocked || decrypt_success) return 1;

    // Check ptrace
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "[!] Debugger detected (ptrace)\n");
        return 0;
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);

    // Check TracerPid
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid;
                if (sscanf(line + 10, "%d", &pid) == 1 && pid != 0) {
                    fclose(f);
                    fprintf(stderr, "[!] Debugger detected (TracerPid)\n");
                    return 0;
                }
                break;
            }
        }
        fclose(f);
    }

    // Check LD_PRELOAD, LD_AUDIT, LD_DEBUG
    const char *ld_vars[] = {"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", NULL};
    for (int i = 0; ld_vars[i]; i++) {
        if (getenv(ld_vars[i])) {
            fprintf(stderr, "[!] LD variable detected: %s\n", ld_vars[i]);
            unsetenv(ld_vars[i]);
        }
    }

    // Simple VM check (DMI)
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        NULL
    };
    const char *vm_strings[] = {"QEMU", "KVM", "VirtualBox", "VMware", NULL};

    for (int i = 0; dmi_files[i]; i++) {
        FILE *df = fopen(dmi_files[i], "r");
        if (df) {
            char buf[128];
            if (fgets(buf, sizeof(buf), df)) {
                for (int j = 0; vm_strings[j]; j++) {
                    if (strstr(buf, vm_strings[j])) {
                        fclose(df);
                        fprintf(stderr, "[!] VM detected: %s\n", vm_strings[j]);
                        return 0;
                    }
                }
            }
            fclose(df);
        }
    }

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

    // Print decoy (unless CTF_SHOW_REAL_K2 is set)
    if (getenv("CTF_SHOW_REAL_K2")) {
        printf("\nDerived K2 (hex): ");
        print_hex(k2, 32);
        printf("\n");
    } else {
        // Print obfuscated decoy
        printf("\nDerived K2 (obfuscated): ");
        for (int i = 0; i < 64; i++) {
            putchar(0x20 + (i % (0x7F - 0x20)));
        }
        printf("\n");
    }

    // Print verifier
    char verif[9];
    k2_verifier(k2, verif);
    printf("K2 Verifier: %s\n", verif);

    // Check if matches target
    if (memcmp(k2, STATIC_K2, 32) == 0) {
        printf("\n[K2 MATCH] You hit the Yahtzee target key!\n");
        k2_unlocked = 1;
    }

    printf("\n");
}

// Cheat mode - manual dice entry (no sorting)
static void cheat_mode(void) {
    if (!check_security()) {
        printf("Security check failed.\n");
        return;
    }

    printf("\n=== Cheat Mode ===\n");
    printf("Enter 5 dice values (space separated, 1-6): ");

    uint8_t dice[5];
    if (scanf("%hhu %hhu %hhu %hhu %hhu", &dice[0], &dice[1], &dice[2], &dice[3], &dice[4]) != 5) {
        printf("Invalid input.\n");
        while (getchar() != '\n');
        return;
    }
    while (getchar() != '\n');

    // Validate
    for (int i = 0; i < 5; i++) {
        if (dice[i] < 1 || dice[i] > 6) {
            printf("Dice values must be 1-6.\n");
            return;
        }
    }

    printf("Entered dice: ");
    for (int i = 0; i < 5; i++) printf("%d ", dice[i]);
    printf("\n");

    // Derive K2 (no sorting in cheat mode!)
    uint8_t k2[32];
    unveil_k2_from_dice(dice, k2);

    // Print decoy or real
    if (getenv("CTF_SHOW_REAL_K2")) {
        printf("\nDerived K2 (hex): ");
        print_hex(k2, 32);
        printf("\n");
    } else {
        printf("\nDerived K2 (obfuscated): ");
        for (int i = 0; i < 64; i++) {
            putchar(0x20 + (i % (0x7F - 0x20)));
        }
        printf("\n");
    }

    // Print verifier
    char verif[9];
    k2_verifier(k2, verif);
    printf("K2 Verifier: %s\n", verif);

    // Check if matches target
    if (memcmp(k2, STATIC_K2, 32) == 0) {
        printf("\n[K2 MATCH] You hit the Yahtzee target key!\n");
        k2_unlocked = 1;
    }

    printf("\n");
}

// Generate weak K1
static void generate_k1(void) {
    printf("\n=== Generate K1 ===\n");

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

    printf("Generated K1 (hex): ");
    print_hex(generated_k1, 32);
    printf("\n");
    printf("(Pattern: AB CB CD EF [1-6] repeating)\n\n");
}

// Decrypt and execute final binary
static void decrypt_and_exec(void) {
    printf("\n=== Decrypt Final Binary ===\n");

    // Get K2
    char k2_hex[65];
    printf("Enter K2 (64 hex chars): ");
    if (scanf("%64s", k2_hex) != 1) {
        printf("Invalid input.\n");
        while (getchar() != '\n');
        return;
    }
    while (getchar() != '\n');

    uint8_t k2[32];
    if (!hex_to_bytes(k2_hex, k2, 32)) {
        printf("Invalid K2 hex string.\n");
        return;
    }

    // Get K1
    char k1_hex[65];
    if (k1_generated) {
        printf("Enter K1 (64 hex chars, or press Enter to use generated): ");
        if (fgets(k1_hex, sizeof(k1_hex), stdin) == NULL) {
            printf("Read error.\n");
            return;
        }
        if (k1_hex[0] == '\n') {
            // Use generated K1
            memcpy(k1_hex, generated_k1, 32);
        } else {
            k1_hex[strcspn(k1_hex, "\n")] = 0;
            if (!hex_to_bytes(k1_hex, generated_k1, 32)) {
                printf("Invalid K1 hex string.\n");
                return;
            }
        }
    } else {
        printf("Enter K1 (64 hex chars): ");
        if (scanf("%64s", k1_hex) != 1) {
            printf("Invalid input.\n");
            while (getchar() != '\n');
            return;
        }
        while (getchar() != '\n');
        if (!hex_to_bytes(k1_hex, generated_k1, 32)) {
            printf("Invalid K1 hex string.\n");
            return;
        }
    }

    printf("\nDecrypting...\n");

    // Decrypt with K2
    size_t stage1_len;
    unsigned char *stage1 = aes_decrypt(ciphertext, ciphertext_len, k2, IV, &stage1_len);
    if (!stage1) {
        printf("Decryption failed (K2 stage).\n");
        return;
    }

    // Decrypt with K1
    size_t stage2_len;
    unsigned char *stage2 = aes_decrypt(stage1, stage1_len, generated_k1, IV, &stage2_len);
    free(stage1);
    if (!stage2) {
        printf("Decryption failed (K1 stage).\n");
        return;
    }

    // Base64 decode
    size_t final_len;
    unsigned char *final_bin = b64_decode((char*)stage2, stage2_len, &final_len);
    free(stage2);
    if (!final_bin) {
        printf("Base64 decode failed.\n");
        return;
    }

    printf("Decryption successful! Writing ./final_bin...\n");

    // Write to file
    FILE *out = fopen("./final_bin", "wb");
    if (!out) {
        perror("fopen");
        free(final_bin);
        return;
    }
    fwrite(final_bin, 1, final_len, out);
    fclose(out);
    free(final_bin);

    // Make executable
    chmod("./final_bin", 0755);

    printf("Wrote ./final_bin (%zu bytes)\n", final_len);
    decrypt_success = 1;

    // Auto-exec unless CTF_NO_AUTOEXEC
    if (!getenv("CTF_NO_AUTOEXEC")) {
        printf("\nExecuting ./final_bin...\n\n");
        setenv("ALLOW_DEBUG", "1", 1);
        execl("./final_bin", "./final_bin", NULL);
        perror("execl");
    } else {
        printf("Auto-exec disabled. Run ./final_bin manually.\n");
    }
}

int main(void) {
    srand(time(NULL));

    // Parse static K2
    if (!hex_to_bytes(STATIC_K2_HEX, STATIC_K2, 32)) {
        fprintf(stderr, "Failed to parse STATIC_K2_HEX\n");
        return 1;
    }

    printf("╔═══════════════════════════════════════╗\n");
    printf("║     Play to Earn - Yahtzee CTF        ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    while (1) {
        printf("1) Play game (Yahtzee)\n");
        printf("2) Cheat (manual dice)\n");
        printf("3) Generate a Key\n");
        printf("4) Decrypt final binary\n");
        printf("5) Exit\n");
        printf("\nChoice: ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input.\n");
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                play_yahtzee();
                break;
            case 2:
                cheat_mode();
                break;
            case 3:
                generate_k1();
                break;
            case 4:
                decrypt_and_exec();
                break;
            case 5:
                printf("Goodbye!\n");
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }

    return 0;
}
