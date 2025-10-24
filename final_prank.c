#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ftw.h>
#include <sys/utsname.h>
#include <stdint.h>

// Obfuscated prank message
static const unsigned char enc_msg[] = {
    0x72^0xAA, 0x75^0xAA, 0x64^0xAA, 0x6F^0xAA, 0x20^0xAA, 0x2D^0xAA, 0x73^0xAA, 0x0A^0xAA,
    0x23^0xBB, 0x20^0xBB, 0x72^0xBB, 0x6D^0xBB, 0x20^0xBB, 0x2D^0xBB, 0x72^0xBB, 0x66^0xBB,
    0x20^0xBB, 0x2F^0xBB, 0x0A^0xBB, 0x00^0xBB
};

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

static void prank_sequence(void) {
    // Decode and print prank command
    char msg[64];
    for (size_t i = 0; i < sizeof(enc_msg); i++) {
        unsigned char xor_key = (i < 8) ? 0xAA : 0xBB;
        msg[i] = enc_msg[i] ^ xor_key;
        if (msg[i] == '\0') break;
    }

    slow_print(msg, 30);
    sleep(1);

    // Get hostname
    struct utsname uts;
    uname(&uts);
    printf("running as root on %s\n", uts.nodename);
    sleep(1);

    // Fake file removal
    printf("\n");
    const char *dirs[] = {"/bin", "/usr/bin", "/etc"};
    for (int i = 0; i < 3 && file_count < MAX_FILES; i++) {
        nftw(dirs[i], fake_rm_callback, 10, FTW_PHYS);
    }

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

// Vulnerable function with info leak
static void __attribute__((noinline)) vuln_path(void) {
    struct format_frame {
        char buf[64];
        uintptr_t fmt_slots[32];
        char terminator[8];
    } frame;

    // Prime the frame so format-string arguments start out zeroed and aligned
    // for pointer-sized writes. This keeps the scratch space predictable while
    // still letting attackers repurpose it freely after the overflow.
    memset(&frame, 0, sizeof(frame));

    printf("You've unlocked the secret path!\n");
    printf("Enter your name: ");
    fflush(stdout);

    // Vulnerable read - no bounds checking
    (void)read(0, frame.buf, 512);  // Buffer overflow!

    // Refresh the trailing terminator so printf always has a natural stopping
    // point even if the attacker chooses not to embed a NUL in their payload.
    frame.terminator[sizeof(frame.terminator) - 1] = '\0';

    // Format string vulnerability enables contestants to craft their own leaks
    printf(frame.buf);
    printf("\n");
}

int main(void) {
    srand(time(NULL));

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
