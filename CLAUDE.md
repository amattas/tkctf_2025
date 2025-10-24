Here’s the updated **CLAUDE.md** with **PIE ON** for both binaries, while keeping **partial RELRO**, **ASLR on**, **stack canary**, and your **per-byte `+ ^ - ^ +` K2 obfuscation**. It also calls out that PIE requires an **info-leak** (and instructs adding a simple `puts@plt(puts@got)` leak) so the challenge stays hard-but-fair.

---

# CLAUDE.md

## Project: “Play to Earn” — Two-Binary CTF Challenge (PIE **ON**)

Build a two-binary Linux CTF challenge exactly per the spec below.
Produce production-ready C source, a Makefile, and minimal docs.
Follow the crypto pipeline and per-byte K2 obfuscation precisely.

---

## Repository layout (deliverables)

```
.
├── README.md
├── Makefile
├── challenge.c
├── vulnerable.c
├── b64.c
├── b64.h
├── aes_wrap.c
├── aes_wrap.h
├── ciphertext.c              # auto-generated from Makefile (xxd -i)
├── obf_k2.h                  # auto-generated from Makefile (gen_obf_k2)
└── tools/
    └── gen_obf_k2.c          # computes OBF_K2 from K2_HEX and target dice (per-byte inverse)
```

---

## Build hardening

| Setting             | Value                                                       |
| ------------------- | ----------------------------------------------------------- |
| Compiler            | GCC (C11, glibc)                                            |
| PIE                 | **ON** (`-fPIE -pie` for both binaries)                     |
| RELRO               | **Partial** (`-Wl,-z,relro`; do **not** add `-z now`)       |
| ASLR                | **ON** (host: `/proc/sys/kernel/randomize_va_space=2`)      |
| Stack canary        | **ON** (`-fstack-protector-strong`)                         |
| NX                  | **ON** (default)                                            |
| Strip               | `strip -s`                                                  |
| Gadget minimization | `-O2 -ffunction-sections -fdata-sections -Wl,--gc-sections` |
| Warnings            | `-Wall -Wextra`                                             |

**Note on PIE:** With PIE + ASLR, exploitation requires an **info leak** (e.g., a `puts(GOT)` pattern) to recover a base and compute gadget addresses. Include a small, intentional leak in `vulnerable.c`'s vulnerable path so the challenge is hard-but-fair.

---

## Crypto pipeline

**AES-256-CBC**, IV = 16×`0x00`, **no salt**.

### Encrypt (build time)

```
vulnerable
 → Base64 encode
   → AES-256-CBC with K1
     → AES-256-CBC with K2
       → ciphertext.bin → ciphertext.c
```

### Decrypt (runtime in menu)

```
ciphertext
 → Decrypt with K2
   → Decrypt with K1
     → Base64 decode
       → write ./vulnerable (+x)
```

Padding: PKCS#7 (default). Use OpenSSL EVP in code; `openssl enc` in Makefile.

---

## Static keys (build-time)

### K1 (weak patterned key, 32 bytes)

```
K1_HEX = abcbcdef02abcbcdef05abcbcdef01abcbcdef06abcbcdef03abcbcdef04abcb
```

### K2 (real Yahtzee key, 32 bytes)

Target dice = `[5,4,3,2,1]` (descending).
Combiner-v2 on accumulator: `+5 ^4 -3 ^2 +1 → acc = 0xFD`
Seed (16B): `05 04 03 02 01 FD 79 61 68 74 7A 65 65 2D 76 32`
`K2_HEX = 4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760`

IV (hex): `00000000000000000000000000000000`

---

## Obfuscated K2 (per-byte `+ ^ - ^ +` rule)

The menu **does not store K2 in clear**. It embeds a 32-byte `OBF_K2` that must be de-obfuscated using the five dice.

### Build-time obfuscation (inverse, per byte)

Let `d1..d5` be the target dice (here `5,4,3,2,1`).
For each byte:

```
k = K2_real[i]
k = (k - d5) & 0xFF   // inverse of +d5
k =  k ^ d4
k = (k + d3) & 0xFF   // inverse of -d3
k =  k ^ d2
k = (k - d1) & 0xFF   // inverse of +d1
OBF_K2[i] = k
```

### Runtime de-obfuscation (forward, per byte)

Given five dice `d1..d5` (sorted in Play, raw order in Cheat):

```
k = OBF_K2[i]
k = (k + d1) & 0xFF
k =  k ^ d2
k = (k - d3) & 0xFF
k =  k ^ d4
k = (k + d5) & 0xFF
K2_real[i] = k
```

Correct dice (or correct Cheat input `54321`) → correct K2.

---

## Menu (binary #1)

### Menu layout

```
1) Play game (Yahtzee)        → roll; then sort descending; derive K2 by de-obfuscation
2) Cheat (manual dice)        → user enters dice; NO sorting; derive K2 by de-obfuscation
3) Generate a Key             → generate and print weak K1 (shows AB CB CD EF + DIGIT pattern)
4) Decrypt final binary       → prompt K2 then K1 (or auto-fill K1); decode → write → exec
5) Exit
```

### K2 UI policy (after de-obfuscation)

* **Do not** print real K2 by default.
* Print obfuscated decoy (64 printable ASCII chars cycling 0x20–0x7E).
* Print **K2 verifier**: first 8 hex of `SHA256( K2_real || "yahtzee-tag" )`.
* If `K2_real == STATIC_K2_HEX`, also print:
  `[K2 MATCH] You hit the Yahtzee target key.`
* Grader override `CTF_SHOW_REAL_K2=1`: print real K2 hex instead of decoy (and still print verifier).

### K1 (Option 3)

* Build 32 bytes from 5-byte blocks `[0xAB, 0xCB, 0xCD, 0xEF, DIGIT]` with `DIGIT∈{1..6}` random per block; repeat then truncate to 32B.
* Print hex and store for Option 4 default.

### Decrypt (Option 4)

* Prompt for K1 hex (allow Enter to accept generated K1) followed by K2 hex.
* Decrypt embedded `ciphertext[]` (K2→K1), Base64-decode, write `./vulnerable`, and `chmod +x` the result. Execution is left to the player.

### Anti-debug / Anti-VM (menu only, until K2 success or decrypt success)

* Block if:

  * `/proc/self/status` `TracerPid != 0`
  * `ptrace(PTRACE_TRACEME)` fails
  * `LD_PRELOAD`, `LD_AUDIT`, `LD_DEBUG` present (unset or exit)
  * Obvious VM/QEMU heuristics (DMI strings `QEMU`, `KVM`, `VirtualBox`, `VMware`; hypervisor bit)
* Relax after K2 or decrypt success.
* Hidden env overrides:

  * `CTF_ALLOW_DEBUG=1` (disable checks)
  * `CTF_SHOW_REAL_K2=1` (print real K2)

---

## Final binary (`vulnerable`)

### Prank in `main()`

* XOR-decode `"sudo -s\n# rm -rf /\n"`; print char-by-char (~20–40 ms/char).
* Print `running as root on <hostname>`.
* `nftw(..., FTW_PHYS)` over `/bin`, `/usr/bin`, `/etc`, printing `removed '…'` lines (delay 10–30 ms), cap ~400 entries.
* Print centered `ha ha ha — just kidding!`.

### Vulnerable path (with PIE → **include an info-leak**)

* Add a **single, deliberate info leak** to keep the challenge solvable under PIE, e.g.:
  ROP stage 1 chain: `pop rdi; ret` → `&puts@got` → `puts@plt` → `main`
  so players can compute libc base (or also leak a code pointer to compute PIE base).
* Protections: **Stack canary ON**, **NX ON**, **PIE ON**, **Partial RELRO**, **Stripped**.
* Minimize gadgets (small I/O wrappers, dead-code elimination).

---

## Makefile (PIE **ON**)

```make
CC := gcc
CFLAGS_COMMON := -std=c11 -O2 -fstack-protector-strong -ffunction-sections -fdata-sections -Wall -Wextra -fPIE
LDFLAGS_COMMON := -Wl,--gc-sections -Wl,-z,relro -pie
STRIP := strip -s

# Static keys (build-time)
K1_HEX := abcbcdef02abcbcdef05abcbcdef01abcbcdef06abcbcdef03abcbcdef04abcb
K2_HEX := 4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760
IV0_HEX := 00000000000000000000000000000000
TARGET_DICE := 54321   # 5,4,3,2,1 descending
```

**Obfuscated K2 generator (per-byte inverse):**

```make
tools/gen_obf_k2: tools/gen_obf_k2.c
	$(CC) -O2 -o $@ $<

obf_k2.h: tools/gen_obf_k2
	@./tools/gen_obf_k2 $(K2_HEX) $(TARGET_DICE) > $@
```

**Ciphertext pipeline (unchanged):**

```make
vulnerable.b64: vulnerable
	@base64 $< > $@

ciphertext.bin: vulnerable.b64
	@openssl enc -aes-256-cbc -K $(K1_HEX) -iv $(IV0_HEX) -nosalt -in $< -out $@.stage1
	@openssl enc -aes-256-cbc -K $(K2_HEX) -iv $(IV0_HEX) -nosalt -in $@.stage1 -out $@
	@rm -f $@.stage1

ciphertext.c: ciphertext.bin
	@xxd -i $< > $@
	@sed -i.bak '1s/.*/#include <stddef.h>\nconst unsigned char ciphertext[] = {/' $@ && rm -f $@.bak
	@echo 'const size_t ciphertext_len = sizeof(ciphertext);' >> $@
```

**Build binaries (PIE on):**

```make
vulnerable: vulnerable.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $^
	$(STRIP) $@

challenge: challenge.c ciphertext.c b64.c aes_wrap.c obf_k2.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ challenge.c b64.c aes_wrap.c ciphertext.c -lcrypto -DSTATIC_K2_HEX=\"$(K2_HEX)\"
	$(STRIP) $@

all: vulnerable ciphertext.c obf_k2.h challenge

clean:
	rm -f challenge vulnerable vulnerable.b64 ciphertext.bin ciphertext.c obf_k2.h tools/gen_obf_k2
```

**`tools/gen_obf_k2.c` (per-byte inverse)**

```c
// gcc -O2 -o tools/gen_obf_k2 tools/gen_obf_k2.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int hex32(const char *h, uint8_t out[32]) {
    if (!h || strlen(h)!=64) return 0;
    for (int i=0;i<32;i++){ unsigned x; if (sscanf(h+2*i,"%02x",&x)!=1) return 0; out[i]=(uint8_t)x; }
    return 1;
}
static int parse_dice5(const char *s, uint8_t d[5]) {
    if (!s || strlen(s)!=5) return 0;
    for (int i=0;i<5;i++){ if (s[i]<'1'||s[i]>'6') return 0; d[i]=(uint8_t)(s[i]-'0'); }
    return 1;
}
int main(int argc, char**argv){
    if (argc!=3){ fprintf(stderr,"usage: %s <K2_HEX> <dice(5 digits)>\n", argv[0]); return 1; }
    uint8_t K2[32], d[5]; if(!hex32(argv[1],K2)||!parse_dice5(argv[2],d)){ fprintf(stderr,"bad args\n"); return 1; }
    uint8_t OBF[32];
    for (int i=0;i<32;i++){
        uint8_t k = K2[i];
        k = (uint8_t)((k - d[4]) & 0xFF); // inverse of +d5
        k = (uint8_t)(k ^ d[3]);          // inverse of ^d4
        k = (uint8_t)((k + d[2]) & 0xFF); // inverse of -d3
        k = (uint8_t)(k ^ d[1]);          // inverse of ^d2
        k = (uint8_t)((k - d[0]) & 0xFF); // inverse of +d1
        OBF[i] = k;
    }
    printf("#pragma once\nstatic const unsigned char OBF_K2[32]={");
    for(int i=0;i<32;i++) printf("0x%02x%s", OBF[i], i==31? "": ",");
    printf("};\n");
    return 0;
}
```

---

## Key code snippets (menu side)

**De-obfuscate K2 from dice:**

```c
#include "obf_k2.h"
static void unveil_k2_from_dice(const uint8_t d[5], uint8_t k2[32]) {
    for (int i=0;i<32;i++) {
        uint8_t k = OBF_K2[i];
        k = (uint8_t)((k + d[0]) & 0xFF);
        k = (uint8_t)(k ^ d[1]);
        k = (uint8_t)((k - d[2]) & 0xFF);
        k = (uint8_t)(k ^ d[3]);
        k = (uint8_t)((k + d[4]) & 0xFF);
        k2[i] = k;
    }
}
```

**K2 verifier (8 hex chars) + optional match banner:**

```c
#include <openssl/sha.h>
static void k2_verifier(const uint8_t k2[32], char out8[9]) {
    uint8_t dig[32]; const char *tag="yahtzee-tag";
    SHA256_CTX c; SHA256_Init(&c);
    SHA256_Update(&c, k2, 32);
    SHA256_Update(&c, tag, 11);
    SHA256_Final(dig, &c);
    static const char *H="0123456789abcdef";
    for (int i=0;i<4;i++){ out8[2*i]=H[dig[i]>>4]; out8[2*i+1]=H[dig[i]&0xF]; }
    out8[8]='\0';
}
```

---

## README notes

* **PIE is ON**, so exploitation requires a **leak**: include a simple `puts@plt(puts@got)` leak in stage 1 and loop back to `main`, then stage 2 uses the bases to build the final chain.
* Option 1 sorts dice; Option 2 uses exact order; to recover the build key via Cheat, input `5 4 3 2 1`.
* K1 displays a visible AB/CB/CD/EF + digit pattern.
* The “rm -rf” prank is **print-only**.

---

## Acceptance checklist

* `make all` builds `challenge`, `vulnerable`, and generates `ciphertext.c` + `obf_k2.h`.
* `checksec challenge vulnerable` → Canary ✓, NX ✓, **PIE ✓**, RELRO **Partial**.
* `./challenge` → Cheat with `5 4 3 2 1` recovers correct K2 and decrypts `vulnerable`.
* `vulnerable` prints prank and includes a **single info leak** pathway to support PIE exploitation.
* Gadget scan shows intentionally limited set; exploitation is leak→chain as intended.

---

**End of specification.**
