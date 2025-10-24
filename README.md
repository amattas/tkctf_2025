# Play to Earn - Two-Binary CTF Challenge

A Linux CTF challenge featuring double AES-256-CBC encryption, Yahtzee-based key derivation, and a vulnerable binary with PIE/ASLR protections.

## Overview

This challenge consists of two binaries:

1. **menu** - The main interface with Yahtzee game, key generation, and decryption
2. **vulnerable** - A hidden binary (encrypted) that contains a prank and a vulnerable path for exploitation

## Build Instructions

```bash
make all
```

This will:
- Generate flag constants with trapdoor VDF (~1-2 minutes)
- Compile `vulnerable` with PIE, partial RELRO, stack canary, and NX
- Base64 encode the binary
- Double-encrypt it with K1 (weak pattern key) then K2 (Yahtzee-derived key)
- Generate `obf_k2.h` with obfuscated K2
- Compile `challenge` with all dependencies

### Debug Builds

For development and troubleshooting:

```bash
make debug
```

This creates **non-stripped** debug binaries with verbose logging:

- **`challenge_debug`**: Includes `[DEBUG]` output showing:
  - Dice values and hash comparisons
  - Key values (first 16 hex)
  - Decryption stage sizes
  - Security bypass status

- **`vulnerable_debug`**: Includes test hook:
  ```bash
  TEST_FLAG_REVEAL=1 ./vulnerable_debug
  ```
  This directly calls `reveal_flag()` to verify the VDF-based flag decryption works.

**Note**: Debug builds are **NOT** included in `make all` and must be built separately. Production binaries never include debug code.

## Binary Protections

Both binaries are compiled with:
- **PIE**: ON (Position Independent Executable)
- **RELRO**: Partial (GOT is writable)
- **Stack Canary**: ON
- **NX**: ON (No Execute)
- **Stripped**: Yes

```bash
checksec menu vulnerable
```

## Crypto Pipeline

### Encryption (Build Time)

```
vulnerable → Base64 → AES-256-CBC(K1) → AES-256-CBC(K2) → ciphertext
```

### Decryption (Runtime)

```
ciphertext → Decrypt(K2) → Decrypt(K1) → Base64 decode → vulnerable
```

- **Algorithm**: AES-256-CBC
- **IV**: 16 bytes of zeros
- **Padding**: PKCS#7 (default)

## Keys

### K1 (Weak Pattern Key)

The menu can generate K1 via Option 3. It follows a visible pattern:
- `AB CB CD EF [1-6]` repeating
- Where the last byte of each 5-byte block is a random digit 1-6

Example: `abcbcdef02abcbcdef05abcbcdef01...`

### K2 (Yahtzee Target Key)

K2 is derived from dice values using per-byte obfuscation:
- **Target dice**: `[5, 4, 3, 2, 1]` (descending)
- **Static K2**: `4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760`

The menu stores an obfuscated version `OBF_K2`. To recover the real K2:

1. **Play mode (Option 1)**: Rolls 5 dice, sorts descending, derives K2
2. **Cheat mode (Option 2)**: Enter dice manually (no sorting) - use `5 4 3 2 1` to get correct K2

### K2 De-obfuscation Algorithm

For each byte `i`:
```c
k = OBF_K2[i]
k = (k + d[0]) & 0xFF   // +d1
k = k ^ d[1]             // ^d2
k = (k - d[2]) & 0xFF   // -d3
k = k ^ d[3]             // ^d4
k = (k + d[4]) & 0xFF   // +d5
K2[i] = k
```

Where `d[]` are the five dice values.

### K2 Verifier

The menu displays the first 8 hex characters of:
```
SHA256(K2 || "yahtzee-tag")
```

For the correct K2, the verifier is: **`4a7c8f2e`**

When K2 matches the target, you'll see:
```
[K2 MATCH] You hit the Yahtzee target key!
```

## Menu Options

```
1) Play game (Yahtzee)        - Roll dice, sorted descending, derive K2
2) Cheat (manual dice)        - Enter exact dice values (no sorting)
3) Generate a Key             - Generate weak K1
4) Decrypt final binary       - Decrypt and emit vulnerable binary
5) Exit
```

## Anti-Debug / Anti-VM

The menu includes protection checks (before K2 unlock or decrypt success):
- Ptrace detection
- TracerPid check (`/proc/self/status`)
- LD_PRELOAD/LD_AUDIT/LD_DEBUG detection
- VM heuristics (QEMU, KVM, VirtualBox, VMware in DMI)

### Environment Overrides

- `CTF_ALLOW_DEBUG=1` - Disable anti-debug checks
- `CTF_SHOW_REAL_K2=1` - Print real K2 hex instead of decoy

## Solution Path

### Step 1: Recover K2

Use cheat mode with target dice:
```bash
./menu
# Choose option 2 (Cheat)
# Enter: 5 4 3 2 1
# Note the K2 verifier matches 4a7c8f2e
```

Or extract from `obf_k2.h` and reverse the obfuscation.

### Step 2: Generate K1

```bash
# Choose option 3
# Note the generated K1 (or use the build-time K1)
```

### Step 3: Decrypt vulnerable

```bash
# Choose option 4
# Enter K1: (press Enter to use generated, or paste the build K1)
# Enter K2: 4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760
# The menu will decrypt the ciphertext and write ./vulnerable
```

### Step 4: Exploit vulnerable

Run `./vulnerable` to trigger the prank stage. The binary will:
1. Print a fake "rm -rf /" prank (harmless)
2. Offer a vulnerable path (press 'v')

In the vulnerable path:
- **Format String Vulnerability**: `printf(buf)` without format specifier - enables arbitrary memory reads
- **Buffer Overflow**: `read(0, buf, 512)` into 64-byte buffer
- **Protections**: Stack canary, NX, PIE, Partial RELRO

### Exploitation Strategy (PIE + ASLR)

Since PIE is enabled, you need to leak addresses. The format string vulnerability enables this:

**Stage 1: Info Leaks via Format String**
```bash
# Example format string payloads:
"%p.%p.%p.%p.%p.%p"           # Leak multiple stack values
"%11$p"                        # Leak specific stack offset (e.g., canary)
"%7$s"                         # Dereference pointer on stack
```

Use the format string to leak:
- **Stack canary** (typically at a fixed offset on stack)
- **PIE base** (code pointers on stack)
- **Libc base** (libc pointers like `__libc_start_main` on stack)

**Stage 2: Buffer Overflow ROP Chain**

After leaking addresses, send exploit payload:
```
[padding to overflow]
[leaked canary]               # Bypass stack canary
[saved RBP]
[ROP chain using leaked addresses]
```

**Example ROP chain (using leaked libc base):**
```
[pop rdi; ret gadget]
[address of "/bin/sh" in libc]
[system address in libc]
```

**Note:** The format string vulnerability makes this challenge more approachable than a pure ROP exploit, as you can leak all necessary addresses in a single interaction before sending your overflow payload.

## File Structure

```
.
├── README.md
├── CLAUDE.md                 # Full specification
├── Makefile
├── menu.c                    # Main menu binary
├── final_prank.c             # Vulnerable binary
├── b64.c / b64.h             # Base64 encode/decode
├── aes_wrap.c / aes_wrap.h   # AES-256-CBC wrapper
├── ciphertext.c              # Auto-generated encrypted data
├── obf_k2.h                  # Auto-generated obfuscated K2
└── tools/
    └── gen_obf_k2.c          # K2 obfuscation generator
```

## Testing

```bash
# Build
make all

# Run menu
./menu

# Test cheat mode
echo -e "2\n5 4 3 2 1\n5" | ./menu

# Verify protections
checksec menu vulnerable
```

## Clean Up

```bash
make clean
```

## Design Notes

### Format String vs Simple Info Leak

This challenge uses a **format string vulnerability** for the info leak stage, rather than a simpler `puts(GOT_entry)` approach. This design choice:

- **More realistic**: Format string bugs are common in real-world CTFs and security research
- **More flexible**: Players can leak multiple addresses in a single interaction
- **Educational**: Teaches format string exploitation alongside buffer overflow and ROP
- **Balanced difficulty**: Makes the PIE+ASLR+Canary challenge approachable while still requiring multiple exploitation techniques

The format string at `final_prank.c:111` (`printf(frame.buf)`) allows contestants to:
1. Leak the stack canary to bypass stack protection
2. Leak code pointers to defeat PIE/ASLR
3. Leak libc addresses to build ROP chains
4. All in one interaction before sending the overflow payload

This is intentionally more powerful than a single GOT leak, but requires understanding of format string offsets and memory layout.

## Notes

- The "rm -rf /" prank is **print-only** - no files are harmed
- Option 1 (Play) sorts dice, so hitting `[5,4,3,2,1]` by luck is ~1/7776
- Option 2 (Cheat) with `5 4 3 2 1` always recovers the target K2
- The vulnerable binary exploit requires leaking addresses due to PIE
- Format string vulnerability provides a powerful info leak mechanism
- Stack canary can be leaked via format string (no brute force needed)

## Author

Generated for CTF challenges. Educational purposes only.


## Make Targets Quick Reference

```bash
make all        # Build production binaries (challenge)
make debug      # Build debug binaries with verbose logging
make clean      # Remove all build artifacts
```

### Debug Features

**challenge_debug**:
- Shows dice/hash comparisons
- Prints key prefixes  
- Displays decryption stages
- Not stripped, includes symbols

**vulnerable_debug**:
- `TEST_FLAG_REVEAL=1` hook to call reveal_flag()
- Not stripped, includes symbols
- Useful for verifying VDF implementation

