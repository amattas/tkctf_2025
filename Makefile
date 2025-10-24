CC := gcc
CFLAGS_COMMON := -std=c11 -O2 -fstack-protector-strong -ffunction-sections -fdata-sections -Wall -Wextra -fPIE
LDFLAGS_COMMON := -Wl,--gc-sections -Wl,-z,relro -Wl,-z,lazy -pie
STRIP := strip -s

# Static keys (build-time)
K1_HEX := abcbcdef02abcbcdef05abcbcdef01abcbcdef06abcbcdef03abcbcdef04abcb
K2_HEX := 4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760
IV0_HEX := 00000000000000000000000000000000
TARGET_DICE := 54321

.PHONY: all clean debug

all: challenge

# Debug builds (not stripped, with debug macros)
debug: challenge_debug vulnerable_debug
	@echo ""
	@echo "=== Debug builds complete ==="
	@echo "challenge_debug: includes verbose logging"
	@echo "vulnerable_debug: TEST_FLAG_REVEAL=1 to call reveal_flag()"
	@echo ""

# Build obfuscation generator
tools/gen_obf_k2: tools/gen_obf_k2.c
	$(CC) -O2 -o $@ $<

# Generate obfuscated K2 header
obf_k2.h: tools/gen_obf_k2
	./tools/gen_obf_k2 $(K2_HEX) $(TARGET_DICE) > $@

# Build flag constants generator
tools/gen_flag_consts: tools/gen_flag_consts.c
	$(CC) -O2 -o $@ $< -lcrypto

# Generate flag constants
FLAG ?= flag{s!x-s3v3n}
flag_consts.h: tools/gen_flag_consts
	@echo "Generating flag constants (this will take 1-2 minutes)..."
	./tools/gen_flag_consts "$(FLAG)" $@

# Build vulnerable binary (stripped, with flag reveal)
vulnerable: vulnerable.c flag_consts.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -DFLAG_REVEAL_ENABLED -o $@ $< -lcrypto
	$(STRIP) $@

# Base64 encode vulnerable
vulnerable.b64: vulnerable
	base64 $< > $@

# Double-encrypt: K1 then K2
ciphertext.bin: vulnerable.b64
	openssl enc -aes-256-cbc -K $(K1_HEX) -iv $(IV0_HEX) -nosalt -in $< -out $@.stage1
	openssl enc -aes-256-cbc -K $(K2_HEX) -iv $(IV0_HEX) -nosalt -in $@.stage1 -out $@
	rm -f $@.stage1

# Convert ciphertext to C array (in custom .uh_oh section)
ciphertext.c: ciphertext.bin
	echo '#include <stddef.h>' > $@
	echo '__attribute__((section(".uh_oh")))' >> $@
	echo 'const unsigned char ciphertext[] = {' >> $@
	python3 tools/bin2c.py < $< | sed 's/^/  /' >> $@
	echo '' >> $@
	echo '};' >> $@
	echo 'const size_t ciphertext_len = sizeof(ciphertext);' >> $@

# Build challenge (with all dependencies)
challenge: challenge.c ciphertext.c b64.c aes_wrap.c obf_k2.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ challenge.c ciphertext.c b64.c aes_wrap.c -lcrypto -DSTATIC_K2_HEX=\"$(K2_HEX)\"
	$(STRIP) $@
	@echo "Cleaning up intermediate files..."
	@rm -f vulnerable vulnerable.b64 ciphertext.bin ciphertext.c obf_k2.h flag_consts.h vulnerable.o

# Debug vulnerable (with symbols, debug hooks)
vulnerable_debug: vulnerable.c flag_consts.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -DFLAG_REVEAL_ENABLED -DCTF_DEBUG -g -o $@ $< -lcrypto

# Debug challenge (with symbols, verbose output)
ciphertext_debug.c: ciphertext.bin
	@echo '#include <stddef.h>' > $@
	@echo '__attribute__((section(".uh_oh")))' >> $@
	@echo 'const unsigned char ciphertext[] = {' >> $@
	@python3 tools/bin2c.py < $< | sed 's/^/  /' >> $@
	@echo '' >> $@
	@echo '};' >> $@
	@echo 'const size_t ciphertext_len = sizeof(ciphertext);' >> $@

challenge_debug: challenge.c ciphertext_debug.c b64.c aes_wrap.c obf_k2.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -DCTF_DEBUG -g -o $@ challenge.c ciphertext_debug.c b64.c aes_wrap.c -lcrypto -DSTATIC_K2_HEX=\"$(K2_HEX)\"

clean:
	rm -f challenge vulnerable vulnerable.b64 ciphertext.bin ciphertext.c ciphertext_debug.c obf_k2.h flag_consts.h tools/gen_obf_k2 tools/gen_flag_consts
	rm -f challenge_debug vulnerable_debug
	rm -f vulnerable.o
