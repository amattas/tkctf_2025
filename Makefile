CC := gcc
CFLAGS_COMMON := -std=c11 -O2 -fstack-protector-strong -ffunction-sections -fdata-sections -Wall -Wextra -fPIE
LDFLAGS_COMMON := -Wl,--gc-sections -Wl,-z,relro -Wl,-z,lazy -pie
STRIP := strip -s

# Static keys (build-time)
K1_HEX := abcbcdef02abcbcdef05abcbcdef01abcbcdef06abcbcdef03abcbcdef04abcb
K2_HEX := 4d387f7065e6224dc3c739bc0dfcb7caaab7bb49fd77ad52ff247b27356b2760
IV0_HEX := 00000000000000000000000000000000
TARGET_DICE := 54321

.PHONY: all clean

all: challenge

# Build obfuscation generator
tools/gen_obf_k2: tools/gen_obf_k2.c
	$(CC) -O2 -o $@ $<

# Generate obfuscated K2 header
obf_k2.h: tools/gen_obf_k2
	./tools/gen_obf_k2 $(K2_HEX) $(TARGET_DICE) > $@

# Build vulnerable binary (stripped)
vulnerable: final_prank.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $^
	$(STRIP) $@

# Base64 encode vulnerable
vulnerable.b64: vulnerable
	base64 $< > $@

# Double-encrypt: K1 then K2
ciphertext.bin: vulnerable.b64
	openssl enc -aes-256-cbc -K $(K1_HEX) -iv $(IV0_HEX) -nosalt -in $< -out $@.stage1
	openssl enc -aes-256-cbc -K $(K2_HEX) -iv $(IV0_HEX) -nosalt -in $@.stage1 -out $@
	rm -f $@.stage1

# Convert ciphertext to C array
ciphertext.c: ciphertext.bin
	echo '#include <stddef.h>' > $@
	echo 'const unsigned char ciphertext[] = {' >> $@
	python3 tools/bin2c.py < $< | sed 's/^/  /' >> $@
	echo '' >> $@
	echo '};' >> $@
	echo 'const size_t ciphertext_len = sizeof(ciphertext);' >> $@

# Build challenge (with all dependencies)
challenge: menu.c ciphertext.c b64.c aes_wrap.c obf_k2.h
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ menu.c ciphertext.c b64.c aes_wrap.c -lcrypto -DSTATIC_K2_HEX=\"$(K2_HEX)\"
	$(STRIP) $@
	@echo "Cleaning up intermediate files..."
	@rm -f vulnerable vulnerable.b64 ciphertext.bin ciphertext.c obf_k2.h

clean:
	rm -f challenge vulnerable vulnerable.b64 ciphertext.bin ciphertext.c obf_k2.h tools/gen_obf_k2
