# ClawTower Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2

PRELOAD_DIR = src/preload

.PHONY: all clean libclawtower libclawtower-v2 test-interpose cargo-test

all: libclawtower libclawtower-v2 test-interpose

# Original v1 library
libclawtower: $(PRELOAD_DIR)/interpose.c
	$(CC) -shared -fPIC $(CFLAGS) -o libclawtower_v1.so $< -ldl

# New v2 behavioral engine
libclawtower-v2: $(PRELOAD_DIR)/interpose_v2.c
	$(CC) -shared -fPIC $(CFLAGS) -o libclawtower.so $< -ldl -lpthread -lm

# Test program
test-interpose: $(PRELOAD_DIR)/test_interpose.c
	$(CC) $(CFLAGS) -o test_interpose $< -ldl

# Run tests
test: libclawtower-v2 test-interpose
	LD_PRELOAD=./libclawtower.so ./test_interpose

# Run Rust tests
cargo-test:
	export PATH="$$HOME/.cargo/bin:$$PATH" && cargo test

clean:
	rm -f libclawtower.so libclawtower_v1.so test_interpose
