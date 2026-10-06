################################################################################
# Makefile for Examples
# HALA Academy - AUTOSAR Crypto Stack Examples
#
# Build all:    make
# Build one:    make example_01
# Clean:        make clean
# Run all:      make run_all
################################################################################

#===============================================================================
# COMPILER SETTINGS
#===============================================================================
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

# Đường dẫn relative từ examples/
PROJECT_ROOT = ..
SRC_DIR = $(PROJECT_ROOT)/src
INC_DIR = $(PROJECT_ROOT)/include
UECC_DIR = $(PROJECT_ROOT)/lib/micro-ecc

#===============================================================================
# INCLUDE PATHS
#===============================================================================
INCLUDES = -I$(INC_DIR) -I$(UECC_DIR)

#===============================================================================
# SOURCE FILES
#===============================================================================
# Common sources
SHA256_SRC = $(SRC_DIR)/Crypto_SHA256.c
ECDSA_SRC = $(SRC_DIR)/Crypto_ECDSA.c
UECC_SRC = $(UECC_DIR)/uECC.c

# Hash-only examples
HASH_DEPS = $(SHA256_SRC)

# ECDSA examples (need hash + ecdsa + uecc)
ECDSA_DEPS = $(SHA256_SRC) $(ECDSA_SRC) $(UECC_SRC)

#===============================================================================
# TARGETS
#===============================================================================
EXAMPLES = example_01 example_02 example_03 example_04 example_05

.PHONY: all clean run_all help

# Build all examples
all: $(EXAMPLES)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║              TẤT CẢ EXAMPLES ĐÃ BUILD!                       ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Chạy từng example:"
	@echo "  ./example_01    # SHA-256 Basic"
	@echo "  ./example_02    # SHA-256 Streaming"
	@echo "  ./example_03    # ECDSA Key Generation"
	@echo "  ./example_04    # ECDSA Sign & Verify"
	@echo "  ./example_05    # Secure Boot Simulation"
	@echo ""
	@echo "Hoặc: make run_all"
	@echo ""

#===============================================================================
# INDIVIDUAL EXAMPLES
#===============================================================================

# Example 1: SHA-256 Basic (chỉ cần SHA256)
example_01: example_01_sha256_basic.c $(HASH_DEPS)
	@echo "Building example_01_sha256_basic..."
	$(CC) $(CFLAGS) $(INCLUDES) $< $(HASH_DEPS) -o $@
	@echo "✓ example_01 built"

# Example 2: SHA-256 Streaming (chỉ cần SHA256)
example_02: example_02_sha256_streaming.c $(HASH_DEPS)
	@echo "Building example_02_sha256_streaming..."
	$(CC) $(CFLAGS) $(INCLUDES) $< $(HASH_DEPS) -o $@
	@echo "✓ example_02 built"

# Example 3: ECDSA Key Generation (cần SHA256 + ECDSA + uECC)
example_03: example_03_ecdsa_keygen.c $(ECDSA_DEPS)
	@echo "Building example_03_ecdsa_keygen..."
	$(CC) $(CFLAGS) $(INCLUDES) $< $(ECDSA_DEPS) -o $@
	@echo "✓ example_03 built"

# Example 4: ECDSA Sign & Verify (cần SHA256 + ECDSA + uECC)
example_04: example_04_ecdsa_sign_verify.c $(ECDSA_DEPS)
	@echo "Building example_04_ecdsa_sign_verify..."
	$(CC) $(CFLAGS) $(INCLUDES) $< $(ECDSA_DEPS) -o $@
	@echo "✓ example_04 built"

# Example 5: Secure Boot Simulation (cần SHA256 + ECDSA + uECC)
example_05: example_05_secure_boot.c $(ECDSA_DEPS)
	@echo "Building example_05_secure_boot..."
	$(CC) $(CFLAGS) $(INCLUDES) $< $(ECDSA_DEPS) -o $@
	@echo "✓ example_05 built"

#===============================================================================
# RUN ALL EXAMPLES
#===============================================================================
run_all: $(EXAMPLES)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "                    RUNNING ALL EXAMPLES"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running Example 1: SHA-256 Basic"
	@echo "════════════════════════════════════════════════════════════════"
	./example_01
	@echo ""
	@echo ">>> Running Example 2: SHA-256 Streaming"
	@echo "════════════════════════════════════════════════════════════════"
	./example_02
	@echo ""
	@echo ">>> Running Example 3: ECDSA Key Generation"
	@echo "════════════════════════════════════════════════════════════════"
	./example_03
	@echo ""
	@echo ">>> Running Example 4: ECDSA Sign & Verify"
	@echo "════════════════════════════════════════════════════════════════"
	./example_04
	@echo ""
	@echo ">>> Running Example 5: Secure Boot Simulation"
	@echo "════════════════════════════════════════════════════════════════"
	./example_05

#===============================================================================
# CLEAN
#===============================================================================
clean:
	rm -f $(EXAMPLES)
	@echo "Đã xóa các file executable"

#===============================================================================
# HELP
#===============================================================================
help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║         HALA ACADEMY - CRYPTO EXAMPLES                       ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Danh sách Examples:"
	@echo "───────────────────"
	@echo "  example_01  SHA-256 Basic (hash string, binary, FIPS vectors)"
	@echo "  example_02  SHA-256 Streaming (firmware verification mô phỏng)"
	@echo "  example_03  ECDSA Key Generation (tạo/export/import keys)"
	@echo "  example_04  ECDSA Sign & Verify (quy trình ký và xác thực)"
	@echo "  example_05  Secure Boot Simulation (OEM→ECU full flow)"
	@echo ""
	@echo "Commands:"
	@echo "─────────"
	@echo "  make              Build tất cả examples"
	@echo "  make example_01   Build example cụ thể"
	@echo "  make run_all      Chạy tất cả examples"
	@echo "  make clean        Xóa executables"
	@echo "  make help         Hiển thị help này"
	@echo ""
