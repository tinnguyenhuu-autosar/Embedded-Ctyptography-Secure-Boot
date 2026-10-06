# Makefile – AUTOSAR Crypto Stack Demo (STM32F103)
# Build: make
# Clean: make clean

# Default target
all:

CC      = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size

# STM32F103C8 (Medium-density, Cortex-M3)
CFLAGS  = -mcpu=cortex-m3 -mthumb -O2 -g3 -Wall -Wextra
CFLAGS += -ffreestanding -ffunction-sections -fdata-sections
CFLAGS += -DSTM32F10X_MD -DUSE_STDPERIPH_DRIVER -DRUN_ON_RENODE
LDFLAGS = -T stm32f103.ld --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections

# ===== Include paths (per-module, giống COM) =====
INC  = -Iautosar/include
INC += -Iautosar/csm
INC += -Iautosar/cryif
INC += -Iautosar/crypto
INC += -Iconfig
INC += -Ibsp
INC += -Ibsp/cmsis
INC += -Ilib/micro-ecc
INC += -Ispl/inc

# ===== Source files =====
# AUTOSAR Crypto Stack
SRCS  = autosar/csm/Csm.c
SRCS += autosar/cryif/CryIf.c
SRCS += autosar/crypto/Crypto_SHA256.c
SRCS += autosar/crypto/Crypto_ECDSA.c

# Config
SRCS += config/Csm_Cfg.c

# Library
SRCS += lib/micro-ecc/uECC.c

# BSP
SRCS += bsp/uart_log.c

# SPL (chỉ compile module cần thiết)
SRCS += spl/src/stm32f10x_rcc.c
SRCS += spl/src/stm32f10x_gpio.c
SRCS += spl/src/stm32f10x_usart.c
SRCS += spl/src/misc.c
SRCS += spl/src/system_stm32f10x.c

# Startup
ASM_SRCS = startup_stm32f103.s

# ===== Auto-scan app/ =====
BUILD_DIR = build
APP_SRCS = $(wildcard app/*_ecu.c)

# Template tự động build cho mọi ứng dụng trong thư mục example
define MAKE_APP_TEMPLATE
APP_BASENAME_$(1) = $$(basename $$(notdir $(1)))
APP_TARGET_$(1) = $$(BUILD_DIR)/app/$$(APP_BASENAME_$(1))

OBJS_$(1) = $$(patsubst %.c,$$(BUILD_DIR)/$$(APP_BASENAME_$(1))/%.o,$(1)) \
             $$(patsubst %.c,$$(BUILD_DIR)/$$(APP_BASENAME_$(1))/%.o,$$(SRCS)) \
             $$(patsubst %.s,$$(BUILD_DIR)/$$(APP_BASENAME_$(1))/%.o,$$(ASM_SRCS))

$$(APP_TARGET_$(1)).elf: $$(OBJS_$(1))
	@mkdir -p $$(dir $$@)
	$$(CC) $$(CFLAGS) $$^ $$(LDFLAGS) -o $$@

$$(APP_TARGET_$(1)).bin: $$(APP_TARGET_$(1)).elf
	$$(OBJCOPY) -O binary $$< $$@

$$(APP_TARGET_$(1)).hex: $$(APP_TARGET_$(1)).elf
	$$(OBJCOPY) -O ihex $$< $$@

$$(BUILD_DIR)/$$(APP_BASENAME_$(1))/%.o: %.c
	@mkdir -p $$(dir $$@)
	$$(CC) $$(CFLAGS) $$(INC) -c $$< -o $$@

$$(BUILD_DIR)/$$(APP_BASENAME_$(1))/%.o: %.s
	@mkdir -p $$(dir $$@)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

ALL_TARGETS += $$(APP_TARGET_$(1)).elf $$(APP_TARGET_$(1)).bin $$(APP_TARGET_$(1)).hex
endef

$(foreach app,$(APP_SRCS),$(eval $(call MAKE_APP_TEMPLATE,$(app))))

.SECONDARY:

all: $(ALL_TARGETS)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║     BUILD THANH CONG (STM32F103 Cortex-M3)                  ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@$(foreach t,$(filter %.elf,$(ALL_TARGETS)), $(SIZE) $(t);)
	@echo ""
	@echo "Chay tren Renode:"
	@echo "  renode scripts/stm32_crypto.resc"
	@echo ""

# ===== Host build (native Mac/Linux) =====
host:
	@$(MAKE) -f Makefile.host

host-run:
	@$(MAKE) -f Makefile.host run

# ===== Clean =====
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean host host-run
