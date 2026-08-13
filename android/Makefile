# 用户态工具交叉编译（demo + wxshadow_client）
#
#   make CROSS=aarch64-linux-gnu-        # 默认
#   make CROSS=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-

CROSS ?= aarch64-linux-gnu-
CC := $(CROSS)gcc
CFLAGS := -O2 -static -Wall -Wextra

TARGETS := demo_punish_damage

all: $(TARGETS)
	$(MAKE) -C wxshadow_client

demo_punish_damage: demo_punish_damage.c lsdriver.h
	$(CC) $(CFLAGS) -o $@ demo_punish_damage.c

clean:
	rm -f $(TARGETS)
	$(MAKE) -C wxshadow_client clean

.PHONY: all clean
