# wxshadow_client - W^X Shadow Memory 无痕hook 用户态客户端
#
# 用法（Android 上运行，需要 root）：
#   adb push wxshadow_client /data/local/tmp/
#   adb shell chmod +x /data/local/tmp/wxshadow_client
#   adb shell /data/local/tmp/wxshadow_client -p <pid> -a <addr>
#
# 交叉编译（与 lsdriver 相同工具链）：
#   make CROSS=aarch64-linux-gnu-
# 或直接使用 Android NDK：
#   make CROSS=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-

CROSS ?= aarch64-linux-gnu-
CC := $(CROSS)gcc
CFLAGS := -O2 -static -Wall -Wextra
TARGET := wxshadow_client

all: $(TARGET)

$(TARGET): wxshadow_client.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
