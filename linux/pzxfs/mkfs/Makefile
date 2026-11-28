# SPDX-License-Identifier: GPL-2.0
#
# 用户态格式化工具，不参与内核构建（内核构建只认本目录下的 obj-y）。

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11

mkfs.pzxfs: mkfs.pzxfs.c ../pzxfs_ondisk.h
	$(CC) $(CFLAGS) -I.. -o $@ mkfs.pzxfs.c

clean:
	rm -f mkfs.pzxfs

.PHONY: clean
