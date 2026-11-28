# SPDX-License-Identifier: GPL-2.0
#
# obj-y 而不是 obj-m：这个目录被内核顶层 Kbuild 通过
#   linux-6.15.4/Kbuild: obj-y += cuskernel/
# 引用（cuskernel 是指向 pzxcode/linux 的符号链接），所以这里的 obj-y
# 会被链进 vmlinux，不需要 insmod。
obj-y += pzxfs.o
pzxfs-y := super.o inode.o namei.o file.o

clean-files := *.o *.a *.order .*.cmd *.ko *.mod *.mod.c *.mod.o
