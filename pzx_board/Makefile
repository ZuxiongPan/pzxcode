# absolute path
TOP_DIR := $(shell cd ../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
QEMU_DIR := $(TOP_DIR)/qemu-10.2.4
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR UBOOT_DIR QEMU_DIR CROSS_COMPILER_PREFIX

.PHONY: all prepare uboot uboot_clean clean boot image

all: prepare uboot image

prepare:
	sed -i 's/^#define BOOT_METHOD_CUSTOM .*/#define BOOT_METHOD_CUSTOM 0/' $(CODE_DIR)/include/boot/boot_method.h
	[ -L $(UBOOT_DIR)/cusuboot ] || ln -sf $(CODE_DIR)/uboot $(UBOOT_DIR)/cusuboot
	[ -L $(KERNEL_DIR)/cuskernel ] || ln -sf $(CODE_DIR)/linux $(KERNEL_DIR)/cuskernel

uboot:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) arm64_pzx_defconfig
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j4

uboot_clean:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(UBOOT_DIR)/cusuboot

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) pzx_arm64_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j8
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) modules
	$(UBOOT_DIR)/tools/mkimage -f $(CODE_DIR)/pzx_board/linux/pzx.its $(TOP_DIR)/pzx.itb

kernel_clean:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(KERNEL_DIR)/cuskernel

image:
	make -C ./loader all
	dd if=/dev/zero of=$(TOP_DIR)/zero.bin bs=1M count=4
	cat ./loader/loader.img $(TOP_DIR)/zero.bin > $(TOP_DIR)/loadertmp.bin
	dd if=$(TOP_DIR)/loadertmp.bin of=$(TOP_DIR)/loader.bin bs=1M count=1
	cat $(TOP_DIR)/loader.bin $(UBOOT_DIR)/u-boot.bin $(TOP_DIR)/zero.bin > $(TOP_DIR)/boottmp.bin
	dd if=$(TOP_DIR)/boottmp.bin of=$(TOP_DIR)/boot.bin bs=1M count=4
	rm -f $(TOP_DIR)/loader.bin $(TOP_DIR)/zero.bin $(TOP_DIR)/loadertmp.bin $(TOP_DIR)/boottmp.bin
	make -C ./loader clean

boot:
	$(QEMU_DIR)/build/qemu-system-aarch64 -M pzx \
		-monitor telnet:127.0.0.1:9999,server,nowait \
    	-drive file=$(TOP_DIR)/boot.bin,if=sd,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR) \
		-device virtio-net-device,netdev=net0 \
		-nographic -no-reboot

clean:
	make uboot_clean
	make kernel_clean
