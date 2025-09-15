# absolute path
SCRIPTS_DIR := $(shell pwd)
TOP_DIR := $(shell cd ../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
QEMU_DIR := $(TOP_DIR)/qemu-9.2.3
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
BUSYBOX_DIR := $(TOP_DIR)/busybox-1.36.0
ROOT_DIR := $(TOP_DIR)/root
APPLICATIONS_DIR := $(CODE_DIR)/user/applications
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR QEMU_DIR KERNEL_DIR ROOT_DIR CROSS_COMPILER_PREFIX

.PHONY: all prepare config uboot kernel qemu busybox boot version \
	uboot_clean kernel_clean qemu_clean busybox_clean clean

all: prepare config uboot kernel qemu busybox

prepare:
	ln -sf $(CODE_DIR)/linux $(KERNEL_DIR)/cuskernel
	ln -sf $(CODE_DIR)/uboot $(UBOOT_DIR)/cusuboot
	cp -rf $(SCRIPTS_DIR)/baserootfs/* $(ROOT_DIR)
	make -C $(CODE_DIR)/user/buildversion

config:
	rm -f $(KERNEL_DIR)/arch/arm64/configs/kernel_defconfig
	cp $(CODE_DIR)/kernel_defconfig $(KERNEL_DIR)/arch/arm64/configs/
	rm -f $(UBOOT_DIR)/configs/uboot_defconfig
	cp $(CODE_DIR)/uboot_defconfig $(UBOOT_DIR)/configs/

uboot:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) uboot_defconfig
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j16

uboot_clean:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) kernel_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j16

kernel_clean:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

busybox:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) defconfig
	sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' $(BUSYBOX_DIR)/.config
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j8
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) \
		CONFIG_PREFIX=$(ROOT_DIR) install

busybox_clean:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

version:
	make -C $(APPLICATIONS_DIR)
	make -C $(APPLICATIONS_DIR) install
	./mkver.sh

boot:
	qemu-system-aarch64 \
    	-M virt,gic-version=3 \
    	-cpu cortex-a53 \
    	-smp 2 -m 512M \
    	-kernel $(UBOOT_DIR)/u-boot \
		-device nec-usb-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-device edu -device usb-mouse \
    	-nographic -no-reboot

clean:
	make uboot_clean
	make kernel_clean
	make busybox_clean
	make -C $(CODE_DIR)/user/buildversion clean
	make -C $(APPLICATIONS_DIR) clean
	rm -f $(KERNEL_DIR)/cuskernel
	rm -f $(UBOOT_DIR)/cusuboot
	rm -rf $(ROOT_DIR)/*
