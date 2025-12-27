# absolute path
SCRIPTS_DIR := $(shell pwd)
TOP_DIR := $(shell cd ../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
BUSYBOX_DIR := $(TOP_DIR)/busybox-1.36.0
ROOT_DIR := $(TOP_DIR)/root
APPLICATIONS_DIR := $(CODE_DIR)/user/applications
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR KERNEL_DIR UBOOT_DIR ROOT_DIR CROSS_COMPILER_PREFIX

.PHONY: all prepare config uboot kernel busybox boot version \
	uboot_clean kernel_clean busybox_clean clean

all: prepare config uboot kernel busybox

prepare:
	./mkprepare.sh
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
	rm -f $(UBOOT_DIR)/cusuboot

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) kernel_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j16
	$(KERNEL_DIR)/scripts/dtc/dtc -I dts -O dtb $(CODE_DIR)/virt.dts \
		-o $(TOP_DIR)/virt.dtb

kernel_clean:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(KERNEL_DIR)/cuskernel

busybox:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) defconfig
	sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' $(BUSYBOX_DIR)/.config
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j8
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) \
		CONFIG_PREFIX=$(ROOT_DIR) install

busybox_clean:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

version:
	$(UBOOT_DIR)/tools/mkimage -f $(SCRIPTS_DIR)/kernel.its $(TOP_DIR)/kernel.itb
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 $(ROOT_DIR)/lib/ -f
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib64/libc.so.6 $(ROOT_DIR)/lib64/ -f
	find $(CODE_DIR)/linux/ -name *.ko -exec cp -f {} $(ROOT_DIR)/modules \;
	./mkver.sh

boot:
	qemu-system-aarch64 \
    	-M virt,gic-version=3 \
    	-cpu cortex-a53 \
    	-smp 2 -m 128M \
		-monitor telnet:127.0.0.1:9999,server,nowait \
    	-device loader,file=$(UBOOT_DIR)/u-boot.bin \
		-device nec-usb-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR) \
		-device virtio-net-device,netdev=net0 \
		-device edu,dma_mask=32 \
    	-nographic -no-reboot

clean:
	make uboot_clean
	make kernel_clean
	make busybox_clean
	make -C $(CODE_DIR)/user/buildversion clean
	make -C $(APPLICATIONS_DIR) clean
	rm -rf $(ROOT_DIR)/*
