# absolute path
SCRIPTS_DIR := $(shell pwd)
TOP_DIR := $(shell cd ../../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
BUSYBOX_DIR := $(TOP_DIR)/busybox-1.36.0
QEMU_DIR := $(TOP_DIR)/qemu-10.2.4
ROOT_DIR := $(TOP_DIR)/root
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR KERNEL_DIR UBOOT_DIR QEMU_DIR ROOT_DIR CROSS_COMPILER_PREFIX

.PHONY: all prepare config uboot kernel busybox user version \
	uboot_clean kernel_clean busybox_clean user_clean clean \
	boot qemu

all: prepare config uboot kernel busybox user version

prepare:
	./mkprepare.sh
	make -C $(CODE_DIR)/host/buildversion

config:
	rm -f $(KERNEL_DIR)/arch/arm64/configs/kernel_defconfig
	cp $(CODE_DIR)/qemu-virt/kernel_defconfig $(KERNEL_DIR)/arch/arm64/configs/
	rm -f $(UBOOT_DIR)/configs/uboot_defconfig
	cp $(CODE_DIR)/qemu-virt/uboot_defconfig $(UBOOT_DIR)/configs/
	rm -f $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dts
	cp $(CODE_DIR)/qemu-virt/virt-uboot.dts $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dts -f

uboot:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) uboot_defconfig
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j4

uboot_clean:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(UBOOT_DIR)/cusuboot

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) kernel_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j8
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) modules
	$(KERNEL_DIR)/scripts/dtc/dtc -I dts -O dtb $(CODE_DIR)/qemu-virt/virt.dts \
		-o $(TOP_DIR)/virt.dtb

kernel_clean:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(KERNEL_DIR)/cuskernel

busybox:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) defconfig
	sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' $(BUSYBOX_DIR)/.config
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j4
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) \
		CONFIG_PREFIX=$(ROOT_DIR) install

busybox_clean:
	make -C $(BUSYBOX_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

user:
	make -C $(CODE_DIR)/user/lib
	make -C $(CODE_DIR)/user/lib install
	make -C $(CODE_DIR)/user/applications
	make -C $(CODE_DIR)/user/applications install

user_clean:
	make -C $(CODE_DIR)/user/lib clean
	make -C $(CODE_DIR)/user/applications clean

qemu:
	./mkqemu.sh

version:
	$(UBOOT_DIR)/tools/mkimage -f $(SCRIPTS_DIR)/kernel.its $(TOP_DIR)/kernel.itb
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 $(ROOT_DIR)/lib/ -f
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib64/libc.so.6 $(ROOT_DIR)/lib64/ -f
	cp $(CODE_DIR)/rsakeys/pzx.pub $(ROOT_DIR)/etc -f
	find $(CODE_DIR)/linux/ -name *.ko -exec cp -f {} $(ROOT_DIR)/modules/ \;
	./mkver.sh

boot:
	$(QEMU_DIR)/build/qemu-system-aarch64 \
    	-M virt,gic-version=3 \
    	-cpu cortex-a53 \
    	-smp 2 -m 128M \
		-monitor telnet:127.0.0.1:9999,server,nowait \
		-dtb $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dtb \
		-kernel $(UBOOT_DIR)/u-boot \
		-device qemu-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR),hostfwd=tcp::8888-:8888 \
		-device virtio-net-pci,netdev=net0 \
    	-nographic -no-reboot

clean:
	make uboot_clean
	make kernel_clean
	make busybox_clean
	make user_clean
	make -C $(CODE_DIR)/host/buildversion clean
	rm -rf $(ROOT_DIR)/*
