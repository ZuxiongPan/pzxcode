# absolute path
TOP_DIR := $(shell cd ../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
QEMU_DIR := $(TOP_DIR)/qemu-10.2.4
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
BUSYBOX_DIR := $(TOP_DIR)/busybox-1.36.0
ROOT_DIR := $(TOP_DIR)/root
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR UBOOT_DIR QEMU_DIR ROOT_DIR CROSS_COMPILER_PREFIX
export PZX_BOARD=y

.PHONY: all prepare uboot uboot_clean clean kernel_clean \
	busybox busybox_clean image boot user user_clean

all: prepare uboot kernel busybox user

prepare:
	sed -i 's/^#define BOOT_METHOD_CUSTOM .*/#define BOOT_METHOD_CUSTOM 0/' $(CODE_DIR)/include/boot/boot_method.h
	[ -L $(UBOOT_DIR)/cusuboot ] || ln -sf $(CODE_DIR)/uboot $(UBOOT_DIR)/cusuboot
	[ -L $(KERNEL_DIR)/cuskernel ] || ln -sf $(CODE_DIR)/linux $(KERNEL_DIR)/cuskernel
	cp $(CODE_DIR)/pzx_board/linux/pzx_arm64_defconfig $(KERNEL_DIR)/arch/arm64/configs/ -f
	cp $(CODE_DIR)/pzx_board/linux/pzx-arm64.dts $(KERNEL_DIR)/arch/arm64/boot/dts/arm/ -f
	cp $(CODE_DIR)/pzx_board/uboot/arm64_pzx $(UBOOT_DIR)/board/ -rf
	cp $(CODE_DIR)/pzx_board/uboot/arm64_pzx.h $(UBOOT_DIR)/include/configs/ -f
	cp $(CODE_DIR)/pzx_board/uboot/arm64-pzx.dts $(UBOOT_DIR)/arch/arm/dts/ -f
	cp $(CODE_DIR)/pzx_board/uboot/arm64_pzx_defconfig $(UBOOT_DIR)/configs/ -f
	mkdir -p $(ROOT_DIR)/proc $(ROOT_DIR)/sys $(ROOT_DIR)/dev $(ROOT_DIR)/mnt 
	mkdir -p $(ROOT_DIR)/lib64 $(ROOT_DIR)/lib $(ROOT_DIR)/modules $(ROOT_DIR)/var
	cp $(CODE_DIR)/pzx_board/baserootfs/* $(ROOT_DIR)/ -rf

uboot:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) arm64_pzx_defconfig
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j4
	make -C ./loader all
	dd if=/dev/zero of=$(TOP_DIR)/zero.bin bs=1M count=4
	cat ./loader/loader.img $(TOP_DIR)/zero.bin > $(TOP_DIR)/loadertmp.bin
	dd if=$(TOP_DIR)/loadertmp.bin of=$(TOP_DIR)/loader.bin bs=1M count=1
	cat $(TOP_DIR)/loader.bin $(UBOOT_DIR)/u-boot.bin $(TOP_DIR)/zero.bin > $(TOP_DIR)/boottmp.bin
	dd if=$(TOP_DIR)/boottmp.bin of=$(TOP_DIR)/boot.bin bs=1M count=4
	rm -f $(TOP_DIR)/loader.bin $(TOP_DIR)/zero.bin $(TOP_DIR)/loadertmp.bin $(TOP_DIR)/boottmp.bin
	make -C ./loader clean

uboot_clean:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(UBOOT_DIR)/cusuboot

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) pzx_arm64_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j8
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) modules

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
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 $(ROOT_DIR)/lib/ -f
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib64/libc.so.6 $(ROOT_DIR)/lib64/ -f

user_clean:
	make -C $(CODE_DIR)/user/lib clean
	make -C $(CODE_DIR)/user/applications clean

image:
	$(UBOOT_DIR)/tools/mkimage -f $(CODE_DIR)/pzx_board/linux/pzx.its $(TOP_DIR)/pzx.itb

boot:
	$(QEMU_DIR)/build/qemu-system-aarch64 -M pzx -smp 1 \
		-monitor telnet:127.0.0.1:9999,server,nowait \
    	-drive file=$(TOP_DIR)/boot.bin,if=sd,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR) \
		-device virtio-net-device,netdev=net0 \
		-nographic -no-reboot

boot_debug:
	$(QEMU_DIR)/build/qemu-system-aarch64 -M pzx -smp 1 \
		-monitor telnet:127.0.0.1:9999,server,nowait \
    	-drive file=$(TOP_DIR)/boot.bin,if=sd,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR) \
		-device virtio-net-device,netdev=net0 \
		-nographic -no-reboot -S -s

clean:
	make uboot_clean
	make kernel_clean
	make busybox_clean
	make user_clean
	rm -rf $(ROOT_DIR)/*
