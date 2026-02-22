# absolute path
SCRIPTS_DIR := $(shell pwd)
TOP_DIR := $(shell cd ../.. && pwd)
CODE_DIR := $(TOP_DIR)/pzxcode
UBOOT_DIR := $(TOP_DIR)/u-boot-2024.10
KERNEL_DIR := $(TOP_DIR)/linux-6.15.4
BUSYBOX_DIR := $(TOP_DIR)/busybox-1.36.0
OPTEE_DIR := $(TOP_DIR)/optee_os-4.8.0
TFA_DIR := $(TOP_DIR)/arm-trusted-firmware-2.13.0
ROOT_DIR := $(TOP_DIR)/root
CROSS_COMPILER_DIR := $(TOP_DIR)/aarch64-none-linux-gnu-14.3
CROSS_COMPILER_PREFIX := $(CROSS_COMPILER_DIR)/bin/aarch64-none-linux-gnu-

export TOP_DIR CODE_DIR KERNEL_DIR UBOOT_DIR ROOT_DIR CROSS_COMPILER_PREFIX

.PHONY: all prepare config uboot kernel busybox boot user version \
	uboot_clean kernel_clean busybox_clean user_clean clean

all: prepare config optee uboot kernel busybox user

prepare:
	./mkprepare.sh
	make -C $(CODE_DIR)/host/buildversion

config:
	rm -f $(KERNEL_DIR)/arch/arm64/configs/kernel_defconfig
	cp $(CODE_DIR)/kernel_defconfig $(KERNEL_DIR)/arch/arm64/configs/
	rm -f $(UBOOT_DIR)/configs/uboot_defconfig
	cp $(CODE_DIR)/uboot_defconfig $(UBOOT_DIR)/configs/
	rm -f $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dts
	cp $(CODE_DIR)/virt-uboot.dts $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dts -f

optee:
	cp $(CODE_DIR)/include/optee/platform_config.h $(OPTEE_DIR)/core/arch/arm/plat-vexpress/ -f
	make -C $(OPTEE_DIR) PLATFORM=vexpress PLATFORM_FLAVOR=qemu_armv8a CROSS_COMPILE64=$(CROSS_COMPILER_PREFIX) \
		CFG_ARM64_core=y CFG_ARM_GICV3=y CFG_TZDRAM_START=0x47000000 CFG_TZDRAM_SIZE=0xf00000 \
		CFG_USER_TA_TARGETS=ta_arm64 CFG_SHMEM_START=0x47f00000 CFG_SHMEM_SIZE=0x100000 DEBUG=1

optee_clean:
	make -C $(OPTEE_DIR) PLATFORM=vexpress PLATFORM_FLAVOR=qemu_armv8a clean
	rm -rf $(OPTEE_DIR)/out

tfa:
	cp $(CODE_DIR)/include/tfa/platform_def.h $(TFA_DIR)/plat/qemu/qemu/include/ -f
	make -C $(TFA_DIR) PLAT=qemu CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) BL33=$(UBOOT_DIR)/u-boot.bin \
		BL32=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-header_v2.bin \
		BL32_EXTRA1=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-pager_v2.bin \
		BL32_EXTRA2=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-pageable_v2.bin \
		BL32_BASE=0x47000000 SPD=opteed DEBUG=1 QEMU_USE_GIC_DRIVER=QEMU_GICV3 all fip
	cp $(TFA_DIR)/build/qemu/debug/bl1.bin $(TOP_DIR) -f
	cp $(TFA_DIR)/build/qemu/debug/fip.bin $(TOP_DIR) -f

tfa_clean:
	make -C $(TFA_DIR) PLAT=qemu CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

uboot:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) uboot_defconfig
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j16

uboot_clean:
	make -C $(UBOOT_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean
	rm -f $(UBOOT_DIR)/cusuboot

kernel:
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) kernel_defconfig
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) -j32
	make -C $(KERNEL_DIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) modules
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

user:
	make -C $(CODE_DIR)/user/lib
	make -C $(CODE_DIR)/user/lib install
	make -C $(CODE_DIR)/user/applications
	make -C $(CODE_DIR)/user/applications install

user_clean:
	make -C $(CODE_DIR)/user/lib clean
	make -C $(CODE_DIR)/user/applications clean

version:
	$(UBOOT_DIR)/tools/mkimage -f $(SCRIPTS_DIR)/kernel.its $(TOP_DIR)/kernel.itb
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 $(ROOT_DIR)/lib/ -f
	cp $(CROSS_COMPILER_DIR)/aarch64-none-linux-gnu/libc/lib64/libc.so.6 $(ROOT_DIR)/lib64/ -f
	cp $(CODE_DIR)/rsakeys/pzx.pub $(ROOT_DIR)/etc -f
	find $(CODE_DIR)/linux/ -name *.ko -exec cp -f {} $(ROOT_DIR)/modules \;
	./mkver.sh
	./combine_bl31_fip.sh

tfa_boot:
	qemu-system-aarch64 \
    	-M virt,gic-version=3,secure=on \
    	-cpu cortex-a53 \
    	-smp 2 -m 128M \
		-monitor telnet:127.0.0.1:9999,server,nowait \
		-dtb $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dtb \
		-drive if=pflash,format=raw,unit=0,file=$(TOP_DIR)/combined.bin,readonly=on \
		-device qemu-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR),hostfwd=tcp::2222-:23 \
		-device virtio-net-pci,netdev=net0 \
		-device edu,dma_mask=32 \
    	-nographic -no-reboot

boot:
	qemu-system-aarch64 \
    	-M virt,gic-version=3 \
    	-cpu cortex-a53 \
    	-smp 2 -m 128M \
		-monitor telnet:127.0.0.1:9999,server,nowait \
		-dtb $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dtb \
    	-device loader,file=$(UBOOT_DIR)/u-boot.bin \
		-device nec-usb-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR),hostfwd=tcp::2222-:23 \
		-device virtio-net-device,netdev=net0 \
		-device edu,dma_mask=32 \
    	-nographic -no-reboot

clean:
	make uboot_clean
	make kernel_clean
	make busybox_clean
	make user_clean
	make optee_clean
	make tfa_clean
	make -C $(CODE_DIR)/host/buildversion clean
	rm -rf $(ROOT_DIR)/*
