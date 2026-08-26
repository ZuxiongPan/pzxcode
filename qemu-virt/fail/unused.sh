OPTEE_DIR := $(TOP_DIR)/optee_os-4.8.0
TFA_DIR := $(TOP_DIR)/arm-trusted-firmware-2.13.0

optee:
	cp $(CODE_DIR)/qemu-virt/optee/platform_config.h $(OPTEE_DIR)/core/arch/arm/plat-vexpress/ -f
	make -C $(OPTEE_DIR) PLATFORM=vexpress PLATFORM_FLAVOR=qemu_armv8a CROSS_COMPILE64=$(CROSS_COMPILER_PREFIX) \
		CFG_ARM64_core=y CFG_ARM_GICV3=y CFG_TZDRAM_START=0x47000000 CFG_TZDRAM_SIZE=0xf00000 \
		CFG_USER_TA_TARGETS=ta_arm64 CFG_SHMEM_START=0x47f00000 CFG_SHMEM_SIZE=0x100000 DEBUG=1 -j2

optee_clean:
	make -C $(OPTEE_DIR) PLATFORM=vexpress PLATFORM_FLAVOR=qemu_armv8a clean
	rm -rf $(OPTEE_DIR)/out

tfa:
	cp $(CODE_DIR)/qemu-virt/tfa/platform_def.h $(TFA_DIR)/plat/qemu/qemu/include/ -f
	make -C $(TFA_DIR) PLAT=qemu CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) BL33=$(UBOOT_DIR)/u-boot.bin \
		BL32=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-header_v2.bin \
		BL32_EXTRA1=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-pager_v2.bin \
		BL32_EXTRA2=$(OPTEE_DIR)/out/arm-plat-vexpress/core/tee-pageable_v2.bin \
		BL32_BASE=0x47000000 SPD=opteed DEBUG=1 QEMU_USE_GIC_DRIVER=QEMU_GICV3 all fip -j2
	cp $(TFA_DIR)/build/qemu/debug/bl1.bin $(TOP_DIR) -f
	cp $(TFA_DIR)/build/qemu/debug/fip.bin $(TOP_DIR) -f

tfa_clean:
	make -C $(TFA_DIR) PLAT=qemu CROSS_COMPILE=$(CROSS_COMPILER_PREFIX) distclean

tfa_boot:
	$(QEMU_DIR)/build/qemu-system-aarch64 \
    	-M virt,gic-version=3,secure=on \
    	-cpu cortex-a53 \
    	-smp 2 -m 128M \
		-monitor telnet:127.0.0.1:9999,server,nowait \
		-dtb $(UBOOT_DIR)/arch/arm/dts/qemu-arm64.dtb \
		-drive if=pflash,format=raw,unit=0,file=$(TOP_DIR)/combined.bin,readonly=on \
		-device qemu-xhci,id=xhci \
		-device usb-storage,drive=usbdisk,bus=xhci.0 \
		-drive if=none,id=usbdisk,file=$(TOP_DIR)/version.bin,format=raw \
		-netdev user,id=net0,tftp=$(TOP_DIR),hostfwd=tcp::2222-:23,hostfwd=tcp::8888-:8888 \
		-device virtio-net-pci,netdev=net0 \
    	-nographic -no-reboot

./combine_bl31_fip.sh

