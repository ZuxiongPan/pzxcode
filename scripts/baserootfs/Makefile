
initramfs:
	find . -print0 | cpio --null -ov --format=newc | gzip > ../initramfs.cpio.gz

rootfsimg:
	rm -f ../rootfs.img
	mkfs.ext4 -F -b 1024 -d $(PWD) ../rootfs.img 0x4000